"""Per-user daily plans: attendance, working hours, remote/VPN days, trips and evenings."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta

import numpy as np

from agentic_soc.simulator.calibration import Calibration
from agentic_soc.simulator.catalog import CONSUMER_VPN_BLOCKS
from agentic_soc.simulator.enterprise import TRAVEL_BLOCKS, VPN_NET, Enterprise, User
from agentic_soc.simulator.rng import rng_for

_PROFILE_ANCHOR_H = 8.6  # population mean start hour the calibrated profile corresponds to


@dataclass(slots=True)
class Trip:
    start_day: int
    end_day: int
    country: str
    ip: str


@dataclass(slots=True)
class DayPlan:
    user_id: str
    day: int
    works: bool
    remote: bool
    trip: Trip | None
    start: datetime
    end: datetime
    lunch_start: datetime
    lunch_end: datetime
    after_hours: bool
    public_ip: str  # source address of cloud sign-ins (office NAT, home or travel ISP)
    vpn_ip: str | None  # VPN lease for remote/travel days
    shift_h: float  # personal phase shift of the activity profile
    consumer_vpn: bool = False  # public address is a consumer VPN exit

    @property
    def vpn(self) -> bool:
        return self.vpn_ip is not None

    def active(self, t: datetime) -> bool:
        return self.works and self.start <= t < self.end

    def in_lunch(self, t: datetime) -> bool:
        return self.lunch_start <= t < self.lunch_end


class ActivityPlanner:
    """Deterministic, cached day plans; scenario hooks may alter remote work probability."""

    def __init__(
        self,
        ent: Enterprise,
        calibration: Calibration,
        attendance: float = 0.94,
        travel: bool = True,
        consumer_vpn: bool = True,
    ) -> None:
        self.ent = ent
        self.seed = ent.config.seed
        self.attendance = attendance
        self.travel_enabled = travel
        self.consumer_vpn_enabled = consumer_vpn
        profile = calibration.user_profile()
        self._hourly = np.asarray((*profile.hourly, profile.hourly[0]))
        self._weekly = profile.weekly
        work_hours = np.arange(8, 18)
        self._work_mean = float(np.mean(self._hourly[work_hours]))
        self._plans: dict[tuple[str, int], DayPlan] = {}
        self._vpn_pools: dict[int, list[str]] = {}
        self._user_index = {u.user_id: i for i, u in enumerate(ent.users)}
        self.remote_override: list[tuple[datetime, float]] = []  # (from, remote_prob) for drift
        self.shift_override: list[tuple[datetime, float]] = []  # (from, extra shift hours)
        self.remote_egress_override: list[tuple[datetime, list[str]]] = []  # (from, ZTNA egress)
        self.trips = self._plan_trips()

    # ------------------------------------------------------------------ trips
    def _plan_trips(self) -> dict[str, list[Trip]]:
        days = int(self.ent.config.duration_h // 24) + 2
        trips: dict[str, list[Trip]] = {}
        if not self.travel_enabled:
            return trips
        countries = sorted(TRAVEL_BLOCKS)
        for user in self.ent.users:
            rng = rng_for(self.seed, "trips", user.user_id)
            day = -int(rng.integers(0, 4))  # a trip may already be under way at the start
            while day < days:
                if rng.random() < user.travel_prob * 3:  # boosted so short runs still see trips
                    length = int(rng.integers(2, 5))
                    country = str(rng.choice(countries))
                    ip = self.ent.allocator.take(rng, TRAVEL_BLOCKS[country])[0]
                    trips.setdefault(user.user_id, []).append(
                        Trip(day, day + length - 1, country, ip)
                    )
                    day += length + int(rng.integers(5, 15))
                else:
                    day += 1
        return trips

    def trip_on(self, user: User, day: int) -> Trip | None:
        for trip in self.trips.get(user.user_id, []):
            if trip.start_day <= day <= trip.end_day:
                return trip
        return None

    # ------------------------------------------------------------------ VPN
    def _vpn_ip(self, user: User, day: int) -> str:
        pool = self._vpn_pools.get(day)
        if pool is None:
            rng = rng_for(self.seed, "vpn-pool", day)
            offsets = rng.choice(
                VPN_NET.num_addresses - 512, size=len(self.ent.users), replace=False
            )
            base = int(VPN_NET.network_address) + 256
            pool = [str(ipaddress.ip_address(base + int(o))) for o in offsets]
            self._vpn_pools[day] = pool
        return pool[self._user_index[user.user_id]]

    # ------------------------------------------------------------------ plans
    def remote_prob(self, user: User, t: datetime) -> float:
        prob = user.remote_prob
        for since, override in self.remote_override:
            if t >= since:
                prob = max(prob, override)
        return prob

    def extra_shift(self, t: datetime) -> float:
        shift = 0.0
        for since, value in self.shift_override:
            if t >= since:
                shift = value
        return shift

    def remote_egress(self, t: datetime) -> list[str] | None:
        pool = None
        for since, ips in self.remote_egress_override:
            if t >= since:
                pool = ips
        return pool

    def plan(self, user: User, day: int) -> DayPlan:
        key = (user.user_id, day)
        cached = self._plans.get(key)
        if cached is not None:
            return cached
        rng = rng_for(self.seed, "plan", user.user_id, day)
        midnight = self.ent.day_start(day)
        weekday = midnight.weekday()
        trip = self.trip_on(user, day)
        u = rng.random(8)
        works = u[0] < (self.attendance if weekday < 5 else user.weekend_prob)
        noon = midnight + timedelta(hours=12)
        shift = self.extra_shift(noon)
        start_h = user.work_start_h + float(rng.normal(0, 0.35)) + shift
        length_h = user.work_len_h + float(rng.normal(0, 0.4))
        if weekday >= 5:
            length_h *= 0.45
        start = midnight + timedelta(hours=min(max(start_h, 5.0), 14.0))
        end = min(start + timedelta(hours=max(length_h, 2.0)), midnight + timedelta(hours=23.5))
        lunch_start = midnight + timedelta(hours=12.0 + float(u[1]) * 1.2)
        lunch_end = lunch_start + timedelta(minutes=30 + float(u[2]) * 30)
        remote = trip is not None or u[3] < self.remote_prob(user, noon)
        consumer_vpn = False
        if trip is not None:
            public_ip = trip.ip
        elif remote and (egress := self.remote_egress(noon)):
            public_ip = egress[int(u[7] * len(egress))]
        elif remote:
            public_ip = user.home_ip
            if self.consumer_vpn_enabled and user.consumer_vpn and u[5] < 0.6:
                block = CONSUMER_VPN_BLOCKS[int(u[6] * len(CONSUMER_VPN_BLOCKS))]
                public_ip = self.ent.allocator.take(
                    rng_for(self.seed, "cvpn", user.user_id, day), block
                )[0]
                consumer_vpn = True
        else:
            public_ip = self.ent.office_egress[user.office]
        plan = DayPlan(
            user_id=user.user_id,
            day=day,
            works=bool(works),
            remote=bool(remote),
            trip=trip,
            start=start.astimezone(self.ent.config.start.tzinfo),
            end=end.astimezone(self.ent.config.start.tzinfo),
            lunch_start=lunch_start,
            lunch_end=lunch_end,
            after_hours=bool(u[4] < user.after_hours_prob),
            public_ip=public_ip,
            vpn_ip=self._vpn_ip(user, day) if remote else None,
            shift_h=(user.work_start_h - _PROFILE_ANCHOR_H) + shift,
            consumer_vpn=consumer_vpn,
        )
        self._plans[key] = plan
        return plan

    def plans_at(self, t: datetime) -> list[tuple[User, DayPlan]]:
        day = self.ent.day_index(t)
        return [(u, self.plan(u, day)) for u in self.ent.users]

    # ------------------------------------------------------------------ intensity
    def intensity(self, local_hour: float, shift_h: float) -> float:
        """Activity multiplier during working time (mean ~1 over a normal working day)."""
        h = (local_hour - shift_h) % 24.0
        i = int(h)
        frac = h - i
        value = self._hourly[i] * (1 - frac) + self._hourly[i + 1] * frac
        return float(value / self._work_mean)

    def weekly(self, weekday: int) -> float:
        return float(self._weekly[weekday])

    def workstation_ip(self, host_id: str, t: datetime) -> str | None:
        """Address a workstation uses at ``t``: VPN lease when its owner works remotely.

        Remote laptops are only visible to the corporate sensors while the VPN is up.
        """
        host = self.ent.hosts_by_id[host_id]
        if host.owner is None:
            return self.ent.host_ip(host_id, t)
        user = self.ent.users_by_id[host.owner]
        plan = self.plan(user, self.ent.day_index(t))
        if plan.remote:
            return plan.vpn_ip if plan.active(t) else None
        return self.ent.dhcp_ip(host_id, t)
