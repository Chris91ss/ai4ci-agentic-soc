"""Per-account sign-in baselines learned from history (part of the M1 model artifact).

Profiles are built offline from benign history and frozen online, so that an attacker cannot
teach the baseline its own behaviour. They are rebuilt when M1 is retrained (e.g. after drift).
"""

from __future__ import annotations

import json
import math
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

TOP_IPS = 50


@dataclass
class AccountProfile:
    n: int = 0
    fails: int = 0
    hours: list[int] = field(default_factory=lambda: [0] * 24)
    countries: Counter[str] = field(default_factory=Counter)
    asns: Counter[str] = field(default_factory=Counter)
    ips: Counter[str] = field(default_factory=Counter)
    devices: set[str] = field(default_factory=set)
    apps: set[str] = field(default_factory=set)
    logon_types: set[str] = field(default_factory=set)
    dst_hosts: set[str] = field(default_factory=set)
    cities: Counter[str] = field(default_factory=Counter)

    def hour_prob(self, hour: int) -> float:
        """Smoothed probability of a successful sign-in at this local hour."""
        smoothed = [(h + 0.25) for h in self.hours]
        return smoothed[hour] / sum(smoothed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "n": self.n,
            "fails": self.fails,
            "hours": self.hours,
            "countries": dict(self.countries),
            "asns": dict(self.asns),
            "ips": dict(self.ips.most_common(TOP_IPS)),
            "devices": sorted(self.devices),
            "apps": sorted(self.apps),
            "logon_types": sorted(self.logon_types),
            "dst_hosts": sorted(self.dst_hosts),
            "cities": dict(self.cities),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AccountProfile:
        return cls(
            n=data["n"],
            fails=data["fails"],
            hours=list(data["hours"]),
            countries=Counter(data["countries"]),
            asns=Counter(data["asns"]),
            ips=Counter(data["ips"]),
            devices=set(data["devices"]),
            apps=set(data["apps"]),
            logon_types=set(data["logon_types"]),
            dst_hosts=set(data["dst_hosts"]),
            cities=Counter(data["cities"]),
        )


class Profiles:
    def __init__(
        self,
        accounts: dict[str, AccountProfile] | None = None,
        known_ips: set[str] | None = None,
        global_hours: list[int] | None = None,
        timezone: str = "UTC",
        built_from: dict[str, Any] | None = None,
    ) -> None:
        self.accounts = accounts or {}
        self.known_ips = known_ips or set()
        self.global_hours = global_hours or [0] * 24
        self.timezone = timezone
        self.tz = ZoneInfo(timezone)
        self.built_from = built_from or {}

    def local_hour(self, t: datetime) -> int:
        return t.astimezone(self.tz).hour

    def local_weekday(self, t: datetime) -> int:
        return t.astimezone(self.tz).weekday()

    def global_hour_prob(self, hour: int) -> float:
        smoothed = [(h + 1.0) for h in self.global_hours]
        return smoothed[hour] / sum(smoothed)

    @staticmethod
    def device_of(row: Any) -> str:
        return row.device_id or row.user_agent or ""

    @classmethod
    def build(cls, signins: Iterable[Any], timezone: str) -> Profiles:
        """Build baselines from successful and failed sign-ins (NormSignin-like rows)."""
        tz = ZoneInfo(timezone)
        accounts: dict[str, AccountProfile] = {}
        known_ips: set[str] = set()
        global_hours = [0] * 24
        first = last = None
        for row in signins:
            if row.user_kind == "unknown":
                continue
            profile = accounts.setdefault(row.user_id, AccountProfile())
            first = row.event_time if first is None else min(first, row.event_time)
            last = row.event_time if last is None else max(last, row.event_time)
            if row.outcome != "success":
                profile.fails += 1
                continue
            hour = row.event_time.astimezone(tz).hour
            profile.n += 1
            profile.hours[hour] += 1
            global_hours[hour] += 1
            if row.src_country:
                profile.countries[row.src_country] += 1
            if row.src_asn is not None:
                profile.asns[str(row.src_asn)] += 1
            if row.src_city:
                profile.cities[row.src_city] += 1
            profile.ips[row.src_ip] += 1
            device = cls.device_of(row)
            if device:
                profile.devices.add(device)
            profile.apps.add(row.app)
            profile.logon_types.add(row.logon_type)
            if row.dst_host:
                profile.dst_hosts.add(row.dst_host)
            if row.src_zone == "external":
                known_ips.add(row.src_ip)
        built = {
            "first": first.isoformat() if first else None,
            "last": last.isoformat() if last else None,
            "accounts": len(accounts),
        }
        return cls(accounts, known_ips, global_hours, timezone, built)

    # ------------------------------------------------------------------ persistence
    def to_json(self) -> dict[str, Any]:
        return {
            "timezone": self.timezone,
            "built_from": self.built_from,
            "global_hours": self.global_hours,
            "known_ips": sorted(self.known_ips),
            "accounts": {k: v.to_dict() for k, v in sorted(self.accounts.items())},
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Profiles:
        return cls(
            accounts={k: AccountProfile.from_dict(v) for k, v in data["accounts"].items()},
            known_ips=set(data["known_ips"]),
            global_hours=list(data["global_hours"]),
            timezone=data["timezone"],
            built_from=data.get("built_from", {}),
        )

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_json()))

    @classmethod
    def load(cls, path: str | Path) -> Profiles:
        return cls.from_json(json.loads(Path(path).read_text()))


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))
