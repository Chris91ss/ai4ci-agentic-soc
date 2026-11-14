"""Entity resolution: link accounts, hosts and IP addresses across streams over time.

Static links come from the inventory (server addresses, workstation owners, the employee
behind an ``adm-`` account). Dynamic links are learned from successful sign-ins: an
interactive logon on a workstation binds its DHCP address to the host and the account, a VPN
logon binds the leased address to the account (and the employee's device), and Kerberos network
logons bind a source address to the account (and, for regular users, to their own workstation
when the address is not bound yet). Bindings are time-stamped and expire after a lease
period, so an address is resolved to whoever held it at the time of the event.
"""

from __future__ import annotations

import bisect
from collections import defaultdict
from datetime import datetime, timedelta

from agentic_soc.ingestion.inventory import Inventory
from agentic_soc.ingestion.models import NormSignin

_SKEW = timedelta(minutes=10)  # a binding may be logged shortly after the address is used


class _Bindings:
    """Per-key time-sorted list of (time, value)."""

    def __init__(self, max_per_key: int = 64) -> None:
        self._times: dict[str, list[float]] = defaultdict(list)
        self._values: dict[str, list[str]] = defaultdict(list)
        self.max_per_key = max_per_key

    def add(self, key: str, t: datetime, value: str) -> None:
        times, values = self._times[key], self._values[key]
        ts = t.timestamp()
        i = bisect.bisect_right(times, ts)
        if i > 0 and values[i - 1] == value:
            return  # same binding renewed
        times.insert(i, ts)
        values.insert(i, value)
        if len(times) > self.max_per_key:
            del times[0], values[0]

    def at(self, key: str, t: datetime, lease: timedelta) -> str | None:
        times = self._times.get(key)
        if not times:
            return None
        ts = (t + _SKEW).timestamp()
        i = bisect.bisect_right(times, ts) - 1
        if i < 0 or times[i] < t.timestamp() - lease.total_seconds():
            return None
        return self._values[key][i]

    def between(self, key: str, start: datetime, end: datetime, lease: timedelta) -> list[str]:
        times = self._times.get(key, [])
        values = self._values.get(key, [])
        lo, hi = (start - lease).timestamp(), (end + _SKEW).timestamp()
        return list(dict.fromkeys(v for ts, v in zip(times, values, strict=True) if lo <= ts <= hi))


class EntityResolver:
    def __init__(self, inventory: Inventory, lease_h: float = 24.0) -> None:
        self.inventory = inventory
        self.lease = timedelta(hours=lease_h)
        self.ip_host = _Bindings()
        self.ip_user = _Bindings()
        self.host_ip = _Bindings()
        self.user_ip = _Bindings()
        self.observed = 0

    def observe(self, event: NormSignin) -> None:
        if event.outcome != "success":
            return
        t = event.event_time
        if (
            event.logon_type == "interactive"
            and event.dst_host
            and event.src_zone in {"corp", "vpn"}
        ):
            self._bind(event.src_ip, t, host=event.dst_host, user=event.user_id)
        elif event.logon_type == "vpn" and event.assigned_ip:
            person = event.person or event.user_id
            device = self.inventory.users.get(person)
            self._bind(
                event.assigned_ip,
                t,
                host=device.workstation if device else None,
                user=event.user_id,
            )
        elif (
            event.logon_type == "network"
            and event.src_zone in {"corp", "vpn"}
            and event.user_kind in {"user", "admin"}
        ):
            self.ip_user.add(event.src_ip, t, event.user_id)
            self.user_ip.add(event.user_id, t, event.src_ip)
        else:
            return
        self.observed += 1

    def _bind(self, ip: str, t: datetime, host: str | None, user: str | None) -> None:
        if host:
            self.ip_host.add(ip, t, host)
            self.host_ip.add(host, t, ip)
        if user:
            self.ip_user.add(ip, t, user)
            self.user_ip.add(user, t, ip)

    # ------------------------------------------------------------------ queries
    def host_for_ip(self, ip: str, t: datetime) -> str | None:
        static = self.inventory.static_host(ip)
        if static:
            return static
        return self.ip_host.at(ip, t, self.lease)

    def user_for_ip(self, ip: str, t: datetime) -> str | None:
        user = self.ip_user.at(ip, t, self.lease)
        if user:
            return user
        host = self.host_for_ip(ip, t)
        if host:
            return self.inventory.workstation_owner.get(host)
        return None

    def ips_for_host(self, host: str, start: datetime, end: datetime) -> list[str]:
        info = self.inventory.hosts.get(host)
        ips = [info.static_ip] if info and info.static_ip else []
        return list(dict.fromkeys(ips + self.host_ip.between(host, start, end, self.lease)))

    def ips_for_user(self, user: str, start: datetime, end: datetime) -> list[str]:
        return self.user_ip.between(user, start, end, self.lease)
