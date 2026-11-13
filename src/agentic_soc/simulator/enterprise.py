"""Enterprise model: identities, hosts, network zones, IP plan, DHCP and a synthetic GeoIP DB.

Everything is derived deterministically from the config and seed, so the ingestion service can
rebuild the same asset and identity inventory (CMDB + DHCP + GeoIP) without seeing any ground
truth from the simulator.
"""

from __future__ import annotations

import ipaddress
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any, Literal
from zoneinfo import ZoneInfo

import numpy as np

from agentic_soc.simulator.catalog import (
    DESKTOP_USER_AGENTS,
    FIRST_NAMES,
    LAST_NAMES,
    MOBILE_USER_AGENTS,
    NETBLOCKS,
    ROLE_APPS,
    SERVICES,
    Netblock,
)
from agentic_soc.simulator.config import SimulatorConfig
from agentic_soc.simulator.rng import rng_for

CORP_NET = ipaddress.ip_network("10.10.0.0/16")
DATACENTER_NET = ipaddress.ip_network("10.20.0.0/16")
DMZ_NET = ipaddress.ip_network("172.16.10.0/24")
VPN_NET = ipaddress.ip_network("10.99.0.0/16")
_OFFICE_POOL_PREFIX = 20  # each office gets a /20 DHCP scope inside CORP_NET
_DHCP_RENEW_SHARE = 0.12  # share of workstations that get a new address each day

HOME_BLOCKS: dict[str, list[str]] = {
    "Cluj-Napoca": ["86.120.0.0/16", "188.24.0.0/16"],
    "Bucharest": ["79.112.0.0/16", "5.12.0.0/16"],
}
MOBILE_BLOCK = "37.120.0.0/16"
TRAVEL_BLOCKS: dict[str, str] = {
    "DE": "91.64.0.0/16",
    "FR": "90.84.0.0/16",
    "GB": "81.96.0.0/16",
    "US": "73.0.0.0/16",
    "IT": "93.40.0.0/16",
    "ES": "88.0.0.0/16",
    "NL": "84.24.0.0/16",
}


@dataclass(slots=True)
class Device:
    device_id: str
    kind: Literal["desktop", "mobile"]
    user_agent: str


@dataclass(slots=True)
class User:
    user_id: str  # canonical identity (sAMAccountName)
    upn: str
    display_name: str
    role: str
    department: str
    office: str
    home_city: str
    home_ip: str
    workstation: str
    work_start_h: float
    work_len_h: float
    remote_prob: float
    travel_prob: float
    after_hours_prob: float
    weekend_prob: float
    apps: list[str]
    tools: list[str]
    devices: list[Device]
    admin_account: str | None = None
    weak_password: bool = False

    @property
    def is_admin(self) -> bool:
        return self.admin_account is not None


@dataclass(slots=True)
class ServiceAccount:
    name: str
    upn: str
    purpose: str
    source_hosts: list[str]
    target_hosts: list[str]


@dataclass(slots=True)
class Host:
    host_id: str
    fqdn: str
    kind: Literal["workstation", "server"]
    role: str
    zone: Literal["corp", "datacenter", "dmz"]
    os: Literal["windows", "linux"]
    criticality: int
    office: str | None = None
    owner: str | None = None
    static_ip: str | None = None


@dataclass(slots=True)
class ExternalService:
    name: str
    ips: list[str]
    ports: tuple[int, ...]
    popularity: float
    bytes_scale: float


@dataclass(frozen=True, slots=True)
class GeoInfo:
    country: str
    city: str
    lat: float
    lon: float
    asn: int
    org: str
    category: str


class GeoIP:
    """Longest-prefix lookup over the synthetic netblock table."""

    def __init__(self, netblocks: list[Netblock]) -> None:
        self._by_len: dict[int, dict[int, GeoInfo]] = {}
        for block in netblocks:
            net = ipaddress.ip_network(block.cidr)
            info = GeoInfo(
                block.country,
                block.city,
                block.lat,
                block.lon,
                block.asn,
                block.org,
                block.category,
            )
            self._by_len.setdefault(net.prefixlen, {})[int(net.network_address)] = info
        self._lengths = sorted(self._by_len, reverse=True)
        self.lookup = lru_cache(maxsize=65536)(self._lookup)  # type: ignore[method-assign]

    def _lookup(self, ip: str) -> GeoInfo | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.version != 4:
            return None
        value = int(addr)
        for length in self._lengths:
            mask = (0xFFFFFFFF << (32 - length)) & 0xFFFFFFFF
            info = self._by_len[length].get(value & mask)
            if info is not None:
                return info
        return None


def zone_of_ip(ip: str) -> str:
    """Network zone of an address: corp, datacenter, dmz, vpn or external."""
    addr = ipaddress.ip_address(ip)
    if addr in CORP_NET:
        return "corp"
    if addr in DATACENTER_NET:
        return "datacenter"
    if addr in DMZ_NET:
        return "dmz"
    if addr in VPN_NET:
        return "vpn"
    return "external"


def is_internal(ip: str) -> bool:
    return zone_of_ip(ip) != "external"


def _ascii(name: str) -> str:
    return unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode().lower()


def _allocate_counts(shares: dict[str, float], total: int) -> dict[str, int]:
    """Largest-remainder apportionment so that counts sum exactly to ``total``."""
    norm = sum(shares.values())
    raw = {k: v / norm * total for k, v in shares.items()}
    counts = {k: int(v) for k, v in raw.items()}
    remainder = total - sum(counts.values())
    for key in sorted(raw, key=lambda k: raw[k] - counts[k], reverse=True)[:remainder]:
        counts[key] += 1
    return counts


class AddressAllocator:
    """Hands out unique host addresses from netblocks."""

    def __init__(self) -> None:
        self.used: set[str] = set()

    def take(self, rng: np.random.Generator, cidr: str, n: int = 1) -> list[str]:
        net = ipaddress.ip_network(cidr)
        span = net.num_addresses
        out: list[str] = []
        while len(out) < n:
            offset = int(rng.integers(1, span - 1)) if span > 2 else 0
            ip = str(net.network_address + offset)
            if ip.endswith(".0") or ip.endswith(".255") or ip in self.used:
                continue
            self.used.add(ip)
            out.append(ip)
        return out


@dataclass
class Enterprise:
    config: SimulatorConfig
    users: list[User]
    hosts: list[Host]
    service_accounts: list[ServiceAccount]
    services: dict[str, ExternalService]
    office_egress: dict[str, str]
    geo: GeoIP
    allocator: AddressAllocator
    users_by_id: dict[str, User] = field(init=False)
    hosts_by_id: dict[str, Host] = field(init=False)
    servers_by_role: dict[str, list[Host]] = field(init=False)
    static_ips: dict[str, str] = field(init=False)
    _dhcp_days: list[dict[str, str]] = field(init=False, default_factory=list)
    _dhcp_rev: list[dict[str, str]] = field(init=False, default_factory=list)

    def __post_init__(self) -> None:
        self.users_by_id = {u.user_id: u for u in self.users}
        self.hosts_by_id = {h.host_id: h for h in self.hosts}
        self.servers_by_role = {}
        for host in self.hosts:
            if host.kind == "server":
                self.servers_by_role.setdefault(host.role, []).append(host)
        self.static_ips = {h.static_ip: h.host_id for h in self.hosts if h.static_ip}
        self.tz = ZoneInfo(self.config.org.timezone)
        self._start_date = self.config.start.astimezone(self.tz).date()

    # ------------------------------------------------------------------ construction
    @classmethod
    def build(cls, config: SimulatorConfig) -> Enterprise:
        seed, org = config.seed, config.org
        rng = rng_for(seed, "enterprise")
        allocator = AddressAllocator()

        office_egress = {
            office.name: allocator.take(
                rng_for(seed, "egress", office.name), office.egress_netblock
            )[0]
            for office in org.offices
        }
        role_counts = _allocate_counts({k: r.share for k, r in org.roles.items()}, org.users)
        roles = [role for role, count in role_counts.items() for _ in range(count)]
        rng.shuffle(roles)
        office_counts = _allocate_counts({o.name: o.share for o in org.offices}, org.users)
        offices = [name for name, count in office_counts.items() for _ in range(count)]
        rng.shuffle(offices)
        office_by_name = {o.name: o for o in org.offices}

        users: list[User] = []
        taken: set[str] = set()
        for i in range(org.users):
            role_name = roles[i]
            role = org.roles[role_name]
            first = str(rng.choice(FIRST_NAMES))
            last = str(rng.choice(LAST_NAMES))
            base = f"{_ascii(first)}.{_ascii(last)}"
            username, n = base, 2
            while username in taken:
                username, n = f"{base}{n}", n + 1
            taken.add(username)
            office = office_by_name[offices[i]]
            home_block = str(rng.choice(HOME_BLOCKS.get(office.city, ["86.120.0.0/16"])))
            start_mu = 7.0 if role_name == "operations" else 8.6
            devices = [
                Device(f"dev-{i:04d}-d", "desktop", str(rng.choice(DESKTOP_USER_AGENTS[:3], p=[0.55, 0.33, 0.12]))),
            ]  # fmt: skip
            if rng.random() < 0.75:
                devices.append(
                    Device(f"dev-{i:04d}-m", "mobile", str(rng.choice(MOBILE_USER_AGENTS)))
                )
            users.append(
                User(
                    user_id=username,
                    upn=f"{username}@{org.domain}",
                    display_name=f"{first} {last}",
                    role=role_name,
                    department=role.department,
                    office=office.name,
                    home_city=office.city,
                    home_ip=allocator.take(rng, home_block)[0],
                    workstation=f"WS-{i + 1:04d}",
                    work_start_h=float(np.clip(rng.normal(start_mu, 0.6), 6.0, 10.5)),
                    work_len_h=float(np.clip(rng.normal(8.6, 0.5), 7.0, 10.5)),
                    remote_prob=role.remote_prob,
                    travel_prob=role.travel_prob,
                    after_hours_prob=role.after_hours_prob,
                    weekend_prob=role.weekend_prob,
                    apps=list(role.apps),
                    tools=list(role.tools),
                    devices=devices,
                    admin_account=f"adm-{username}" if role.admin else None,
                    weak_password=bool(rng.random() < org.weak_password_share) and not role.admin,
                )
            )
        candidates = [u for u in users if not u.is_admin]
        while sum(u.weak_password for u in users) < 2 and candidates:
            candidates[int(rng.integers(len(candidates)))].weak_password = True

        hosts: list[Host] = []
        for user in users:
            crit = 3 if user.role in {"executive", "it_admin", "finance"} else 2
            hosts.append(
                Host(
                    host_id=user.workstation,
                    fqdn=f"{user.workstation.lower()}.{org.domain}",
                    kind="workstation",
                    role="workstation",
                    zone="corp",
                    os="windows",
                    criticality=crit,
                    office=user.office,
                    owner=user.user_id,
                )
            )
        dmz_next = 10
        for dc_index, group in enumerate(org.servers, start=1):
            for n in range(1, group.count + 1):
                host_id = f"SRV-{group.role.upper()}-{n:02d}"
                if group.zone == "dmz":
                    ip = str(DMZ_NET.network_address + dmz_next)
                    dmz_next += 1
                else:
                    ip = str(DATACENTER_NET.network_address + dc_index * 256 + 10 + n)
                allocator.used.add(ip)
                hosts.append(
                    Host(
                        host_id=host_id,
                        fqdn=f"{host_id.lower()}.{org.domain}",
                        kind="server",
                        role=group.role,
                        zone=group.zone,
                        os=group.os,
                        criticality=group.criticality,
                        static_ip=ip,
                    )
                )

        by_role: dict[str, list[str]] = {}
        for host in hosts:
            by_role.setdefault(host.role, []).append(host.host_id)

        def role_hosts(*names: str) -> list[str]:
            return [h for name in names for h in by_role.get(name, [])]

        purposes = {
            "svc_backup": ("nightly backups", role_hosts("backup"), role_hosts("file", "db", "erp", "mail")),
            "svc_sql": ("application database access", role_hosts("app", "erp"), role_hosts("db")),
            "svc_web": ("web tier to application tier", role_hosts("web"), role_hosts("app")),
            "svc_monitor": ("health checks", role_hosts("monitoring"), [h.host_id for h in hosts if h.kind == "server"]),
            "svc_build": ("CI builds and artifact shares", role_hosts("build"), role_hosts("file")),
        }  # fmt: skip
        service_accounts = [
            ServiceAccount(name, f"{name}@{org.domain}", *purposes.get(name, ("service", [], [])))
            for name in org.service_accounts
        ]

        services: dict[str, ExternalService] = {}
        for spec in SERVICES:
            ips = allocator.take(rng_for(seed, "service", spec.name), spec.netblock, spec.n_ips)
            services[spec.name] = ExternalService(
                spec.name, ips, spec.ports, spec.popularity, spec.bytes_scale
            )

        return cls(
            config=config,
            users=users,
            hosts=hosts,
            service_accounts=service_accounts,
            services=services,
            office_egress=office_egress,
            geo=GeoIP(NETBLOCKS),
            allocator=allocator,
        )

    # ------------------------------------------------------------------ helpers
    @property
    def workstations(self) -> list[Host]:
        return [h for h in self.hosts if h.kind == "workstation"]

    @property
    def servers(self) -> list[Host]:
        return [h for h in self.hosts if h.kind == "server"]

    @property
    def admins(self) -> list[User]:
        return [u for u in self.users if u.is_admin]

    def app_service(self, app: str) -> ExternalService:
        return self.services[ROLE_APPS.get(app, "o365")]

    def local(self, t: datetime) -> datetime:
        return t.astimezone(self.tz)

    def day_index(self, t: datetime) -> int:
        return max(0, (t.astimezone(self.tz).date() - self._start_date).days)

    def day_start(self, day: int) -> datetime:
        """Local midnight of simulation day ``day`` as an aware datetime."""
        date = self._start_date + timedelta(days=day)
        return datetime(date.year, date.month, date.day, tzinfo=self.tz)

    # ------------------------------------------------------------------ DHCP
    def _office_pool(self, office: str) -> list[str]:
        index = [o.name for o in self.config.org.offices].index(office)
        scope = list(CORP_NET.subnets(new_prefix=_OFFICE_POOL_PREFIX))[index * 2]
        return [str(ip) for ip in scope.hosts() if not str(ip).endswith((".0", ".255", ".1"))]

    def _dhcp_ensure(self, day: int) -> None:
        while len(self._dhcp_days) <= day:
            d = len(self._dhcp_days)
            rng = rng_for(self.config.seed, "dhcp", d)
            assign: dict[str, str] = {}
            for office in self.config.org.offices:
                members = [h.host_id for h in self.workstations if h.office == office.name]
                pool = self._office_pool(office.name)
                if d == 0:
                    chosen = rng.choice(len(pool), size=len(members), replace=False)
                    assign.update({h: pool[i] for h, i in zip(members, chosen, strict=True)})
                    continue
                previous = self._dhcp_days[d - 1]
                in_use = {previous[h] for h in members}
                free = [ip for ip in pool if ip not in in_use]
                renew = set(
                    rng.choice(
                        members, size=max(1, int(len(members) * _DHCP_RENEW_SHARE)), replace=False
                    )
                )
                picks = iter(rng.permutation(free))
                for h in members:
                    assign[h] = str(next(picks)) if h in renew else previous[h]
            self._dhcp_days.append(assign)
            self._dhcp_rev.append({ip: h for h, ip in assign.items()})

    def dhcp_ip(self, host_id: str, t: datetime) -> str:
        """Address leased to workstation ``host_id`` at time ``t``."""
        host = self.hosts_by_id[host_id]
        if host.static_ip:
            return host.static_ip
        day = self.day_index(t)
        self._dhcp_ensure(day)
        return self._dhcp_days[day][host_id]

    def host_ip(self, host_id: str, t: datetime) -> str:
        return self.dhcp_ip(host_id, t)

    def host_for_ip(self, ip: str, t: datetime) -> str | None:
        """Resolve an internal address to a host at time ``t`` (static IPs and DHCP leases)."""
        if ip in self.static_ips:
            return self.static_ips[ip]
        if zone_of_ip(ip) != "corp":
            return None
        day = self.day_index(t)
        self._dhcp_ensure(day)
        return self._dhcp_rev[day].get(ip)

    # ------------------------------------------------------------------ inventory export
    def inventory(self) -> dict[str, Any]:
        """Asset and identity inventory as a JSON-serialisable document (no ground truth)."""
        return {
            "org": {
                "name": self.config.org.name,
                "domain": self.config.org.domain,
                "netbios": self.config.org.netbios,
                "timezone": self.config.org.timezone,
                "home_country": self.config.org.home_country,
            },
            "users": [
                {
                    "user_id": u.user_id,
                    "upn": u.upn,
                    "display_name": u.display_name,
                    "role": u.role,
                    "department": u.department,
                    "office": u.office,
                    "workstation": u.workstation,
                    "admin_account": u.admin_account,
                }
                for u in self.users
            ],
            "service_accounts": [
                {"name": s.name, "upn": s.upn, "purpose": s.purpose} for s in self.service_accounts
            ],
            "hosts": [
                {
                    "host_id": h.host_id,
                    "fqdn": h.fqdn,
                    "kind": h.kind,
                    "role": h.role,
                    "zone": h.zone,
                    "os": h.os,
                    "criticality": h.criticality,
                    "office": h.office,
                    "owner": h.owner,
                    "static_ip": h.static_ip,
                }
                for h in self.hosts
            ],
            "office_egress": self.office_egress,
            "networks": {
                "corp": str(CORP_NET),
                "datacenter": str(DATACENTER_NET),
                "dmz": str(DMZ_NET),
                "vpn": str(VPN_NET),
            },
        }
