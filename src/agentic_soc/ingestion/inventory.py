"""Asset and identity inventory used for enrichment (what the CMDB, the IdP and a GeoIP database
would provide). It is loaded from ``inventory.json`` and never contains ground truth."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentic_soc.simulator.catalog import NETBLOCKS
from agentic_soc.simulator.enterprise import GeoInfo, GeoIP

SYSTEM_ACCOUNTS = {"system", "root", "local service", "network service", "localsystem"}


@dataclass(frozen=True, slots=True)
class HostInfo:
    host_id: str
    fqdn: str
    kind: str
    role: str
    zone: str
    os: str
    criticality: int
    office: str | None
    owner: str | None
    static_ip: str | None


@dataclass(frozen=True, slots=True)
class UserInfo:
    user_id: str
    upn: str
    display_name: str
    role: str
    department: str
    office: str
    workstation: str
    admin_account: str | None


def canonical_account(raw: str) -> str:
    """``CORP\\ana.pop``, ``ana.pop@corp.example`` and ``ana.pop@CORP.EXAMPLE`` -> ``ana.pop``."""
    value = raw.strip()
    if "\\" in value:
        value = value.split("\\", 1)[1]
    if "@" in value:
        value = value.split("@", 1)[0]
    return value.lower()


class Inventory:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        org = data["org"]
        self.domain = org["domain"].lower()
        self.netbios = org["netbios"].upper()
        self.home_country = org.get("home_country")
        self.timezone = org.get("timezone", "UTC")
        self.users = {u["user_id"]: UserInfo(**u) for u in data["users"]}
        self.admin_owner = {
            u.admin_account: u.user_id for u in self.users.values() if u.admin_account
        }
        self.service_accounts = {s["name"].lower(): s for s in data.get("service_accounts", [])}
        self.hosts = {h["host_id"]: HostInfo(**h) for h in data["hosts"]}
        self.fqdn = {h.fqdn.lower(): h.host_id for h in self.hosts.values()}
        self.static_ips = {h.static_ip: h.host_id for h in self.hosts.values() if h.static_ip}
        self.workstation_owner = {h.host_id: h.owner for h in self.hosts.values() if h.owner}
        self.office_egress = data.get("office_egress", {})
        self.egress_office = {ip: office for office, ip in self.office_egress.items()}
        self.networks = {
            zone: ipaddress.ip_network(cidr) for zone, cidr in data.get("networks", {}).items()
        }
        self.geo = GeoIP(NETBLOCKS)
        self._zone_cache: dict[str, str] = {}

    @classmethod
    def from_file(cls, path: str | Path) -> Inventory:
        return cls(json.loads(Path(path).read_text()))

    @classmethod
    def from_enterprise(cls, enterprise: Any) -> Inventory:
        return cls(enterprise.inventory())

    # ------------------------------------------------------------------ identities
    def account_kind(self, account: str) -> str:
        if account in self.users:
            return "user"
        if account in self.admin_owner:
            return "admin"
        if account in self.service_accounts:
            return "service"
        if account in SYSTEM_ACCOUNTS:
            return "system"
        return "unknown"

    def resolve_account(self, raw: str) -> tuple[str, str]:
        """Canonical account name and its kind (user, admin, service, system, unknown)."""
        account = canonical_account(raw)
        return account, self.account_kind(account)

    def person_of(self, account: str) -> str | None:
        """Employee behind an account (the owner of an ``adm-`` account)."""
        if account in self.users:
            return account
        return self.admin_owner.get(account)

    # ------------------------------------------------------------------ assets
    def resolve_host(self, raw: str | None) -> str | None:
        if not raw:
            return None
        value = raw.strip()
        host_id = self.fqdn.get(value.lower())
        if host_id:
            return host_id
        upper = value.split(".")[0].upper()
        return upper if upper in self.hosts else None

    def static_host(self, ip: str) -> str | None:
        return self.static_ips.get(ip)

    def zone(self, ip: str) -> str:
        cached = self._zone_cache.get(ip)
        if cached is not None:
            return cached
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "invalid"
        zone = "external"
        for name, net in self.networks.items():
            if addr.version == net.version and addr in net:
                zone = name
                break
        if len(self._zone_cache) < 200_000:
            self._zone_cache[ip] = zone
        return zone

    def geoip(self, ip: str) -> GeoInfo | None:
        return self.geo.lookup(ip)
