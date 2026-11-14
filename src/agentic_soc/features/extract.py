"""Feature extraction for the three detectors from fired windows.

* M1 (sign-in anomaly): one row per account window and one per external source-IP window.
* M2 (flow classifier): one row per conversation (src, dst, port) in a source window, with
  beacon-regularity history and the source's fan-out in the same window.
* M3 (process rarity): one row per host window carrying its parent->child pairs.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from agentic_soc.features.history import ConversationHistory, DestinationPopularity
from agentic_soc.features.profiles import Profiles, haversine_km
from agentic_soc.features.resolver import EntityResolver
from agentic_soc.features.windows import Window
from agentic_soc.ingestion.inventory import Inventory
from agentic_soc.ingestion.models import NormFlow, NormProcess, NormSignin

M1_USER_FEATURES = [
    "n", "n_fail", "fail_ratio", "n_ips", "n_countries", "new_country_share", "new_ip_share",
    "new_asn_share", "hosting_share", "foreign_share", "hour_surprise", "weekend",
    "new_device_share", "legacy_share", "mfa_share", "new_app_share", "new_logon_type_share",
    "n_remote_interactive", "ntlm_share", "n_dst_hosts", "new_dst_host_share", "is_admin",
    "n_mfa_denied", "geo_km_max", "maturity",
]  # fmt: skip
M1_IP_FEATURES = [
    "n", "n_fail", "fail_ratio", "n_users", "n_unknown_users", "n_users_failed",
    "n_success_after_fail", "hosting", "anonymizer", "foreign", "known_ip", "n_apps",
    "legacy_share", "n_user_agents", "hour_surprise", "vpn_share",
]  # fmt: skip
M2_FEATURES = [
    "n_flows", "log_bytes_out", "log_bytes_in", "log_bytes_out_max", "log_out_in_ratio",
    "log_duration_mean", "blocked_share", "udp", "port_web", "port_smb", "port_rdp", "port_ssh",
    "port_db", "port_dns", "port_ldap", "port_rpc", "port_other", "dir_outbound", "dir_internal",
    "dir_inbound", "dst_hosting", "dst_anonymizer", "dst_cloud", "dst_cdn", "dst_isp",
    "dst_unknown_external", "src_corp", "src_datacenter", "src_dmz", "src_vpn", "src_external",
    "hist_n", "hist_interval_log", "hist_interval_cv", "hist_regularity", "hist_bytes_cv",
    "hist_span_h", "src_n_flows", "src_distinct_dsts", "src_distinct_ports", "src_small_share",
    "src_log_bytes_out", "src_n_external_dsts", "dst_popularity_log", "night", "hour_sin",
    "hour_cos",
]  # fmt: skip
M3_FEATURES = [
    "n", "n_distinct_pairs", "log_max_cmd_len", "encoded_cmds", "lolbins",
    "high_integrity_share", "system_share", "n_users", "admin_share",
]  # fmt: skip
FEATURES = {
    "M1-user": M1_USER_FEATURES,
    "M1-ip": M1_IP_FEATURES,
    "M2": M2_FEATURES,
    "M3": M3_FEATURES,
}

LOLBINS = {
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe",
    "psexesvc.exe", "7za.exe", "vssadmin.exe", "nltest.exe", "net.exe", "whoami.exe", "sqlcmd.exe",
}  # fmt: skip
ENCODED = re.compile(r"\s-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\s", re.IGNORECASE)
PORT_GROUPS = {
    80: "web", 443: "web", 8443: "web", 8080: "web", 445: "smb", 3389: "rdp", 22: "ssh",
    1433: "db", 3200: "db", 53: "dns", 389: "ldap", 88: "ldap", 135: "rpc", 5985: "rpc",
}  # fmt: skip


@dataclass(slots=True)
class FeatureRow:
    detector: str
    key: str
    window_start: datetime
    window_end: datetime
    users: list[str]
    hosts: list[str]
    ips: list[str]
    event_ids: list[str]
    features: dict[str, float]
    late: bool = False
    context: dict[str, Any] = field(default_factory=dict)

    def vector(self) -> list[float]:
        return [self.features[name] for name in FEATURES[self.detector]]


def host_class_of(inv: Inventory, host_id: str) -> str:
    """Peer group of a host for process baselines: workstations by owner role, servers by role."""
    info = inv.hosts.get(host_id)
    if info is None:
        return "unknown"
    if info.kind == "workstation":
        owner = inv.users.get(info.owner or "")
        return f"ws:{owner.role}" if owner else "ws"
    return f"srv:{info.role}"


def _uniq(values: Any) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


class FeatureExtractor:
    def __init__(self, inventory: Inventory, profiles: Profiles, resolver: EntityResolver) -> None:
        self.inv = inventory
        self.profiles = profiles
        self.resolver = resolver
        self._home: dict[str, tuple[float, float] | None] = {}

    # ------------------------------------------------------------------ M1
    def _home_location(self, account: str) -> tuple[float, float] | None:
        if account not in self._home:
            location = None
            profile = self.profiles.accounts.get(account)
            if profile:
                for ip, _ in profile.ips.most_common():
                    geo = self.inv.geoip(ip)
                    if geo is not None:
                        location = (geo.lat, geo.lon)
                        break
            self._home[account] = location
        return self._home[account]

    def m1_user(self, window: Window) -> FeatureRow:
        events: list[NormSignin] = window.events
        account = window.key.split(":", 1)[1]
        profile = self.profiles.accounts.get(account)
        n = len(events)

        def share(pred: Any) -> float:
            return sum(1 for e in events if pred(e)) / n

        fails = [e for e in events if e.outcome == "failure"]
        if profile is not None:
            new = {
                "new_country_share": share(lambda e: e.src_country and e.src_country not in profile.countries),
                "new_ip_share": share(lambda e: e.src_ip not in profile.ips),
                "new_asn_share": share(lambda e: e.src_asn is not None and str(e.src_asn) not in profile.asns),
                "new_device_share": share(lambda e: Profiles.device_of(e) and Profiles.device_of(e) not in profile.devices),
                "new_app_share": share(lambda e: e.app not in profile.apps),
                "new_logon_type_share": share(lambda e: e.logon_type not in profile.logon_types),
                "new_dst_host_share": share(lambda e: e.dst_host and e.dst_host not in profile.dst_hosts),
            }  # fmt: skip
            surprise = (
                sum(
                    -math.log2(profile.hour_prob(self.profiles.local_hour(e.event_time)))
                    for e in events
                )
                / n
            )
            maturity = math.log1p(profile.n)
        else:
            new = dict.fromkeys(
                ["new_country_share", "new_ip_share", "new_asn_share", "new_device_share",
                 "new_app_share", "new_logon_type_share", "new_dst_host_share"], 1.0)  # fmt: skip
            surprise, maturity = math.log2(24), 0.0
        home = self._home_location(account)
        geo_km = 0.0
        if home is not None:
            for e in events:
                if e.src_zone == "external":
                    geo = self.inv.geoip(e.src_ip)
                    if geo is not None:
                        geo_km = max(geo_km, haversine_km(home[0], home[1], geo.lat, geo.lon))
        home_country = self.inv.home_country
        features = {
            "n": float(n),
            "n_fail": float(len(fails)),
            "fail_ratio": len(fails) / n,
            "n_ips": float(len({e.src_ip for e in events})),
            "n_countries": float(len({e.src_country for e in events if e.src_country})),
            **new,
            "hosting_share": share(lambda e: e.src_category in {"hosting", "anonymizer"}),
            "foreign_share": share(
                lambda e: e.src_country is not None and e.src_country != home_country
            ),
            "hour_surprise": surprise,
            "weekend": float(self.profiles.local_weekday(window.start) >= 5),
            "legacy_share": share(lambda e: e.schema_version != "1.0" or e.source == "vpn-legacy"),
            "mfa_share": share(lambda e: e.mfa),
            "n_remote_interactive": float(
                sum(e.logon_type == "remote_interactive" for e in events)
            ),
            "ntlm_share": share(lambda e: e.auth_protocol == "ntlm"),
            "n_dst_hosts": float(len({e.dst_host for e in events if e.dst_host})),
            "is_admin": float(events[0].user_kind == "admin"),
            "n_mfa_denied": float(sum(e.failure_reason == "mfa_denied" for e in events)),
            "geo_km_max": geo_km / 1000.0,
            "maturity": maturity,
        }
        hosts = _uniq(e.dst_host for e in events)
        person = events[0].person

        def risky(e: NormSignin) -> bool:
            if e.src_category in {"hosting", "anonymizer"}:
                return True
            if profile is None:
                return e.src_zone == "external"
            return bool(
                (e.src_country and e.src_country not in profile.countries)
                or (e.src_asn is not None and str(e.src_asn) not in profile.asns)
            )

        # A success from an unusual source suggests someone else holds the credentials; failures
        # next to the owner's routine sign-ins only make the account a target.
        risky_success = any(e.outcome == "success" and risky(e) for e in events)
        if risky_success and person and person in self.inv.users and events[0].user_kind == "user":
            # ...and puts the account's own workstation at risk.
            hosts = _uniq([*hosts, self.inv.users[person].workstation])
        # Addresses that matter: where a suspicious success came from, else where attempts failed.
        external = [e for e in events if e.src_zone == "external"]
        if risky_success:
            ips = _uniq(e.src_ip for e in external if e.outcome == "success" and risky(e))
        else:
            ips = _uniq(e.src_ip for e in external if e.outcome == "failure")
        return FeatureRow(
            "M1-user", window.key, window.start, window.end,
            users=[account], hosts=hosts, ips=ips,
            event_ids=[e.event_id for e in events], features=features, late=window.late,
            context={
                "countries": _uniq(e.src_country for e in events),
                "orgs": _uniq(e.src_org for e in events),
                "logon_types": _uniq(e.logon_type for e in events),
                "outcomes": {"success": n - len(fails), "failure": len(fails)},
                "risky_success": risky_success,
            },
        )  # fmt: skip

    def m1_ip(self, window: Window) -> FeatureRow:
        events: list[NormSignin] = window.events
        ip = window.key.split(":", 1)[1]
        n = len(events)
        fails = [e for e in events if e.outcome == "failure"]
        failed_users = {e.user_id for e in fails}
        succeeded = {e.user_id for e in events if e.outcome == "success"}
        first = events[0]
        surprise = (
            sum(
                -math.log2(self.profiles.global_hour_prob(self.profiles.local_hour(e.event_time)))
                for e in events
            )
            / n
        )
        features = {
            "n": float(n),
            "n_fail": float(len(fails)),
            "fail_ratio": len(fails) / n,
            "n_users": float(len({e.user_id for e in events})),
            "n_unknown_users": float(len({e.user_id for e in events if e.user_kind == "unknown"})),
            "n_users_failed": float(len(failed_users)),
            "n_success_after_fail": float(len(succeeded & failed_users)),
            "hosting": float(first.src_category == "hosting"),
            "anonymizer": float(first.src_category == "anonymizer"),
            "foreign": float(
                first.src_country is not None and first.src_country != self.inv.home_country
            ),
            "known_ip": float(ip in self.profiles.known_ips),
            "n_apps": float(len({e.app for e in events})),
            "legacy_share": sum(
                e.schema_version != "1.0" or e.source == "vpn-legacy" for e in events
            )
            / n,
            "n_user_agents": float(len({e.user_agent for e in events})),
            "hour_surprise": surprise,
            "vpn_share": sum(e.logon_type == "vpn" for e in events) / n,
        }
        users = _uniq(
            e.user_id for e in events if e.user_kind != "unknown" and e.outcome == "success"
        )
        return FeatureRow(
            "M1-ip", window.key, window.start, window.end, users=users, hosts=[], ips=[ip],
            event_ids=[e.event_id for e in events], features=features, late=window.late,
            context={"org": first.src_org, "country": first.src_country, "category": first.src_category},
        )  # fmt: skip

    # ------------------------------------------------------------------ M2
    def m2(
        self, window: Window, history: ConversationHistory, popularity: DestinationPopularity
    ) -> list[FeatureRow]:
        flows: list[NormFlow] = window.events
        src_ip = window.key
        groups: dict[tuple[str, int], list[NormFlow]] = defaultdict(list)
        for f in flows:
            groups[(f.dst_ip, f.dst_port)].append(f)
        first = flows[0]
        src_host = (
            self.resolver.host_for_ip(src_ip, window.start)
            if first.src_zone != "external"
            else None
        )
        src_user = (
            self.resolver.user_for_ip(src_ip, window.start)
            if first.src_zone != "external"
            else None
        )
        hour = self.profiles.local_hour(window.start)
        src_bytes = sum(f.bytes_out for f in flows)
        src = {
            "src_n_flows": float(len(flows)),
            "src_distinct_dsts": float(len({f.dst_ip for f in flows})),
            "src_distinct_ports": float(len({f.dst_port for f in flows})),
            "src_small_share": sum(f.bytes_out + f.bytes_in < 400 for f in flows) / len(flows),
            "src_log_bytes_out": math.log1p(src_bytes),
            "src_n_external_dsts": float(len({f.dst_ip for f in flows if f.dst_zone == "external"})),
            "night": float(hour < 6 or hour >= 21),
            "hour_sin": math.sin(2 * math.pi * hour / 24),
            "hour_cos": math.cos(2 * math.pi * hour / 24),
            **{f"src_{z}": float(first.src_zone == z) for z in ("corp", "datacenter", "dmz", "vpn", "external")},
        }  # fmt: skip
        rows = []
        for (dst_ip, dst_port), conv in groups.items():
            c = conv[0]
            n = len(conv)
            out_b = sum(f.bytes_out for f in conv)
            in_b = sum(f.bytes_in for f in conv)
            group = PORT_GROUPS.get(dst_port, "other")
            category = c.dst_category if c.dst_zone == "external" else None
            features = {
                "n_flows": float(n),
                "log_bytes_out": math.log1p(out_b),
                "log_bytes_in": math.log1p(in_b),
                "log_bytes_out_max": math.log1p(max(f.bytes_out for f in conv)),
                "log_out_in_ratio": math.log1p(out_b) - math.log1p(in_b),
                "log_duration_mean": math.log1p(sum(f.duration_ms for f in conv) / n),
                "blocked_share": sum(f.fw_action == "blocked" for f in conv) / n,
                "udp": float(c.protocol == "udp"),
                **{f"port_{g}": float(group == g) for g in ("web", "smb", "rdp", "ssh", "db", "dns", "ldap", "rpc", "other")},
                "dir_outbound": float(c.direction == "outbound"),
                "dir_internal": float(c.direction == "internal"),
                "dir_inbound": float(c.direction == "inbound"),
                "dst_hosting": float(category == "hosting"),
                "dst_anonymizer": float(category == "anonymizer"),
                "dst_cloud": float(category == "cloud"),
                "dst_cdn": float(category == "cdn"),
                "dst_isp": float(category in {"isp", "mobile", "corporate"}),
                "dst_unknown_external": float(c.dst_zone == "external" and category is None),
                **history.stats(f"{src_ip}|{dst_ip}|{dst_port}", window.end),
                **src,
                "dst_popularity_log": math.log1p(popularity.popularity(dst_ip, window.end)) if c.dst_zone == "external" else 0.0,
            }  # fmt: skip
            hosts = _uniq([src_host, c.dst_host])
            ips = _uniq([src_ip, dst_ip])
            rows.append(
                FeatureRow(
                    "M2",
                    f"{src_ip}|{dst_ip}|{dst_port}",
                    window.start,
                    window.end,
                    users=_uniq([src_user]),
                    hosts=hosts,
                    ips=ips,
                    event_ids=[f.event_id for f in conv],
                    features=features,
                    late=window.late,
                    context={"dst_org": c.dst_org, "service": c.service, "src_host": src_host},
                )
            )
        return rows

    # ------------------------------------------------------------------ M3
    def host_class(self, host_id: str) -> str:
        return host_class_of(self.inv, host_id)

    def m3(self, window: Window) -> FeatureRow:
        events: list[NormProcess] = sorted(window.events, key=lambda e: (e.event_time, e.pid))
        host = window.key
        n = len(events)
        pairs = [(e.parent_name, e.process_name) for e in events]
        users = _uniq(e.user_id for e in events if e.user_kind in {"user", "admin"})
        features = {
            "n": float(n),
            "n_distinct_pairs": float(len(set(pairs))),
            "log_max_cmd_len": math.log1p(max(len(e.command_line) for e in events)),
            "encoded_cmds": float(sum(bool(ENCODED.search(f" {e.command_line} ")) for e in events)),
            "lolbins": float(sum(e.process_name in LOLBINS for e in events)),
            "high_integrity_share": sum(e.integrity in {"high", "system"} for e in events) / n,
            "system_share": sum(e.user_kind == "system" for e in events) / n,
            "n_users": float(len(users)),
            "admin_share": sum(e.user_kind == "admin" for e in events) / n,
        }
        return FeatureRow(
            "M3", f"host:{host}", window.start, window.end, users=users, hosts=[host], ips=[],
            event_ids=[e.event_id for e in events], features=features, late=window.late,
            context={"host_class": self.host_class(host), "pairs": pairs},
        )  # fmt: skip
