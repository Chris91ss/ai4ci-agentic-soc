"""A verifier for the triage agent's containment actions (a stretch goal of the RFC).

Before an action the agent proposed is executed, a second, independent check asks whether the
evidence the agent cited actually ties the target to the attack in a way that justifies this kind
of containment. It is deterministic on purpose: it reads the cited alerts (and the alerts holding
cited events), never the agent's rationale, so it cannot be talked into an action.

- block_ip: the address sprayed passwords, signed in to an account as valid-account use, or is
  the external end of command-and-control or exfiltration traffic, and it is not the company's own
  or a cloud/CDN address;
- revoke_sessions / disable_account: the account was used from attacker-like infrastructure
  (hosting or anonymiser networks, or an address that sprayed) or from inside the network, or ran
  attacker tooling on a host;
- isolate_host: the host ran late-stage activity (credential dumping, attacker tooling, lateral
  movement) or is the internal end of command-and-control or exfiltration traffic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from agentic_soc.agent.scripted import C2_EXFIL, HOST_COMPROMISE, LATE

PRIVATE = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)")
ATTACKER_NETWORKS = {"hosting", "anonymizer"}
SHARED_NETWORKS = {"cloud", "cdn", "corporate"}
LATERAL = {"T1021.001", "T1021.002", "T1569.002"}


@dataclass(frozen=True)
class Review:
    approved: bool
    reason: str


class EvidenceVerifier:
    def __init__(self, inventory: Any, resolver: Any = None) -> None:
        self.inv = inventory
        self.resolver = resolver  # address -> host at a time (DHCP and VPN leases)

    def _category(self, ip: str) -> str | None:
        if ip in self.inv.office_egress.values():
            return "corporate"
        geo = self.inv.geoip(ip)
        return geo.category if geo is not None else None

    def _attacker_like(self, ip: str, spray_sources: set[str]) -> bool:
        return (
            bool(PRIVATE.match(ip))
            or ip in spray_sources
            or self._category(ip) in ATTACKER_NETWORKS
        )

    @staticmethod
    def cited_alerts(alerts: list[Any], cited: set[str]) -> list[Any]:
        """The alerts the decision cites, directly or through one of their events."""
        return [a for a in alerts if a.alert_id in cited or cited.intersection(a.event_ids)]

    def review(self, action_type: str, target: str, alerts: list[Any], cited: set[str]) -> Review:
        backing = self.cited_alerts(alerts, cited)
        if not backing:
            return Review(False, "the decision cites no alert or event of this incident")
        spray_sources = {ip for a in alerts if "T1110.003" in a.techniques for ip in a.entities.ips}
        for alert in backing:
            t = set(alert.techniques)
            ips, hosts, users = alert.entities.ips, alert.entities.hosts, alert.entities.users
            if action_type == "block_ip" and target in ips:
                if PRIVATE.match(target) or self._category(target) in SHARED_NETWORKS:
                    return Review(
                        False, f"{target} is an internal, corporate or shared cloud address"
                    )
                if "T1110.003" in t or ("T1078" in t and alert.detector == "M1"):
                    return Review(
                        True,
                        f"{target} sprayed or signed in as a stolen account ({alert.alert_id})",
                    )
                if alert.detector == "M2" and t & C2_EXFIL and len(ips) > 1 and ips[1] == target:
                    return Review(
                        True, f"{target} is the far end of C2 or exfiltration ({alert.alert_id})"
                    )
            if action_type in {"revoke_sessions", "disable_account"} and target in users:
                if t & (HOST_COMPROMISE | LATERAL):
                    return Review(True, f"{target} ran attacker tooling ({alert.alert_id})")
                attacker = not ips or any(self._attacker_like(ip, spray_sources) for ip in ips)
                if "T1078" in t and alert.detector == "M1" and attacker:
                    return Review(
                        True,
                        f"{target} signed in from attacker-like infrastructure ({alert.alert_id})",
                    )
            if action_type == "isolate_host" and target in hosts and t & (LATE - C2_EXFIL):
                return Review(True, f"{target} ran late-stage activity ({alert.alert_id})")
            if action_type == "isolate_host" and alert.detector == "M2" and t & C2_EXFIL:
                source = hosts[0] if hosts else None
                if source is None and ips and self.resolver is not None:
                    source = self.resolver.host_for_ip(ips[0], alert.window_end)
                if source == target:
                    return Review(True, f"{target} talks to C2 or exfiltrates ({alert.alert_id})")
        return Review(
            False,
            f"no cited alert ties {target} to the attack in a way that justifies {action_type}",
        )
