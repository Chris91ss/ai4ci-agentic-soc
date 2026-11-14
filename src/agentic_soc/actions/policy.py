"""Policy gate for containment actions: allow-list, targets, protected assets, impact, limits."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal

from agentic_soc.ingestion.inventory import Inventory
from agentic_soc.schemas import ACTION_IMPACT, ACTION_TARGET_KIND

PROTECTED_ROLES = {"dc", "edr", "vpn", "proxy", "monitoring", "backup", "wsus", "mail"}
PROTECTED_ORGS = {
    "Microsoft",
    "Google",
    "GitHub",
    "Zoom",
    "Salesforce",
    "Atlassian",
    "Cloudflare",
    "Fastly",
}

Outcome = Literal["execute", "pending_approval", "deny"]


@dataclass
class PolicyConfig:
    auto_approve_high_impact: bool = False  # unattended evaluation runs only
    max_actions_per_incident: int = 6
    max_auto_actions_per_hour: int = 12
    protected_roles: set[str] = field(default_factory=lambda: set(PROTECTED_ROLES))
    protected_orgs: set[str] = field(default_factory=lambda: set(PROTECTED_ORGS))


@dataclass(frozen=True, slots=True)
class Verdict:
    outcome: Outcome
    reason: str
    target: str  # normalised target


class PolicyGate:
    def __init__(self, inventory: Inventory, config: PolicyConfig | None = None) -> None:
        self.inv = inventory
        self.cfg = config or PolicyConfig()
        self._auto: list[datetime] = []

    def normalise(self, action_type: str, target: str) -> str:
        value = target.strip()
        for prefix in ("user:", "host:", "ip:"):
            if value.lower().startswith(prefix):
                value = value[len(prefix) :]
        kind = ACTION_TARGET_KIND.get(action_type)
        if kind == "user":
            return value.split("\\")[-1].split("@")[0].lower()
        if kind == "host":
            return self.inv.resolve_host(value) or value.upper()
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value

    def check_target(self, action_type: str, target: str) -> str | None:
        """Reason the target is unacceptable, or None."""
        kind = ACTION_TARGET_KIND[action_type]
        if kind == "user":
            account_kind = self.inv.account_kind(target)
            if account_kind == "unknown":
                return f"unknown account {target!r}"
            if account_kind in {"service", "system"}:
                return f"{target} is a {account_kind} account; disabling or revoking it breaks business processes"
            return None
        if kind == "host":
            host = self.inv.hosts.get(target)
            if host is None:
                return f"unknown host {target!r}"
            if host.kind == "server" and host.role in self.cfg.protected_roles:
                return f"{target} is protected infrastructure ({host.role}); only an analyst may isolate it"
            return None
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return f"{target!r} is not an IP address"
        if self.inv.zone(target) != "external":
            return f"{target} is an internal address; block_ip only applies at the perimeter"
        if target in self.inv.office_egress.values():
            return f"{target} is a company office NAT address"
        geo = self.inv.geoip(target)
        if geo is not None and geo.org in self.cfg.protected_orgs:
            return f"{target} belongs to {geo.org}, a business-critical provider"
        return None

    def evaluate(
        self,
        action_type: str,
        target: str,
        requested_by: str,
        now: datetime,
        incident_actions: int = 0,
        dry_run: bool = False,
    ) -> Verdict:
        """``dry_run`` previews the verdict without counting against the automatic-action rate."""
        if action_type not in ACTION_IMPACT:
            return Verdict("deny", f"{action_type!r} is not on the action allow-list", target)
        normalised = self.normalise(action_type, target)
        problem = self.check_target(action_type, normalised)
        if problem and not (requested_by == "analyst" and "protected infrastructure" in problem):
            return Verdict("deny", problem, normalised)
        if requested_by != "analyst" and incident_actions >= self.cfg.max_actions_per_incident:
            return Verdict(
                "deny", f"incident already has {incident_actions} actions (limit)", normalised
            )
        if requested_by == "analyst":
            return Verdict("execute", "requested by an analyst", normalised)
        impact = ACTION_IMPACT[action_type]
        if impact == "high" and not self.cfg.auto_approve_high_impact:
            return Verdict(
                "pending_approval", "high-impact action needs analyst approval", normalised
            )
        self._auto = [t for t in self._auto if now - t < timedelta(hours=1)]
        if len(self._auto) >= self.cfg.max_auto_actions_per_hour:
            return Verdict(
                "pending_approval",
                "automatic action rate limit reached; analyst approval needed",
                normalised,
            )
        if not dry_run:
            self._auto.append(now)
        reason = (
            "low-impact action"
            if impact == "low"
            else "high-impact action auto-approved (unattended run)"
        )
        return Verdict("execute", reason, normalised)
