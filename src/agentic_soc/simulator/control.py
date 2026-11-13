"""Containment state of the simulated environment (the control interface).

Executed actions change what the generators emit next: disabled accounts can no longer sign
in, revoked sessions force a re-authentication, isolated hosts stop emitting flows (except
to the EDR server) and blocked external IPs are dropped at the perimeter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class AppliedAction:
    type: str
    target: str
    at: datetime
    action_id: str | None = None


@dataclass
class ControlState:
    disabled_accounts: dict[str, datetime] = field(default_factory=dict)
    revoked_sessions: dict[str, datetime] = field(default_factory=dict)
    isolated_hosts: dict[str, datetime] = field(default_factory=dict)
    blocked_ips: dict[str, datetime] = field(default_factory=dict)
    history: list[AppliedAction] = field(default_factory=list)
    _reauth_done: set[tuple[str, datetime]] = field(default_factory=set)

    def apply(
        self, action_type: str, target: str, at: datetime, action_id: str | None = None
    ) -> bool:
        """Apply an action; returns False for unknown types or no-op repeats."""
        table = {
            "disable_account": self.disabled_accounts,
            "revoke_sessions": self.revoked_sessions,
            "isolate_host": self.isolated_hosts,
            "block_ip": self.blocked_ips,
        }.get(action_type)
        if table is None:
            return False
        if action_type != "revoke_sessions" and target in table:
            return False
        table[target] = at
        self.history.append(AppliedAction(action_type, target, at, action_id))
        return True

    def is_disabled(self, account: str, t: datetime) -> bool:
        since = self.disabled_accounts.get(account)
        return since is not None and t >= since

    def is_isolated(self, host_id: str, t: datetime) -> bool:
        since = self.isolated_hosts.get(host_id)
        return since is not None and t >= since

    def is_blocked(self, ip: str, t: datetime) -> bool:
        since = self.blocked_ips.get(ip)
        return since is not None and t >= since

    def revoked_after(self, account: str, since: datetime) -> datetime | None:
        """Time of a session revocation after ``since`` (the session's start), if any."""
        at = self.revoked_sessions.get(account)
        return at if at is not None and at > since else None

    def needs_reauth(self, account: str, t: datetime) -> bool:
        """True once per revocation: the next sign-in after it must re-authenticate."""
        at = self.revoked_sessions.get(account)
        if at is None or t < at or (account, at) in self._reauth_done:
            return False
        self._reauth_done.add((account, at))
        return True
