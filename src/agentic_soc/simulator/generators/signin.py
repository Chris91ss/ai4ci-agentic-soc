"""Benign sign-in stream: IdP SSO, VPN, domain-controller logons, admins and service accounts."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import numpy as np

from agentic_soc.simulator.activity import DayPlan
from agentic_soc.simulator.enterprise import Host, User
from agentic_soc.simulator.generators.base import GenContext, RdpSession
from agentic_soc.simulator.model import Label, SimEvent, iso
from agentic_soc.simulator.rng import rng_for

VPN_CLIENT_UA = "AnyConnect Windows 5.1.2.42"
_SAML_APPS = {"o365", "teams", "azure-portal", "workday", "sap"}
_LOGON_TARGETS = {"file": 0.35, "dc": 0.2, "app": 0.15, "mail": 0.1, "print": 0.08, "erp": 0.12}


class SigninGenerator:
    stream = "signin"

    def __init__(self, ctx: GenContext) -> None:
        self.ctx = ctx
        ent = ctx.ent
        self.cfg = ctx.config.activity.signin
        self.look = ctx.config.lookalikes
        self.realm = ent.config.org.domain.upper()
        self.typo_prob = ctx.calibration.signin_failure_rate * 0.6
        self.retry_fail_prob = ctx.calibration.signin_failure_rate * 0.3
        self.logon_targets: list[tuple[list[Host], float]] = [
            (ent.servers_by_role[r], w)
            for r, w in _LOGON_TARGETS.items()
            if r in ent.servers_by_role
        ]
        total = sum(w for _, w in self.logon_targets)
        self.logon_weights = np.asarray([w / total for _, w in self.logon_targets])
        self.rdp_targets = [h for h in ent.servers if h.os == "windows" and h.zone == "datacenter"]
        self.jump_hosts = ent.servers_by_role.get("jump", [])
        self._maintenance: dict[int, list[tuple[datetime, Host]]] = {}
        self._mobile_ips: dict[tuple[str, int], str] = {}

    # ------------------------------------------------------------------ helpers
    def principal(self, account: str) -> str:
        """Kerberos-style principal as logged by the domain controllers."""
        return f"{account}@{self.realm}"

    def make(
        self,
        t: datetime,
        user: str,
        src_ip: str,
        app: str,
        logon_type: str,
        auth_protocol: str,
        outcome: str = "success",
        *,
        source: str = "idp",
        failure_reason: str | None = None,
        mfa: bool = False,
        user_agent: str = "",
        device_id: str | None = None,
        dst_host: str | None = None,
        assigned_ip: str | None = None,
        tag: str | None = None,
        label: Label | None = None,
    ) -> SimEvent:
        payload: dict[str, Any] = {
            "event_id": self.ctx.ids.next("signin"),
            "schema_version": "1.0",
            "event_time": iso(t),
            "source": source,
            "user": user,
            "src_ip": src_ip,
            "app": app,
            "logon_type": logon_type,
            "auth_protocol": auth_protocol,
            "outcome": outcome,
            "mfa": mfa,
            "user_agent": user_agent,
        }
        geo = self.ctx.ent.geo.lookup(src_ip)
        if geo is not None:
            payload["country"], payload["city"] = geo.country, geo.city
        optional = {
            "failure_reason": failure_reason,
            "device_id": device_id,
            "dst_host": dst_host,
            "assigned_ip": assigned_ip,
        }
        payload.update({k: v for k, v in optional.items() if v is not None})
        if label is None and tag is not None:
            label = Label(False, tag=tag)
        return SimEvent("signin", t, payload, key=user.lower(), label=label)

    def guarded(
        self, t: datetime, account: str, src_ip: str, kwargs: dict[str, Any], retry: bool
    ) -> list[SimEvent]:
        """Apply containment to an interactive sign-in attempt, adding re-auth or retries."""
        control = self.ctx.control
        user_field = kwargs.pop("user")
        reason = kwargs.pop("retry_reason", "bad_password")
        if control.is_disabled(account, t):
            return [
                self.make(
                    t,
                    user_field,
                    src_ip,
                    outcome="failure",
                    failure_reason="account_disabled",
                    **kwargs,
                )
            ]
        if control.is_blocked(src_ip, t):
            return [
                self.make(
                    t, user_field, src_ip, outcome="failure", failure_reason="blocked_ip", **kwargs
                )
            ]
        events = []
        if control.needs_reauth(account, t):
            events.append(
                self.make(
                    t,
                    user_field,
                    src_ip,
                    outcome="failure",
                    failure_reason="session_revoked",
                    **kwargs,
                )
            )
            t = t + timedelta(seconds=25)
            kwargs["mfa"] = True
        if retry:
            events.append(
                self.make(
                    t,
                    user_field,
                    src_ip,
                    outcome="failure",
                    failure_reason=reason,
                    **kwargs | {"tag": "typo"},
                )
            )
            t = t + timedelta(seconds=12)
        events.append(self.make(t, user_field, src_ip, **kwargs))
        return events  # fmt: skip

    def desktop(self, user: User):
        return user.devices[0]

    def mobile(self, user: User):
        return user.devices[1] if len(user.devices) > 1 else user.devices[0]

    # ------------------------------------------------------------------ generation
    def generate(self, t0: datetime, dt: float) -> list[SimEvent]:
        ctx, ent, planner = self.ctx, self.ctx.ent, self.ctx.planner
        rng = ctx.tick_rng(self.stream, t0)
        t1 = t0 + timedelta(seconds=dt)
        local = ent.local(t0)
        hour = local.hour + local.minute / 60
        day = ent.day_index(t0)
        out: list[SimEvent] = []
        per_hour = dt / 3600.0
        for user in ent.users:
            plan = planner.plan(user, day)
            if plan.works and t0 <= plan.start < t1:
                out.extend(self.start_of_day(rng, user, plan))
            if plan.active(t0):
                factor = planner.intensity(hour, plan.shift_h) * (0.3 if plan.in_lunch(t0) else 1.0)
                for _ in range(rng.poisson(self.cfg.sso_per_hour * factor * per_hour)):
                    out.extend(
                        self.sso(rng, user, plan, t0 + timedelta(seconds=float(rng.random()) * dt))
                    )
                for _ in range(rng.poisson(self.cfg.network_logons_per_hour * factor * per_hour)):
                    out.extend(
                        self.network_logon(
                            rng, user, t0 + timedelta(seconds=float(rng.random()) * dt)
                        )
                    )
                if user.is_admin and self.look.admin_rdp:
                    rate = self.cfg.admin_rdp_per_day / max(user.work_len_h, 1.0)
                    for _ in range(rng.poisson(rate * per_hour)):
                        out.extend(
                            self.admin_rdp(
                                rng, user, t0 + timedelta(seconds=float(rng.random()) * dt)
                            )
                        )
            elif plan.after_hours and 19.0 <= hour < 23.0 and not (plan.works and t0 < plan.end):
                for _ in range(rng.poisson(self.cfg.mobile_checks_per_evening / 4.0 * per_hour)):
                    out.extend(
                        self.mobile_check(
                            rng, user, plan, t0 + timedelta(seconds=float(rng.random()) * dt)
                        )
                    )
        out.extend(self.service_accounts(rng, t0, dt))
        out.extend(self.maintenance(t0, t1))
        return out  # fmt: skip

    def start_of_day(self, rng: np.random.Generator, user: User, plan: DayPlan) -> list[SimEvent]:
        t = plan.start
        typo = self.look.typos and rng.random() < self.typo_prob
        out: list[SimEvent] = []
        if plan.vpn_ip:
            tag = "travel" if plan.trip else "remote_vpn"
            out += self.guarded(
                t, user.user_id, plan.public_ip,
                dict(user=user.upn, app="vpn", logon_type="vpn", auth_protocol="password",
                     source="vpn", mfa=True, user_agent=VPN_CLIENT_UA,
                     device_id=self.desktop(user).device_id, assigned_ip=plan.vpn_ip, tag=tag),
                retry=typo,
            )  # fmt: skip
            ws_ip = plan.vpn_ip
            typo = False
            t = t + timedelta(seconds=40)
        else:
            ws_ip = self.ctx.ent.dhcp_ip(user.workstation, t)
        out += self.guarded(
            t, user.user_id, ws_ip,
            dict(user=self.principal(user.user_id), app="workstation", logon_type="interactive",
                 auth_protocol="kerberos", source="dc", dst_host=user.workstation),
            retry=typo,
        )  # fmt: skip
        out += self.sso(
            rng, user, plan, t + timedelta(seconds=float(rng.uniform(20, 120))), app="o365"
        )
        return out

    def sso(
        self,
        rng: np.random.Generator,
        user: User,
        plan: DayPlan,
        t: datetime,
        app: str | None = None,
    ) -> list[SimEvent]:
        app = app or str(rng.choice(user.apps))
        on_mobile = rng.random() < self.ctx.calibration.mobile_share * 0.4
        device = self.mobile(user) if on_mobile else self.desktop(user)
        mfa = bool(rng.random() < self.cfg.mfa_prob)
        retry = self.look.typos and rng.random() < self.retry_fail_prob
        reason = "mfa_timeout" if rng.random() < 0.5 else "bad_password"
        tag = "travel" if plan.trip else None
        return self.guarded(
            t, user.user_id, plan.public_ip,
            dict(user=user.upn, app=app, logon_type="sso",
                 auth_protocol="saml" if app in _SAML_APPS else "oauth", mfa=mfa,
                 user_agent=device.user_agent, device_id=device.device_id, tag=tag,
                 retry_reason=reason),
            retry=retry,
        )  # fmt: skip

    def network_logon(self, rng: np.random.Generator, user: User, t: datetime) -> list[SimEvent]:
        src_ip = self.ctx.planner.workstation_ip(user.workstation, t)
        if src_ip is None:
            return []
        group = self.logon_targets[int(rng.choice(len(self.logon_targets), p=self.logon_weights))][
            0
        ]
        target = group[int(rng.integers(len(group)))]
        protocol = "ntlm" if rng.random() < 0.05 else "kerberos"
        if self.ctx.control.is_disabled(user.user_id, t):
            return [self.make(t, self.principal(user.user_id), src_ip, target.role, "network", protocol,
                              "failure", source="dc", failure_reason="account_disabled", dst_host=target.host_id)]  # fmt: skip
        return [self.make(t, self.principal(user.user_id), src_ip, target.role, "network", protocol,
                          source="dc", dst_host=target.host_id)]  # fmt: skip

    def admin_rdp(
        self, rng: np.random.Generator, user: User, t: datetime, tag: str = "admin_rdp"
    ) -> list[SimEvent]:
        ws_ip = self.ctx.planner.workstation_ip(user.workstation, t)
        if ws_ip is None or not self.rdp_targets or user.admin_account is None:
            return []
        target = self.rdp_targets[int(rng.integers(len(self.rdp_targets)))]
        via_jump = bool(self.jump_hosts) and rng.random() < 0.7
        duration = float(rng.uniform(300, 2400))
        return self.rdp_chain(user.admin_account, ws_ip, target, t, duration, via_jump, tag, rng)

    def rdp_chain(
        self,
        account: str,
        ws_ip: str,
        target: Host,
        t: datetime,
        duration: float,
        via_jump: bool,
        tag: str,
        rng: np.random.Generator,
    ) -> list[SimEvent]:
        out: list[SimEvent] = []
        hops: list[tuple[str, Host]] = []
        if via_jump:
            jump = self.jump_hosts[int(rng.integers(len(self.jump_hosts)))]
            hops = [(ws_ip, jump), (jump.static_ip or ws_ip, target)]
        else:
            hops = [(ws_ip, target)]
        for i, (src, dst) in enumerate(hops):
            ts = t + timedelta(seconds=45 * i)
            disabled = self.ctx.control.is_disabled(account, ts)
            out.append(
                self.make(ts, self.principal(account), src, "rdp", "remote_interactive", "kerberos",
                          "failure" if disabled else "success", source="dc",
                          failure_reason="account_disabled" if disabled else None,
                          dst_host=dst.host_id, tag=tag)
            )  # fmt: skip
            if not disabled:
                self.ctx.rdp_sessions.append(
                    RdpSession(src, dst.host_id, account, ts, duration, Label(False, tag=tag))
                )
        return out

    def mobile_check(
        self, rng: np.random.Generator, user: User, plan: DayPlan, t: datetime
    ) -> list[SimEvent]:
        device = self.mobile(user)
        src_ip = user.home_ip
        if rng.random() < 0.4:
            key = (user.user_id, plan.day)
            if key not in self._mobile_ips:
                carrier = rng_for(self.ctx.seed, "mobile-ip", user.user_id, plan.day)
                self._mobile_ips[key] = self.ctx.ent.allocator.take(carrier, "37.120.0.0/16")[0]
            src_ip = self._mobile_ips[key]
        if plan.trip:
            src_ip = plan.trip.ip
        app = "teams" if rng.random() < 0.3 else "o365"
        return self.guarded(
            t, user.user_id, src_ip,
            dict(user=user.upn, app=app, logon_type="sso", auth_protocol="oauth",
                 user_agent=device.user_agent, device_id=device.device_id, tag="mobile_after_hours"),
            retry=False,
        )  # fmt: skip

    def service_accounts(self, rng: np.random.Generator, t0: datetime, dt: float) -> list[SimEvent]:
        ent = self.ctx.ent
        out: list[SimEvent] = []
        per_hour = dt / 3600.0
        by_name = {s.name: s for s in ent.service_accounts}
        schedule = [
            ("svc_monitor", self.cfg.monitor_logons_per_hour),
            ("svc_sql", 12.0),
            ("svc_web", 5.0),
            ("svc_build", 2.0),
        ]
        for name, rate in schedule:
            account = by_name.get(name)
            if account is None or not account.source_hosts or not account.target_hosts:
                continue
            for _ in range(rng.poisson(rate * per_hour)):
                src = ent.hosts_by_id[
                    account.source_hosts[int(rng.integers(len(account.source_hosts)))]
                ]
                dst = account.target_hosts[int(rng.integers(len(account.target_hosts)))]
                t = t0 + timedelta(seconds=float(rng.random()) * dt)
                out.append(self.make(t, self.principal(name), src.static_ip or "", "service", "network",
                                     "kerberos", source="dc", dst_host=dst))  # fmt: skip
        backup = by_name.get("svc_backup")
        local = ent.local(t0)
        hour = local.hour + local.minute / 60
        if (
            self.look.nightly_backup
            and backup
            and backup.source_hosts
            and hour <= self.look.backup_start_h < hour + dt / 3600
        ):
            src = ent.hosts_by_id[backup.source_hosts[0]]
            for i, dst in enumerate(backup.target_hosts):
                t = t0 + timedelta(seconds=min(dt - 1, 2.0 * i))
                out.append(self.make(t, self.principal("svc_backup"), src.static_ip or "", "backup",
                                     "network", "kerberos", source="dc", dst_host=dst, tag="backup"))  # fmt: skip
        return out

    def maintenance(self, t0: datetime, t1: datetime) -> list[SimEvent]:
        """Patch night: one admin RDPs into many servers late in the evening (looks lateral)."""
        if not self.look.admin_rdp:
            return []
        ent = self.ctx.ent
        day = ent.day_index(t0)
        out: list[SimEvent] = []
        for d in (day - 1, day):
            for t, target, account, ws_ip in self.maintenance_plan(d):
                if t0 <= t < t1:
                    rng = rng_for(self.ctx.seed, "maint", d, target.host_id)
                    out += self.rdp_chain(account, ws_ip, target, t, float(rng.uniform(600, 1800)),
                                          True, "admin_maintenance", rng)  # fmt: skip
        return out

    def maintenance_plan(self, day: int) -> list[tuple[datetime, Host, str, str]]:
        if day < 0:
            return []
        if day in self._maintenance:
            return self._maintenance[day]  # type: ignore[return-value]
        ent = self.ctx.ent
        midnight = ent.day_start(day)
        plan: list = []
        admins = ent.admins
        if (
            midnight.weekday() == self.look.admin_maintenance_weekday
            and admins
            and self.rdp_targets
        ):
            rng = rng_for(self.ctx.seed, "maintenance", day)
            admin = admins[int(rng.integers(len(admins)))]
            n = int(rng.integers(8, 16))
            targets = rng.choice(
                len(self.rdp_targets), size=min(n, len(self.rdp_targets)), replace=False
            )
            t = midnight + timedelta(hours=22, minutes=float(rng.uniform(0, 30)))
            ws_ip = ent.dhcp_ip(admin.workstation, t)
            for i in targets:
                plan.append((t, self.rdp_targets[int(i)], admin.admin_account, ws_ip))
                t += timedelta(minutes=float(rng.uniform(6, 15)))
        self._maintenance[day] = plan
        return plan
