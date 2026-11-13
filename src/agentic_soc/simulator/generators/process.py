"""Benign endpoint process stream (EDR telemetry) for workstations and servers."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import numpy as np

from agentic_soc.simulator.enterprise import Host
from agentic_soc.simulator.generators.base import GenContext
from agentic_soc.simulator.generators.process_catalog import (
    BACKUP_JOB,
    COMMAND_LINES,
    IMAGE_DIRS,
    LINUX_DIRS,
    LINUX_SERVER_COMMON,
    LOGON_TREE,
    RDP_SESSION_TOOLS,
    RDP_SESSION_TREE,
    ROLE_EXTRA,
    SERVER_ROLE,
    SYSTEM_PROCESSES,
    WINDOWS_SERVER_COMMON,
    WORKSTATION_COMMON,
    Launch,
)
from agentic_soc.simulator.model import Label, SimEvent, iso
from agentic_soc.simulator.rng import rng_for

_SCRIPTS = ["backup-check", "disk-usage", "rotate-logs", "sync-time"]


def _table(entries: list[Launch]) -> tuple[list[tuple[str, str]], np.ndarray]:
    pairs = [(p, c) for p, c, _ in entries]
    weights = np.asarray([w for *_, w in entries], dtype=float)
    return pairs, weights / weights.sum()


class ProcessGenerator:
    stream = "process"

    def __init__(self, ctx: GenContext) -> None:
        self.ctx = ctx
        ent = ctx.ent
        self.netbios = ent.config.org.netbios
        self.role_tables = {
            role: _table(WORKSTATION_COMMON + ROLE_EXTRA.get(role, []))
            for role in ent.config.org.roles
        }
        self.server_tables: dict[str, tuple[list[tuple[str, str]], np.ndarray]] = {}
        for host in ent.servers:
            base = WINDOWS_SERVER_COMMON if host.os == "windows" else LINUX_SERVER_COMMON
            self.server_tables[host.role] = _table(base + SERVER_ROLE.get(host.role, []))
        self.rdp_tools = _table(RDP_SESSION_TOOLS)
        self.pids: dict[str, int] = {}
        self.parents: dict[tuple[str, str], int] = {}
        self._backup_nights: set[tuple[str, int]] = set()

    # ------------------------------------------------------------------ helpers
    def next_pid(self, host_id: str, rng: np.random.Generator) -> int:
        pid = self.pids.get(host_id)
        if pid is None:
            pid = int(rng_for(self.ctx.seed, "pid", host_id).integers(1000, 6000))
        pid += 4 * int(rng.integers(1, 100))
        if pid > 65000:
            pid = 1000 + pid % 1000
        self.pids[host_id] = pid
        return pid

    def account(self, host: Host, child: str, user: str | None) -> str:
        if host.os == "linux":
            return "root" if user is None else user
        if user is None or child in SYSTEM_PROCESSES:
            return "NT AUTHORITY\\SYSTEM"
        return f"{self.netbios}\\{user}"

    def command_line(
        self, host: Host, child: str, user: str | None, rng: np.random.Generator
    ) -> tuple[str, str]:
        directory = IMAGE_DIRS.get(child) or LINUX_DIRS.get(child)
        if directory is None:
            directory = "/usr/bin" if host.os == "linux" else r"C:\Windows\System32"
        sep = "/" if host.os == "linux" else "\\"
        image = f"{directory}{sep}{child}".replace("{user}", user or "Default")
        templates = COMMAND_LINES.get(child)
        if not templates:
            return (f'"{image}"' if host.os == "windows" else image), image
        template = templates[int(rng.integers(len(templates)))]
        others = self.ctx.ent.users
        cmd = template.format(
            image=image,
            user=user or "Default",
            n=int(rng.integers(1, 999)),
            k=int(rng.integers(1, 4)),
            other=others[int(rng.integers(len(others)))].user_id,
            script=_SCRIPTS[int(rng.integers(len(_SCRIPTS)))],
        )
        return cmd, image

    def make(
        self,
        t: datetime,
        host: Host,
        parent: str,
        child: str,
        user: str | None,
        rng: np.random.Generator,
        *,
        command_line: str | None = None,
        integrity: str | None = None,
        tag: str | None = None,
        label: Label | None = None,
    ) -> SimEvent:
        pid = self.next_pid(host.host_id, rng)
        ppid = self.parents.get((host.host_id, parent))
        if ppid is None:
            ppid = max(4, pid - 4 * int(rng.integers(1, 50)))
            self.parents[(host.host_id, parent)] = ppid
        self.parents[(host.host_id, child)] = pid
        cmd, image = self.command_line(host, child, user, rng)
        account = self.account(host, child, user)
        if integrity is None:
            integrity = (
                "system" if account.startswith("NT AUTHORITY") or account == "root" else "medium"
            )
        payload: dict[str, Any] = {
            "event_id": self.ctx.ids.next("process"),
            "schema_version": "1.0",
            "event_time": iso(t),
            "source": "edr",
            "host": host.fqdn,
            "user": account,
            "pid": pid,
            "ppid": ppid,
            "process_name": child,
            "parent_name": parent,
            "command_line": command_line if command_line is not None else cmd,
            "image_path": image,
            "integrity": integrity,
        }
        if label is None and tag is not None:
            label = Label(False, tag=tag)
        return SimEvent("process", t, payload, key=host.fqdn, label=label)

    # ------------------------------------------------------------------ generation
    def generate(self, t0: datetime, dt: float) -> list[SimEvent]:
        ctx, ent, planner = self.ctx, self.ctx.ent, self.ctx.planner
        rng = ctx.tick_rng(self.stream, t0)
        t1 = t0 + timedelta(seconds=dt)
        local = ent.local(t0)
        hour = local.hour + local.minute / 60
        day = ent.day_index(t0)
        per_hour = dt / 3600.0
        rate = ctx.calibration.processes_per_host_hour
        out: list[SimEvent] = []
        for host in ent.workstations:
            user = ent.users_by_id[host.owner]  # type: ignore[index]
            plan = planner.plan(user, day)
            if plan.works and t0 <= plan.start < t1:
                for i, (parent, child) in enumerate(LOGON_TREE):
                    out.append(
                        self.make(
                            plan.start + timedelta(seconds=50 + 2 * i),
                            host,
                            parent,
                            child,
                            user.user_id,
                            rng,
                        )
                    )
            if not plan.active(t0):
                continue
            factor = planner.intensity(hour, plan.shift_h) * (0.3 if plan.in_lunch(t0) else 1.0)
            pairs, p = self.role_tables[user.role]
            for _ in range(rng.poisson(rate * factor * per_hour)):
                parent, child = pairs[int(rng.choice(len(pairs), p=p))]
                integrity = (
                    "high" if user.is_admin and child in {"mmc.exe", "powershell.exe"} else None
                )
                out.append(self.make(t0 + timedelta(seconds=float(rng.random()) * dt), host, parent, child,
                                     user.user_id, rng, integrity=integrity))  # fmt: skip
        factor = ctx.server_factor(t0)
        for host in ent.servers:
            pairs, p = self.server_tables[host.role]
            for _ in range(
                rng.poisson(ctx.config.activity.process.server_per_hour * factor * per_hour)
            ):
                parent, child = pairs[int(rng.choice(len(pairs), p=p))]
                user = None
                if host.os == "linux" and child in {"bash", "python3", "curl"}:
                    user = "svc-" + host.role
                out.append(
                    self.make(
                        t0 + timedelta(seconds=float(rng.random()) * dt),
                        host,
                        parent,
                        child,
                        user,
                        rng,
                    )
                )
        out.extend(self.rdp_sessions(rng, t0, t1))
        out.extend(self.backup_jobs(rng, t0, t1, hour, day))
        return out  # fmt: skip

    def rdp_sessions(self, rng: np.random.Generator, t0: datetime, t1: datetime) -> list[SimEvent]:
        out: list[SimEvent] = []
        for session in self.ctx.rdp_sessions:
            if not (t0 <= session.start < t1):
                continue
            host = self.ctx.ent.hosts_by_id[session.target]
            if session.label is not None and session.label.malicious:
                continue  # malicious sessions get their own process activity from the campaign
            t = session.start + timedelta(seconds=3)
            for i, (parent, child) in enumerate(RDP_SESSION_TREE):
                out.append(self.make(t + timedelta(seconds=i), host, parent, child, session.account, rng,
                                     label=session.label))  # fmt: skip
            pairs, p = self.rdp_tools
            for j in range(int(rng.integers(1, 4))):
                parent, child = pairs[int(rng.choice(len(pairs), p=p))]
                out.append(self.make(t + timedelta(seconds=30 + 60 * j), host, parent, child, session.account,
                                     rng, integrity="high", label=session.label))  # fmt: skip
        return out

    def backup_jobs(
        self, rng: np.random.Generator, t0: datetime, t1: datetime, hour: float, day: int
    ) -> list[SimEvent]:
        look = self.ctx.config.lookalikes
        if not look.nightly_backup:
            return []
        dt_h = (t1 - t0).total_seconds() / 3600
        if not (hour <= look.backup_start_h < hour + dt_h):
            return []
        out: list[SimEvent] = []
        for host in self.ctx.ent.servers_by_role.get("backup", []):
            if (host.host_id, day) in self._backup_nights:
                continue
            self._backup_nights.add((host.host_id, day))
            for i, (parent, child) in enumerate(BACKUP_JOB):
                out.append(
                    self.make(
                        t0 + timedelta(seconds=5 + 3 * i),
                        host,
                        parent,
                        child,
                        None,
                        rng,
                        tag="backup",
                    )
                )
        return out
