"""Benign network-flow stream observed by the core/datacenter sensors and the edge firewall."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta
from typing import Any

import numpy as np

from agentic_soc.simulator.catalog import NETBLOCKS
from agentic_soc.simulator.distributions import heavy_tailed, lognormal
from agentic_soc.simulator.enterprise import ExternalService, Host, zone_of_ip
from agentic_soc.simulator.generators.base import GenContext
from agentic_soc.simulator.model import Label, SimEvent, iso
from agentic_soc.simulator.rng import rng_for

ROLE_SERVICE_BOOST: dict[str, dict[str, float]] = {
    "engineering": {"github": 3.0, "dev-staging": 3.0, "package-mirror": 3.0, "aws-console": 2.0},
    "sales": {"salesforce": 3.0, "zoom": 2.0},
    "executive": {"salesforce": 2.0, "zoom": 2.0},
    "support": {"slack": 2.0, "cloudflare-cdn": 1.5},
    "it_admin": {"azure-ad": 2.0, "github": 1.5},
    "marketing": {"cloudflare-cdn": 2.0, "fastly-cdn": 2.0},
}
INTERNAL_TARGETS: list[tuple[str, int, str, float]] = [
    # (server role, port, protocol, weight)
    ("dc", 53, "udp", 0.18),
    ("dc", 88, "tcp", 0.12),
    ("dc", 389, "tcp", 0.10),
    ("file", 445, "tcp", 0.30),
    ("app", 443, "tcp", 0.12),
    ("mail", 443, "tcp", 0.10),
    ("print", 9100, "tcp", 0.02),
    ("erp", 3200, "tcp", 0.06),
]
CLIENT_BLOCKS = [b.cidr for b in NETBLOCKS if b.category in {"isp", "mobile"}]


class FlowGenerator:
    stream = "flow"

    def __init__(self, ctx: GenContext) -> None:
        self.ctx = ctx
        ent = ctx.ent
        self.cfg = ctx.config.activity.flow
        self.look = ctx.config.lookalikes
        cal = ctx.calibration
        self.bytes_dist = cal.flow_bytes
        self.dur_dist = cal.flow_duration_ms
        self.services = ent.services
        visible = [s for s in self.services.values() if s.popularity > 0]
        if not self.look.dev_hosting:
            visible = [s for s in visible if s.name not in {"dev-staging", "package-mirror"}]
        self.role_services: dict[str, tuple[list[ExternalService], np.ndarray]] = {}
        for role in ent.config.org.roles:
            boost = ROLE_SERVICE_BOOST.get(role, {})
            weights = np.asarray([s.popularity * boost.get(s.name, 1.0) for s in visible])
            self.role_services[role] = (visible, weights / weights.sum())
        self.internal = [
            (ent.servers_by_role.get(r, []), port, proto, w)
            for r, port, proto, w in INTERNAL_TARGETS
        ]
        self.internal = [x for x in self.internal if x[0]]
        weights = np.asarray([w for *_, w in self.internal])
        self.internal_p = weights / weights.sum()
        edr = ent.servers_by_role.get("edr", [])
        self.edr_ip = edr[0].static_ip if edr else None
        vpn = ent.servers_by_role.get("vpn", [])
        self.vpn_ip = vpn[0].static_ip if vpn else None
        self.phase = {
            h.host_id: float(rng_for(ctx.seed, "phase", h.host_id).uniform(0, self.cfg.heartbeat_s))
            for h in ent.hosts
        }  # fmt: skip
        self._nights: dict[int, list[tuple[datetime, dict[str, Any]]]] = {}

    # ------------------------------------------------------------------ record construction
    def make(
        self,
        t: datetime,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        bytes_out: float,
        bytes_in: float,
        duration_ms: float,
        rng: np.random.Generator,
        protocol: str = "tcp",
        src_port: int | None = None,
        tag: str | None = None,
        label: Label | None = None,
    ) -> SimEvent:
        control = self.ctx.control
        bytes_out, bytes_in = int(bytes_out), int(bytes_in)
        blocked = control.is_blocked(dst_ip, t) or control.is_blocked(src_ip, t)
        if src_port is None:
            src_port = int(rng.integers(49152, 65535))
        if blocked:
            bytes_out, bytes_in, duration_ms = min(bytes_out, 180), 0, 0
        external = zone_of_ip(src_ip) == "external" or zone_of_ip(dst_ip) == "external"
        datacenter = "datacenter" in {zone_of_ip(src_ip), zone_of_ip(dst_ip)}
        sensor = "fw-edge-01" if external else ("sensor-dc-01" if datacenter else "sensor-core-01")
        payload = {
            "event_id": self.ctx.ids.next("flow"),
            "schema_version": "1.0",
            "event_time": iso(t),
            "source": sensor,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": int(dst_port),
            "protocol": protocol,
            "duration_ms": int(duration_ms),
            "bytes_out": bytes_out,
            "bytes_in": bytes_in,
            "packets_out": 3 if blocked else max(1, bytes_out // 1100 + 1),
            "packets_in": 0 if blocked else max(1, bytes_in // 1100 + 1) if bytes_in else 0,
            "fw_action": "blocked" if blocked else "allowed",
        }
        if label is None and tag is not None:
            label = Label(False, tag=tag)
        return SimEvent("flow", t, payload, key=src_ip, label=label)

    def sizes(self, rng: np.random.Generator, scale: float = 1.0) -> tuple[float, float, float]:
        d = self.bytes_dist
        down = (
            float(
                heavy_tailed(rng, 1, d.median, d.sigma, d.tail_prob, d.tail_alpha, d.tail_xmin)[0]
            )
            * scale
        )
        up = max(300.0, down * float(lognormal(rng, 0.08, 1.0)))
        dd = self.dur_dist
        duration = float(
            heavy_tailed(rng, 1, dd.median, dd.sigma, dd.tail_prob, dd.tail_alpha, dd.tail_xmin)[0]
        )
        duration += down / 5e6 * 1000  # ~5 MB/s effective throughput
        return up, down, duration  # fmt: skip

    # ------------------------------------------------------------------ generation
    def generate(self, t0: datetime, dt: float) -> list[SimEvent]:
        ctx, ent, planner = self.ctx, self.ctx.ent, self.ctx.planner
        rng = ctx.tick_rng(self.stream, t0)
        t1 = t0 + timedelta(seconds=dt)
        local = ent.local(t0)
        hour = local.hour + local.minute / 60
        day = ent.day_index(t0)
        per_hour = dt / 3600.0
        out: list[SimEvent] = []
        for host in ent.workstations:
            user = ent.users_by_id[host.owner]  # type: ignore[index]
            plan = planner.plan(user, day)
            ip = planner.workstation_ip(host.host_id, t0)
            n_web = n_int = 0
            if plan.active(t0):
                factor = planner.intensity(hour, plan.shift_h) * (0.3 if plan.in_lunch(t0) else 1.0)
                n_web = int(rng.poisson(self.cfg.web_per_hour * factor * per_hour))
                n_int = int(rng.poisson(self.cfg.internal_per_hour * factor * per_hour))
            if ip is None or ctx.control.is_isolated(host.host_id, t0):
                n_web = n_int = 0
            if plan.remote:
                n_web = 0  # split tunnel: home internet traffic never reaches corporate sensors
            for _ in range(n_web):
                out.append(
                    self.web_flow(
                        rng, ip, user.role, t0 + timedelta(seconds=float(rng.random()) * dt)
                    )
                )  # type: ignore[arg-type]
            for _ in range(n_int):
                out.append(
                    self.internal_flow(rng, ip, t0 + timedelta(seconds=float(rng.random()) * dt))
                )  # type: ignore[arg-type]
            if ip is not None:
                out.extend(self.heartbeats(rng, host, ip, t0, t1))
            if plan.works and plan.vpn_ip and self.vpn_ip and t0 <= plan.start < t1:
                out.append(
                    self.vpn_tunnel(
                        rng, plan.public_ip, plan.start, plan.end, plan.trip is not None
                    )
                )
            if (
                user.role == "engineering"
                and self.look.dev_hosting
                and plan.active(t0)
                and ip is not None
                and not plan.remote
                and rng.random() < 0.3 / max(user.work_len_h, 1) * per_hour
            ):
                out.append(
                    self.dev_deploy(rng, ip, t0 + timedelta(seconds=float(rng.random()) * dt))
                )
        out.extend(self.server_flows(rng, t0, t1, dt))
        out.extend(self.rdp_flows(rng, t0, t1))
        out.extend(self.backups(t0, t1))
        return out  # fmt: skip

    def web_flow(self, rng: np.random.Generator, src_ip: str, role: str, t: datetime) -> SimEvent:
        services, p = self.role_services[role]
        svc = services[int(rng.choice(len(services), p=p))]
        dst = svc.ips[int(rng.integers(len(svc.ips)))]
        port = svc.ports[0] if len(svc.ports) == 1 or rng.random() < 0.85 else svc.ports[1]
        protocol = "udp" if svc.name in {"teams", "zoom"} and rng.random() < 0.3 else "tcp"
        up, down, duration = self.sizes(rng, svc.bytes_scale)
        return self.make(t, src_ip, dst, port, up, down, duration, rng, protocol)

    def internal_flow(self, rng: np.random.Generator, src_ip: str, t: datetime) -> SimEvent:
        hosts, port, protocol, _ = self.internal[
            int(rng.choice(len(self.internal), p=self.internal_p))
        ]
        dst = hosts[int(rng.integers(len(hosts)))]
        if port == 53:
            up, down, duration = 70.0, 180.0, 2.0
        else:
            up, down, duration = self.sizes(rng, 1.5 if port == 445 else 0.6)
            if port == 445 and rng.random() < 0.3:
                up, down = down, up  # saving a document to the share
        return self.make(t, src_ip, dst.static_ip or "", port, up, down, duration, rng, protocol)

    def heartbeats(
        self, rng: np.random.Generator, host: Host, ip: str, t0: datetime, t1: datetime
    ) -> list[SimEvent]:
        if self.edr_ip is None or ip == self.edr_ip:
            return []
        period = self.cfg.heartbeat_s
        base = (t0 - self.ctx.config.start).total_seconds()
        k = int((base - self.phase[host.host_id]) // period) + 1
        out = []
        while True:
            offset = self.phase[host.host_id] + k * period
            t = self.ctx.config.start + timedelta(seconds=offset)
            if t >= t1:
                break
            if t >= t0:
                out.append(self.make(t, ip, self.edr_ip, 8443, 900 + rng.integers(0, 300), 420, 35.0,
                                     rng, tag="edr_heartbeat"))  # fmt: skip
            k += 1
        return out

    def vpn_tunnel(
        self, rng: np.random.Generator, public_ip: str, start: datetime, end: datetime, travel: bool
    ) -> SimEvent:
        duration = max(60.0, (end - start).total_seconds())
        down = duration * float(rng.uniform(15e3, 90e3))
        return self.make(start, public_ip, self.vpn_ip or "", 443, down * 0.3, down, duration * 1000, rng,
                         tag="travel" if travel else "remote_vpn")  # fmt: skip

    def dev_deploy(self, rng: np.random.Generator, src_ip: str, t: datetime) -> SimEvent:
        svc = self.services["dev-staging"]
        dst = svc.ips[int(rng.integers(len(svc.ips)))]
        size = float(rng.uniform(50e6, 300e6))
        return self.make(
            t, src_ip, dst, 22, size, size * 0.01, size / 4e6 * 1000, rng, tag="dev_deploy"
        )

    def server_flows(
        self, rng: np.random.Generator, t0: datetime, t1: datetime, dt: float
    ) -> list[SimEvent]:
        ent, ctx = self.ctx.ent, self.ctx
        factor = ctx.server_factor(t0)
        per_hour = dt / 3600.0
        roles = ent.servers_by_role
        out: list[SimEvent] = []

        def rand_t() -> datetime:
            return t0 + timedelta(seconds=float(rng.random()) * dt)

        dbs = roles.get("db", [])
        for app in roles.get("app", []) + roles.get("erp", []):
            if ctx.control.is_isolated(app.host_id, t0) or not dbs:
                continue
            for _ in range(rng.poisson(self.cfg.app_db_per_hour * factor * per_hour)):
                db = dbs[int(rng.integers(len(dbs)))]
                out.append(self.make(rand_t(), app.static_ip or "", db.static_ip or "", 1433,
                                     float(lognormal(rng, 2500, 1.0)), float(lognormal(rng, 20000, 1.4)),
                                     float(lognormal(rng, 120, 1.0)), rng))  # fmt: skip
        apps = roles.get("app", [])
        for web in roles.get("web", []):
            if ctx.control.is_isolated(web.host_id, t0):
                continue
            for _ in range(rng.poisson(self.cfg.dmz_inbound_per_hour * factor * per_hour)):
                block = ipaddress.ip_network(CLIENT_BLOCKS[int(rng.integers(len(CLIENT_BLOCKS)))])
                client = str(block.network_address + int(rng.integers(1, block.num_addresses - 1)))
                up, down, duration = self.sizes(rng, 0.8)
                t = rand_t()
                out.append(
                    self.make(
                        t, client, web.static_ip or "", 443, min(up, 4000), down, duration, rng
                    )
                )
                if apps and rng.random() < 0.5:
                    app = apps[int(rng.integers(len(apps)))]
                    out.append(self.make(t, web.static_ip or "", app.static_ip or "", 8080,
                                         float(lognormal(rng, 1500, 0.8)), down * 0.9, duration * 0.6, rng))  # fmt: skip
        o365 = self.services["o365"]
        for mail in roles.get("mail", []):
            for _ in range(rng.poisson(6 * factor * per_hour)):
                dst = o365.ips[int(rng.integers(len(o365.ips)))]
                up, down, duration = self.sizes(rng, 1.0)
                out.append(
                    self.make(rand_t(), mail.static_ip or "", dst, 443, up * 3, down, duration, rng)
                )
        wu = self.services["windows-update"]
        for wsus in roles.get("wsus", []):
            for _ in range(rng.poisson(1.0 * per_hour)):
                dst = wu.ips[int(rng.integers(len(wu.ips)))]
                up, down, duration = self.sizes(rng, wu.bytes_scale)
                out.append(
                    self.make(rand_t(), wsus.static_ip or "", dst, 443, up, down, duration, rng)
                )
        build_dst = [self.services["github"], self.services["package-mirror"]]
        files = roles.get("file", [])
        for build in roles.get("build", []):
            for _ in range(rng.poisson(6 * factor * per_hour)):
                svc = build_dst[int(rng.integers(len(build_dst)))]
                up, down, duration = self.sizes(rng, svc.bytes_scale * 2)
                out.append(
                    self.make(
                        rand_t(), build.static_ip or "", svc.ips[0], 443, up, down, duration, rng
                    )
                )
            for _ in range(rng.poisson(2 * per_hour)):
                if files:
                    up, down, duration = self.sizes(rng, 4.0)
                    out.append(self.make(rand_t(), build.static_ip or "", files[0].static_ip or "", 445,
                                         down, up, duration, rng))  # fmt: skip
        dcs = roles.get("dc", [])
        for i, dc in enumerate(dcs):
            peer = dcs[(i + 1) % len(dcs)]
            if peer is dc:
                continue
            for _ in range(rng.poisson(4 * per_hour)):
                out.append(self.make(rand_t(), dc.static_ip or "", peer.static_ip or "", 135,
                                     float(lognormal(rng, 30000, 1.0)), float(lognormal(rng, 30000, 1.0)),
                                     float(lognormal(rng, 400, 0.8)), rng))  # fmt: skip
        out.extend(self.periodic_server_flows(rng, t0, t1))
        return out

    def periodic_server_flows(
        self, rng: np.random.Generator, t0: datetime, t1: datetime
    ) -> list[SimEvent]:
        ent, ctx = self.ctx.ent, self.ctx
        out: list[SimEvent] = []
        start = ctx.config.start
        elapsed0 = (t0 - start).total_seconds()
        elapsed1 = (t1 - start).total_seconds()
        for server in ent.servers:
            if server.static_ip and not ctx.control.is_isolated(server.host_id, t0):
                out.extend(self.heartbeats(rng, server, server.static_ip, t0, t1))
        monitors = ent.servers_by_role.get("monitoring", [])
        if monitors:
            period = self.cfg.monitoring_s
            for server in ent.servers:
                phase = self.phase[server.host_id] % period
                k0 = int((elapsed0 - phase) // period) + 1
                for k in range(k0, int((elapsed1 - phase) // period) + 1):
                    t = start + timedelta(seconds=phase + k * period)
                    if t0 <= t < t1:
                        port = 5985 if server.os == "windows" else 9100
                        mon = monitors[k % len(monitors)]
                        if mon is not server:
                            out.append(self.make(t, mon.static_ip or "", server.static_ip or "", port,
                                                 260, 1800 + int(rng.integers(0, 400)), 20, rng,
                                                 tag="monitoring_poll"))  # fmt: skip
        edr = ent.servers_by_role.get("edr", [])
        if self.look.edr_cloud_sync and edr:
            cloud = self.services["defender-cloud"]
            period = self.cfg.edr_cloud_s
            k0 = int(elapsed0 // period)
            for k in range(k0, int(elapsed1 // period) + 1):
                jitter = float(rng_for(ctx.seed, "edr-sync", k).uniform(-0.03, 0.03)) * period
                t = start + timedelta(seconds=k * period + jitter)
                if t0 <= t < t1:
                    dst = cloud.ips[k % len(cloud.ips)]
                    out.append(self.make(t, edr[0].static_ip or "", dst, 443,
                                         int(rng.integers(2000, 20000)), int(rng.integers(1000, 5000)),
                                         int(rng.integers(80, 400)), rng, tag="edr_cloud_sync"))  # fmt: skip
        return out

    def rdp_flows(self, rng: np.random.Generator, t0: datetime, t1: datetime) -> list[SimEvent]:
        out: list[SimEvent] = []
        for session in self.ctx.rdp_sessions:
            if not (t0 <= session.start < t1):
                continue
            target = self.ctx.ent.hosts_by_id[session.target]
            if self.ctx.control.is_isolated(session.target, session.start):
                continue
            size = session.duration_s * float(rng.uniform(4000, 20000))
            out.append(self.make(session.start + timedelta(seconds=1), session.src_ip, target.static_ip or "",
                                 3389, size * 0.15, size, session.duration_s * 1000, rng,
                                 label=session.label))  # fmt: skip
        return out

    # ------------------------------------------------------------------ nightly backups
    def night_plan(self, day: int) -> list[tuple[datetime, dict[str, Any]]]:
        if day in self._nights:
            return self._nights[day]
        ent = self.ctx.ent
        plan: list[tuple[datetime, dict[str, Any]]] = []
        backups = ent.servers_by_role.get("backup", [])
        sources = [h for r in ("file", "db", "erp", "mail") for h in ent.servers_by_role.get(r, [])]
        if self.look.nightly_backup and backups and sources and day >= 0:
            rng = rng_for(self.ctx.seed, "backup-night", day)
            t = ent.day_start(day) + timedelta(hours=self.look.backup_start_h, seconds=30)
            total = float(rng.uniform(*self.look.backup_internal_gb)) * 1e9
            sent = 0.0
            while sent < total:
                chunk = float(rng.uniform(2e8, 1.5e9))
                src = sources[int(rng.integers(len(sources)))]
                plan.append((t, {"src": backups[0].static_ip, "dst": src.static_ip, "port": 445,
                                 "out": chunk * 0.002, "in": chunk, "ms": chunk / 1.2e8 * 1000, "tag": "backup"}))  # fmt: skip
                t += timedelta(seconds=chunk / 1.2e8 + float(rng.uniform(5, 60)))
                sent += chunk
            s3 = self.services["s3-backup"]
            total = float(rng.uniform(*self.look.backup_offsite_gb)) * 1e9
            sent = 0.0
            while sent < total:
                chunk = float(rng.uniform(1e8, 5e8))
                dst = s3.ips[int(rng.integers(len(s3.ips)))]
                plan.append((t, {"src": backups[-1].static_ip, "dst": dst, "port": 443,
                                 "out": chunk, "in": chunk * 0.001, "ms": chunk / 4e7 * 1000, "tag": "offsite_backup"}))  # fmt: skip
                t += timedelta(seconds=chunk / 4e7 + float(rng.uniform(2, 20)))
                sent += chunk
        self._nights[day] = plan
        return plan

    def backups(self, t0: datetime, t1: datetime) -> list[SimEvent]:
        day = self.ctx.ent.day_index(t0)
        out: list[SimEvent] = []
        rng = self.ctx.tick_rng("backup-ports", t0)
        for d in (day - 1, day):
            for t, f in self.night_plan(d):
                if t0 <= t < t1:
                    out.append(self.make(t, f["src"], f["dst"], f["port"], f["out"], f["in"], f["ms"],
                                         rng, tag=f["tag"]))  # fmt: skip
        return out
