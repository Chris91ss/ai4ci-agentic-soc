"""Online feature pipeline: windows, entity resolution and extraction, shared by the live
system and the offline training-set builder (no train/serve skew)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from agentic_soc.features.extract import FEATURES, FeatureExtractor, FeatureRow
from agentic_soc.features.history import ConversationHistory, DestinationPopularity
from agentic_soc.features.profiles import Profiles
from agentic_soc.features.resolver import EntityResolver
from agentic_soc.features.windows import Window, Windower
from agentic_soc.ingestion.inventory import Inventory
from agentic_soc.ingestion.models import NormEventT


@dataclass
class WindowConfig:
    signin_size_s: int = 900
    flow_size_s: int = 900
    process_size_s: int = 600
    signin_delay_s: float = 60.0
    flow_delay_s: float = 60.0
    process_delay_s: float = 90.0
    retention_s: float = 7200.0
    history_horizon_s: float = 3600.0


@dataclass
class FeatureBatch:
    m1_user: list[FeatureRow] = field(default_factory=list)
    m1_ip: list[FeatureRow] = field(default_factory=list)
    m2: list[FeatureRow] = field(default_factory=list)
    m3: list[FeatureRow] = field(default_factory=list)

    def rows(self) -> list[FeatureRow]:
        return self.m1_user + self.m1_ip + self.m2 + self.m3

    def extend(self, other: FeatureBatch) -> None:
        self.m1_user += other.m1_user
        self.m1_ip += other.m1_ip
        self.m2 += other.m2
        self.m3 += other.m3

    def __len__(self) -> int:
        return len(self.m1_user) + len(self.m1_ip) + len(self.m2) + len(self.m3)


class FeaturePipeline:
    def __init__(
        self,
        inventory: Inventory,
        profiles: Profiles | None = None,
        config: WindowConfig | None = None,
        detectors: set[str] | None = None,
    ) -> None:
        self.inv = inventory
        self.detectors = set(FEATURES if detectors is None else detectors)
        self.cfg = cfg = config or WindowConfig()
        self.profiles = profiles or Profiles(timezone=inventory.timezone)
        self.resolver = EntityResolver(inventory)
        self.history = ConversationHistory(horizon_s=cfg.history_horizon_s)
        self.popularity = DestinationPopularity()
        self.extractor = FeatureExtractor(inventory, self.profiles, self.resolver)
        self.signin_user = Windower(
            "signin-user", cfg.signin_size_s, cfg.signin_delay_s,
            lambda e: [f"user:{e.user_id}"] if e.user_kind != "unknown" else [], cfg.retention_s,
        )  # fmt: skip
        egress = set(inventory.office_egress.values())  # our own NAT: every employee's source
        self.signin_ip = Windower(
            "signin-ip", cfg.signin_size_s, cfg.signin_delay_s,
            lambda e: [f"ip:{e.src_ip}"] if e.src_zone == "external" and e.src_ip not in egress else [],
            cfg.retention_s,
        )  # fmt: skip
        self.flow_src = Windower(
            "flow-src", cfg.flow_size_s, cfg.flow_delay_s, lambda e: [e.src_ip], cfg.retention_s
        )
        self.process_host = Windower(
            "process-host", cfg.process_size_s, cfg.process_delay_s,
            lambda e: [e.host_id] if e.host_id else [], cfg.retention_s,
        )  # fmt: skip
        self.windowers = [self.signin_user, self.signin_ip, self.flow_src, self.process_host]
        self.clock: datetime | None = None
        self._last_trim: datetime | None = None

    def add(self, events: Iterable[NormEventT]) -> None:
        enabled = self.detectors
        m1_user, m1_ip, m2, m3 = (
            "M1-user" in enabled,
            "M1-ip" in enabled,
            "M2" in enabled,
            "M3" in enabled,
        )
        for event in events:
            stream = event.stream
            if stream == "signin":
                self.resolver.observe(event)  # type: ignore[arg-type]
                if m1_user:
                    self.signin_user.add(event)
                if m1_ip:
                    self.signin_ip.add(event)
            elif stream == "flow":
                if m2:
                    self.history.observe(event)  # type: ignore[arg-type]
                    self.popularity.observe(event)  # type: ignore[arg-type]
                    self.flow_src.add(event)
            elif m3:
                self.process_host.add(event)
            if self.clock is None or event.ingest_time > self.clock:
                self.clock = event.ingest_time

    def _extract(
        self,
        signin_user: list[Window],
        signin_ip: list[Window],
        flows: list[Window],
        procs: list[Window],
    ) -> FeatureBatch:
        ex = self.extractor
        batch = FeatureBatch(
            m1_user=[ex.m1_user(w) for w in signin_user],
            m1_ip=[ex.m1_ip(w) for w in signin_ip],
            m3=[ex.m3(w) for w in procs],
        )
        for window in flows:
            batch.m2 += ex.m2(window, self.history, self.popularity)
        return batch

    def advance(self, clock: datetime | None = None) -> FeatureBatch:
        """Advance watermarks to the pipeline clock and extract features of fired windows."""
        clock = clock or self.clock
        if clock is None:
            return FeatureBatch()
        batch = self._extract(
            self.signin_user.advance(clock),
            self.signin_ip.advance(clock),
            self.flow_src.advance(clock),
            self.process_host.advance(clock),
        )
        if self._last_trim is None or clock - self._last_trim > timedelta(minutes=30):
            self.history.trim(clock)
            self.popularity.trim(clock)
            self._last_trim = clock
        return batch

    def flush(self) -> FeatureBatch:
        return self._extract(
            self.signin_user.flush(),
            self.signin_ip.flush(),
            self.flow_src.flush(),
            self.process_host.flush(),
        )

    def stats(self) -> dict[str, Any]:
        return {
            w.name: {
                **vars(w.stats),
                "open": w.open_windows,
                "watermark": w.watermark.isoformat() if w.watermark else None,
            }
            for w in self.windowers
        } | {"resolver_bindings": self.resolver.observed, "conversations": len(self.history)}
