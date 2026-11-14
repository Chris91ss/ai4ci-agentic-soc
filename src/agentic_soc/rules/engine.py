"""SIEM-style detection rules: the "rules and playbooks only" baseline of the evaluation.

Fixed-threshold rules in the spirit of Sigma and vendor analytics rules, evaluated on the same
event-time windows as the detectors but without learned baselines. Each firing becomes an alert
(detector ``rule:<id>``) for the correlation engine and the playbooks.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime

from agentic_soc.detectors.base import Score
from agentic_soc.features import EntityResolver, FeatureRow, Window, WindowConfig, Windower
from agentic_soc.ingestion import Inventory, NormEventT, NormFlow, NormProcess, NormSignin

DISCOVERY = re.compile(
    r"\b(whoami|nltest|net1?\.exe\s+(group|view|user)|ipconfig(\.exe)?\s+/all|systeminfo)", re.I
)
ENCODED_PS = re.compile(r"powershell(\.exe)?\b.*\s-(e|en|enc|encodedcommand)\s", re.I)
LSASS_DUMP = re.compile(r"(comsvcs\.dll.*minidump|procdump.*lsass|sekurlsa)", re.I)
ARCHIVE = re.compile(r"\b(7z|7za|rar|winrar)(\.exe)?\b.*\s(a|-a)\s", re.I)
HOSTILE = {"hosting", "anonymizer"}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    stream: str
    techniques: tuple[str, ...]
    severity: str


RULES = {
    r.rule_id: r
    for r in [
        Rule("R01", "Password spray from one source", "signin", ("T1110.003",), "high"),
        Rule("R02", "Brute force against an account", "signin", ("T1110",), "medium"),
        Rule("R03", "Successful sign-in from abroad", "signin", ("T1078",), "medium"),
        Rule("R04", "Sign-in from a hosting or anonymiser network", "signin", ("T1078", "T1133"), "high"),
        Rule("R05", "Encoded PowerShell command", "process", ("T1059.001",), "medium"),
        Rule("R06", "LSASS memory dump", "process", ("T1003.001",), "critical"),
        Rule("R07", "Burst of discovery commands", "process", ("T1087.002", "T1018"), "medium"),
        Rule("R08", "Remote service execution (PsExec)", "process", ("T1569.002",), "high"),
        Rule("R09", "Data archived with a command-line archiver", "process", ("T1560.001",), "medium"),
        Rule("R10", "Internal network scan", "flow", ("T1018",), "medium"),
        Rule("R11", "Large upload to an external address", "flow", ("T1041",), "high"),
        Rule("R12", "Repeated connections to a hosting provider", "flow", ("T1071.001",), "low"),
    ]
}  # fmt: skip
SEVERITY_SCORE = {"low": 0.75, "medium": 0.85, "high": 0.93, "critical": 0.99}

Found = tuple[FeatureRow, Score]


def _uniq(values: Iterable[str | None]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


class RuleEngine:
    def __init__(
        self,
        inventory: Inventory,
        resolver: EntityResolver | None = None,
        config: WindowConfig | None = None,
    ) -> None:
        self.inv = inventory
        self.resolver = resolver or EntityResolver(inventory)
        cfg = config or WindowConfig()
        self.home = inventory.home_country
        egress = set(inventory.office_egress.values())

        def source_key(e: NormSignin) -> list[str]:
            return [e.src_ip] if e.src_zone == "external" and e.src_ip not in egress else []

        def account_key(e: NormSignin) -> list[str]:
            return [e.user_id] if e.user_kind != "unknown" else []

        size, delay, keep = cfg.signin_size_s, cfg.signin_delay_s, cfg.retention_s
        self.by_source = Windower("rules-signin-ip", size, delay, source_key, keep)
        self.by_account = Windower("rules-signin-user", size, delay, account_key, keep)
        self.flows = Windower(
            "rules-flow", cfg.flow_size_s, cfg.flow_delay_s, lambda e: [e.src_ip], keep
        )
        self.procs = Windower(
            "rules-process", cfg.process_size_s, cfg.process_delay_s,
            lambda e: [e.host_id] if e.host_id else [], keep,
        )  # fmt: skip
        self.fired: dict[str, int] = dict.fromkeys(RULES, 0)

    def add(self, events: Iterable[NormEventT]) -> None:
        for event in events:
            if event.stream == "signin":
                self.resolver.observe(event)  # type: ignore[arg-type]
                self.by_source.add(event)
                self.by_account.add(event)
            elif event.stream == "flow":
                self.flows.add(event)
            else:
                self.procs.add(event)

    def advance(self, clock: datetime) -> list[Found]:
        return self._evaluate(lambda w: w.advance(clock))

    def flush(self) -> list[Found]:
        return self._evaluate(lambda w: w.flush())

    def _evaluate(self, fire: Callable[[Windower], list[Window]]) -> list[Found]:
        out: list[Found] = []
        for window in fire(self.by_source):
            out += self._source_rules(window)
        for window in fire(self.by_account):
            out += self._account_rules(window)
        for window in fire(self.flows):
            out += self._flow_rules(window)
        for window in fire(self.procs):
            out += self._process_rules(window)
        for row, _ in out:
            self.fired[row.context["rule"]] += 1
        return out

    # ------------------------------------------------------------------ alerts
    def _alert(
        self,
        rule_id: str,
        window: Window,
        events: list[NormEventT],
        summary: str,
        users: Iterable[str | None] = (),
        hosts: Iterable[str | None] = (),
        ips: Iterable[str | None] = (),
    ) -> Found:
        rule = RULES[rule_id]
        row = FeatureRow(
            f"rule:{rule_id}", f"{rule_id}:{window.key}", window.start, window.end,
            _uniq(users), _uniq(hosts), _uniq(ips), [e.event_id for e in events][:500],
            {"matches": float(len(events))}, late=window.late,
            context={"rule": rule_id, "stream": rule.stream, "title": rule.title},
        )  # fmt: skip
        score = Score(
            detector=f"rule:{rule_id}",
            kind=f"rule:{rule_id}",
            score=SEVERITY_SCORE[rule.severity],
            threshold=0.5,
            top_features=[
                {"name": "matching events", "value": float(len(events)), "contribution": 1.0}
            ],
            techniques=list(rule.techniques),
            summary=f"{rule.title}: {summary}",
        )
        return row, score

    def _host_of(self, ip: str, t: datetime) -> str | None:
        return self.inv.static_host(ip) or self.resolver.host_for_ip(ip, t)

    def _source_rules(self, window: Window) -> list[Found]:
        events: list[NormSignin] = window.events
        fails = [e for e in events if e.outcome == "failure"]
        accounts = {e.user_id for e in fails}
        if len(fails) >= 10 and len(accounts) >= 5:
            winners = [e.user_id for e in events if e.outcome == "success"]
            what = f"{len(fails)} failures over {len(accounts)} accounts from {window.key}"
            return [self._alert("R01", window, events, what, users=winners, ips=[window.key])]
        return []

    def _account_rules(self, window: Window) -> list[Found]:
        events: list[NormSignin] = window.events
        account = window.key
        out = []
        fails = [e for e in events if e.outcome == "failure"]
        if len(fails) >= 8:
            sources = [e.src_ip for e in fails if e.src_zone == "external"]
            what = f"{len(fails)} failed sign-ins for {account}"
            out.append(self._alert("R02", window, fails, what, users=[account], ips=sources))
        ok = [e for e in events if e.outcome == "success" and e.src_zone == "external"]
        foreign = [e for e in ok if e.src_country and e.src_country != self.home]
        if foreign:
            countries = ", ".join(sorted({e.src_country or "" for e in foreign}))
            what = f"{account} signed in from {countries}"
            sources = [e.src_ip for e in foreign]
            out.append(self._alert("R03", window, foreign, what, users=[account], ips=sources))
        hostile = [e for e in ok if e.src_category in HOSTILE]
        if hostile:
            orgs = ", ".join(sorted({e.src_org or "?" for e in hostile}))
            what = f"{account} signed in from {orgs}"
            sources = [e.src_ip for e in hostile]
            out.append(self._alert("R04", window, hostile, what, users=[account], ips=sources))
        return out

    def _flow_rules(self, window: Window) -> list[Found]:
        flows: list[NormFlow] = window.events
        src = window.key
        host = self._host_of(src, window.start)
        out = []
        small = [f for f in flows if f.dst_zone != "external" and f.bytes_out + f.bytes_in < 2_000]
        targets = {f.dst_ip for f in small}
        if len(targets) >= 20:
            what = f"{src} probed {len(targets)} internal addresses"
            out.append(self._alert("R10", window, small, what, hosts=[host], ips=[src]))
        by_dst: dict[str, list[NormFlow]] = {}
        for f in flows:
            if f.dst_zone == "external":
                by_dst.setdefault(f.dst_ip, []).append(f)
        for dst, group in by_dst.items():
            sent = sum(f.bytes_out for f in group)
            org = group[0].dst_org
            if sent >= 300_000_000:
                what = f"{src} sent {sent / 1e6:.0f} MB to {dst} ({org})"
                out.append(self._alert("R11", window, group, what, hosts=[host], ips=[src, dst]))
            elif (
                group[0].dst_category in HOSTILE
                and len(group) >= 5
                and (host or "").startswith("WS-")
            ):
                what = f"{host} connected {len(group)} times to {dst} ({org})"
                out.append(self._alert("R12", window, group, what, hosts=[host], ips=[src, dst]))
        return out

    def _process_rules(self, window: Window) -> list[Found]:
        procs: list[NormProcess] = window.events
        host = window.key
        out = []
        checks = [
            ("R05", lambda p: bool(ENCODED_PS.search(p.command_line)), "encoded PowerShell"),
            ("R06", lambda p: bool(LSASS_DUMP.search(p.command_line)), "LSASS memory dump"),
            ("R08", lambda p: p.process_name in {"psexesvc.exe", "psexec.exe"}, "PsExec service"),
            ("R09", lambda p: bool(ARCHIVE.search(p.command_line)), "command-line archiving"),
        ]
        for rule_id, matches, what in checks:
            hits = [p for p in procs if matches(p)]
            if hits:
                users = [p.user_id for p in hits if p.user_kind != "system"]
                summary = f"{what} on {host} ({len(hits)} processes)"
                out.append(self._alert(rule_id, window, hits, summary, users=users, hosts=[host]))
        discovery = [p for p in procs if DISCOVERY.search(p.command_line)]
        if len({p.process_name for p in discovery}) >= 3:
            summary = f"{len(discovery)} discovery commands on {host}"
            users = [p.user_id for p in discovery]
            out.append(self._alert("R07", window, discovery, summary, users=users, hosts=[host]))
        return out
