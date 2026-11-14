"""The evidence verifier: agent actions must be justified by the alerts the agent cited."""

from __future__ import annotations

from types import SimpleNamespace

from agentic_soc.agent.verifier import EvidenceVerifier
from conftest import closed_loop

TOR, ZTNA, OFFICE = "185.220.102.90", "165.225.67.6", "198.51.100.10"
CATEGORY = {TOR: "anonymizer", ZTNA: "cloud", "45.32.54.24": "hosting"}


def _alert(
    alert_id: str, detector: str, techniques: list[str], users=(), hosts=(), ips=(), events=()
):
    entities = SimpleNamespace(users=list(users), hosts=list(hosts), ips=list(ips))
    return SimpleNamespace(alert_id=alert_id, detector=detector, techniques=techniques,
                           entities=entities, event_ids=list(events))  # fmt: skip


def _verifier() -> EvidenceVerifier:
    inventory = SimpleNamespace(
        office_egress={"BUC": OFFICE},
        geoip=lambda ip: SimpleNamespace(category=CATEGORY[ip]) if ip in CATEGORY else None,
    )
    return EvidenceVerifier(inventory)


SPRAY = _alert(
    "AL-1", "M1", ["T1110.003"], users=["anna.novak", "lukas.dumitru"], ips=[TOR], events=["si-1"]
)
EGRESS = _alert("AL-2", "M1", ["T1110", "T1078"], users=["florin.tudor", "anna.novak"], ips=[ZTNA])
VICTIM = _alert("AL-3", "M1", ["T1078", "T1133"], users=["lukas.dumitru"], ips=[TOR])
DUMP = _alert("AL-4", "M3", ["T1003.001"], users=["lukas.dumitru"], hosts=["WS-0156"])
BEACON = _alert("AL-5", "M2", ["T1071.001"], hosts=["WS-0156"], ips=["10.10.4.7", "45.32.54.24"])
ALERTS = [SPRAY, EGRESS, VICTIM, DUMP, BEACON]


def test_actions_need_cited_evidence_that_fits_them() -> None:
    v = _verifier()
    every = {a.alert_id for a in ALERTS}
    assert v.review("block_ip", TOR, ALERTS, {"AL-1"}).approved
    assert v.review("block_ip", "45.32.54.24", ALERTS, {"AL-5"}).approved  # the C2 server
    assert not v.review("block_ip", ZTNA, ALERTS, every).approved  # the company's cloud egress
    assert not v.review("block_ip", TOR, ALERTS, {"AL-4"}).approved  # not in the cited alert
    assert v.review("revoke_sessions", "lukas.dumitru", ALERTS, {"AL-3"}).approved
    assert not v.review("revoke_sessions", "florin.tudor", ALERTS, every).approved  # via ZTNA only
    assert v.review("disable_account", "lukas.dumitru", ALERTS, {"AL-4"}).approved  # ran tooling
    assert v.review("isolate_host", "WS-0156", ALERTS, {"AL-4"}).approved
    assert v.review("isolate_host", "WS-0156", ALERTS, {"AL-5"}).approved  # source of the beacon
    assert not v.review("isolate_host", "WS-0156", ALERTS, {"AL-1", "AL-3"}).approved


def test_events_count_as_citations_and_nothing_cited_is_vetoed() -> None:
    v = _verifier()
    assert v.review("block_ip", TOR, ALERTS, {"si-1"}).approved  # an event of the spray alert
    review = v.review("block_ip", TOR, ALERTS, set())
    assert not review.approved and "cites no alert" in review.reason


def test_the_scripted_analyst_passes_the_verifier(mini_soc) -> None:
    checked = closed_loop(mini_soc, mode="agent", verifier=True)
    assert checked.pipeline.stats.get("actions_vetoed", 0) == 0
    entities = checked.truth["campaign"]["entities"]
    attack = set(entities["users"]) | set(entities["hosts"]) | set(entities["ips"])
    executed = [a for a in checked.pipeline.actions.actions.values() if a.status == "executed"]
    assert executed and all(a.target in attack for a in executed)
