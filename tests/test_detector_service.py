from __future__ import annotations

from datetime import UTC, datetime, timedelta

import numpy as np
import pytest
from fastapi.testclient import TestClient

from agentic_soc.detectors import M1Detector, M2Detector, M3Detector
from agentic_soc.detectors.m3 import PairRarity
from agentic_soc.detectors.registry import ModelRegistry
from agentic_soc.detectors.service import HttpDetectorClient, LocalDetectorClient, create_app
from agentic_soc.features import FEATURES, FeatureRow, Profiles

T0 = datetime(2026, 3, 2, 22, tzinfo=UTC)


def tiny_models() -> tuple[M1Detector, M2Detector, M3Detector]:
    rng = np.random.default_rng(0)
    m1 = M1Detector.fit(
        {k: rng.normal(size=(500, len(FEATURES[k]))) for k in ("M1-user", "M1-ip")},
        Profiles(timezone="UTC"),
        n_estimators=20,
    )
    X = rng.normal(size=(2000, len(FEATURES["M2"])))
    y = X[:, 0] > 2.2
    m2 = M2Detector.fit(X, y, rounds=20)
    rarity = PairRarity()
    for _ in range(30):
        rarity.add_host_day("ws:sales", [("explorer.exe", "chrome.exe")])
    m3 = M3Detector.fit(rarity, [("ws:sales", [("explorer.exe", "chrome.exe")])] * 50)
    return m1, m2, m3


def row(kind: str, value: float = 0.0, **context: object) -> FeatureRow:
    return FeatureRow(kind, f"{kind}:k", T0, T0 + timedelta(minutes=15), users=["ana.pop"], hosts=["WS-0001"],
                      ips=["10.10.1.1"], event_ids=["e1"], features=dict.fromkeys(FEATURES[kind], value),
                      context=dict(context))  # fmt: skip


@pytest.fixture()
def registry(tmp_path) -> ModelRegistry:
    registry = ModelRegistry(tmp_path / "models")
    for model in tiny_models():
        registry.save(model)
    return registry


def test_registry_versions_and_rollback(registry) -> None:
    first = registry.current("M2")
    m2 = M2Detector.fit(
        np.random.default_rng(1).normal(size=(500, len(FEATURES["M2"]))),
        np.r_[np.ones(10), np.zeros(490)].astype(bool),
        rounds=5,
    )
    m2.version = "m2-new"
    registry.save(m2, promote=True)
    assert registry.current("M2") == "m2-new"
    assert {v["version"] for v in registry.versions("M2")} == {first, "m2-new"}
    registry.promote("M2", first)
    assert registry.load("M2").version == first
    with pytest.raises(FileNotFoundError):
        registry.promote("M2", "missing")


def test_detector_set_dispatches_rows(registry) -> None:
    detectors = registry.load_set()
    rows = [
        row("M1-user"),
        row("M1-ip"),
        row("M2"),
        row("M3", host_class="ws:sales", pairs=[["powershell.exe", "rundll32.exe"]]),
    ]
    scored = detectors.score(rows)
    assert sorted(r.detector for r, _ in scored) == sorted(r.detector for r in rows)
    assert all(0 <= s.score <= 1 for _, s in scored)
    assert set(detectors.versions) == {"M1", "M2", "M3"}


def test_rest_service_and_http_client(registry) -> None:
    app = create_app(registry)
    http = TestClient(app)
    assert http.get("/health").json()["status"] == "ok"
    assert http.get("/features/M2").json() == FEATURES["M2"]
    assert len(http.get("/models").json()["M1"]) == 1
    client = HttpDetectorClient(client=http)
    remote = client.score(
        "M3", [row("M3", host_class="ws:sales", pairs=[["powershell.exe", "rundll32.exe"]])]
    )
    local = LocalDetectorClient(registry.load_set()).score(
        "M3", [row("M3", host_class="ws:sales", pairs=[["powershell.exe", "rundll32.exe"]])]
    )
    assert remote[0].score == pytest.approx(local[0].score) and remote[0].top_features
    assert client.versions() == registry.load_set().versions
    bad = http.post("/score/M2", json={"rows": [{"detector": "M1-user", "key": "x", "window_start": T0.isoformat(),
                                                 "window_end": T0.isoformat(), "features": {}}]})  # fmt: skip
    assert bad.status_code == 422
    assert http.post("/score/M9", json={"rows": []}).status_code == 404
    assert http.post("/reload").json()["status"] == "reloaded"
