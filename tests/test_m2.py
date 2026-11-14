from __future__ import annotations

from datetime import UTC, datetime, timedelta

import numpy as np
import pytest

from agentic_soc.detectors import M2Detector
from agentic_soc.features import FEATURES, FeatureRow

NAMES = FEATURES["M2"]
COL = {n: i for i, n in enumerate(NAMES)}
T0 = datetime(2026, 3, 2, 22, tzinfo=UTC)


def benign(rng: np.random.Generator, n: int) -> np.ndarray:
    X = np.zeros((n, len(NAMES)))
    X[:, COL["n_flows"]] = rng.poisson(1.2, n) + 1
    X[:, COL["log_bytes_out"]] = rng.normal(7, 1.5, n)
    X[:, COL["log_bytes_in"]] = rng.normal(9, 2, n)
    X[:, COL["log_out_in_ratio"]] = X[:, COL["log_bytes_out"]] - X[:, COL["log_bytes_in"]]
    X[:, COL["port_web"]] = 1
    X[:, COL["dir_outbound"]] = 1
    X[:, COL["dst_cloud"]] = rng.binomial(1, 0.8, n)
    X[:, COL["src_corp"]] = 1
    X[:, COL["hist_n"]] = rng.poisson(2, n)
    X[:, COL["hist_interval_cv"]] = rng.uniform(0.5, 2, n)
    X[:, COL["hist_regularity"]] = rng.uniform(0, 0.4, n)
    X[:, COL["src_n_flows"]] = rng.poisson(10, n)
    X[:, COL["src_distinct_dsts"]] = rng.poisson(6, n)
    X[:, COL["dst_popularity_log"]] = rng.normal(3, 0.5, n)
    return X


def beacons(rng: np.random.Generator, n: int) -> np.ndarray:
    X = benign(rng, n)
    X[:, COL["n_flows"]] = rng.poisson(12, n) + 5
    X[:, COL["log_bytes_out"]] = rng.normal(8.5, 0.3, n)
    X[:, COL["hist_n"]] = rng.poisson(40, n) + 10
    X[:, COL["hist_interval_log"]] = np.log1p(rng.uniform(50, 120, n))
    X[:, COL["hist_interval_cv"]] = rng.uniform(0.05, 0.25, n)
    X[:, COL["hist_regularity"]] = rng.uniform(0.8, 1.0, n)
    X[:, COL["dst_cloud"]] = 0
    X[:, COL["dst_hosting"]] = 1
    X[:, COL["dst_popularity_log"]] = np.log1p(1)
    return X


@pytest.fixture(scope="module")
def trained() -> M2Detector:
    rng = np.random.default_rng(0)
    X = np.vstack([benign(rng, 20_000), beacons(rng, 200)])
    y = np.r_[np.zeros(20_000, bool), np.ones(200, bool)]
    Xv = np.vstack([benign(rng, 10_000), beacons(rng, 100)])
    yv = np.r_[np.zeros(10_000, bool), np.ones(100, bool)]
    det = M2Detector.fit(X, y, Xv, yv, rounds=80)
    det.calibrate(Xv[~yv], fpr=1e-3)
    return det


def row(x: np.ndarray, key: str = "10.10.1.5|95.216.3.4|443") -> FeatureRow:
    return FeatureRow("M2", key, T0, T0 + timedelta(minutes=15), users=["ana.pop"], hosts=["WS-0001"],
                      ips=key.split("|")[:2], event_ids=["f1"], features=dict(zip(NAMES, x, strict=True)),
                      context={"dst_org": "Hetzner", "service": "https", "src_host": "WS-0001"})  # fmt: skip


def test_beacons_are_detected_and_explained(trained) -> None:
    rng = np.random.default_rng(7)
    scores = trained.score([row(x) for x in beacons(rng, 20)] + [row(x) for x in benign(rng, 2000)])
    assert np.mean([s.alert for s in scores[:20]]) > 0.9
    assert np.mean([s.alert for s in scores[20:]]) < 0.01
    hit = next(s for s in scores[:20] if s.alert)
    assert hit.techniques[:1] == ["T1071.001"] and "Regular beacon from WS-0001" in hit.summary
    assert hit.top_features and all(f["contribution"] > 0 for f in hit.top_features)
    assert trained.meta["training_positives"] == 200 and trained.meta["validation_ap_curve"]


def test_describe_other_patterns() -> None:
    upload = dict.fromkeys(NAMES, 0.0) | {
        "dir_outbound": 1,
        "log_bytes_out": np.log1p(2e9),
        "n_flows": 9,
    }
    techniques, summary = M2Detector.describe(row(np.array([upload[n] for n in NAMES])))
    assert techniques == ["T1041"] and "GB" in summary
    sweep = dict.fromkeys(NAMES, 0.0) | {
        "dir_internal": 1,
        "src_distinct_dsts": 45,
        "src_small_share": 0.8,
        "src_distinct_ports": 2,
    }
    techniques, summary = M2Detector.describe(
        row(np.array([sweep[n] for n in NAMES]), "10.10.1.5|10.20.1.11|445")
    )
    assert techniques == ["T1018"] and "45 destinations" in summary


def test_save_and_load(trained, tmp_path) -> None:
    trained.save(tmp_path / "m2")
    loaded = M2Detector.load(tmp_path / "m2")
    X = beacons(np.random.default_rng(3), 5)
    assert np.allclose(loaded.raw_scores(X), trained.raw_scores(X))
    assert loaded.thresholds == trained.thresholds
