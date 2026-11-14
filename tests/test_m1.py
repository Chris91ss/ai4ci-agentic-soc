from __future__ import annotations

from datetime import UTC, datetime, timedelta

import numpy as np
import pytest

from agentic_soc.detectors import M1Detector
from agentic_soc.detectors.base import TailCalibrator, threshold_for_fpr
from agentic_soc.features import FEATURES, FeatureRow, Profiles

T0 = datetime(2026, 3, 2, 21, tzinfo=UTC)


def benign_user(rng: np.random.Generator, n: int) -> np.ndarray:
    names = FEATURES["M1-user"]
    X = np.zeros((n, len(names)))
    col = {name: i for i, name in enumerate(names)}
    X[:, col["n"]] = rng.poisson(1.5, n) + 1
    X[:, col["n_fail"]] = rng.binomial(1, 0.04, n)
    X[:, col["fail_ratio"]] = X[:, col["n_fail"]] / X[:, col["n"]]
    X[:, col["n_ips"]] = 1
    X[:, col["n_countries"]] = 1
    X[:, col["new_ip_share"]] = rng.binomial(1, 0.05, n) * 0.5
    X[:, col["hour_surprise"]] = rng.normal(3.0, 0.6, n)
    X[:, col["mfa_share"]] = rng.uniform(0, 1, n)
    X[:, col["maturity"]] = rng.normal(5, 0.5, n)
    X[:, col["legacy_share"]] = rng.binomial(1, 0.05, n) * 0.5
    return X


def benign_ip(rng: np.random.Generator, n: int) -> np.ndarray:
    names = FEATURES["M1-ip"]
    X = np.zeros((n, len(names)))
    col = {name: i for i, name in enumerate(names)}
    X[:, col["n"]] = rng.poisson(3, n) + 1
    X[:, col["n_users"]] = np.minimum(X[:, col["n"]], rng.poisson(2, n) + 1)
    X[:, col["n_fail"]] = rng.binomial(1, 0.05, n)
    X[:, col["n_users_failed"]] = X[:, col["n_fail"]]
    X[:, col["fail_ratio"]] = X[:, col["n_fail"]] / X[:, col["n"]]
    X[:, col["known_ip"]] = rng.binomial(1, 0.9, n)
    X[:, col["n_apps"]] = rng.poisson(1, n) + 1
    X[:, col["n_user_agents"]] = 1
    X[:, col["hour_surprise"]] = rng.normal(3.5, 0.5, n)
    return X


def spray_row() -> FeatureRow:
    f = dict.fromkeys(FEATURES["M1-ip"], 0.0) | {
        "n": 18, "n_fail": 17, "fail_ratio": 0.94, "n_users": 18, "n_unknown_users": 2, "n_users_failed": 17,
        "n_success_after_fail": 0, "hosting": 1, "foreign": 1, "known_ip": 0, "n_apps": 1, "legacy_share": 1,
        "n_user_agents": 3, "hour_surprise": 7.5, "vpn_share": 1,
    }  # fmt: skip
    return FeatureRow("M1-ip", "ip:45.32.1.2", T0, T0 + timedelta(minutes=15), users=[], hosts=[],
                      ips=["45.32.1.2"], event_ids=["e1"], features=f,
                      context={"org": "Vultr", "country": "US", "category": "hosting"})  # fmt: skip


def takeover_row() -> FeatureRow:
    f = dict.fromkeys(FEATURES["M1-user"], 0.0) | {
        "n": 1, "n_ips": 1, "n_countries": 1, "new_country_share": 1, "new_ip_share": 1, "new_asn_share": 1,
        "hosting_share": 1, "foreign_share": 1, "hour_surprise": 9.0, "new_device_share": 1, "legacy_share": 1,
        "new_logon_type_share": 1, "geo_km_max": 1.8, "maturity": 5,
    }  # fmt: skip
    return FeatureRow("M1-user", "user:ana.pop", T0, T0 + timedelta(minutes=15), users=["ana.pop"],
                      hosts=["WS-0001"], ips=["193.106.191.5"], event_ids=["e2"], features=f,
                      context={"countries": ["RU"], "orgs": ["Selectel"], "logon_types": ["vpn"],
                               "outcomes": {"success": 1, "failure": 0}})  # fmt: skip


@pytest.fixture(scope="module")
def detector() -> M1Detector:
    rng = np.random.default_rng(0)
    det = M1Detector.fit(
        {"M1-user": benign_user(rng, 4000), "M1-ip": benign_ip(rng, 2000)},
        Profiles(timezone="UTC"),
        n_estimators=100,
    )
    det.calibrate({"M1-user": benign_user(rng, 3000), "M1-ip": benign_ip(rng, 2000)})
    return det


def test_attacks_score_above_calibrated_thresholds(detector) -> None:
    spray, takeover = detector.score([spray_row(), takeover_row()])
    assert spray.alert and takeover.alert
    assert spray.score > 0.999 and takeover.score > 0.999
    assert spray.techniques[0] == "T1110.003" and "Vultr" in spray.summary
    assert "T1078" in takeover.techniques and "T1133" in takeover.techniques
    assert "new country" in takeover.summary
    names = [f["name"] for f in spray.top_features]
    assert "n_users_failed" in names or "n_fail" in names
    assert spray.severity in {"high", "critical"}


def test_false_positive_rate_matches_target(detector) -> None:
    rng = np.random.default_rng(42)
    X = benign_user(rng, 20_000)
    scores = detector.raw_scores("M1-user", X)
    fpr = float((scores >= detector.thresholds["M1-user"]).mean())
    assert fpr < 0.006


def test_save_and_load_roundtrip(detector, tmp_path) -> None:
    detector.save(tmp_path / "m1")
    loaded = M1Detector.load(tmp_path / "m1")
    a = detector.score([spray_row(), takeover_row()])
    b = loaded.score([spray_row(), takeover_row()])
    assert [x.score for x in a] == pytest.approx([x.score for x in b])
    assert loaded.version == detector.version and loaded.thresholds == detector.thresholds


def test_tail_calibration_is_monotonic() -> None:
    raw = np.random.default_rng(1).normal(size=5000)
    cal = TailCalibrator.fit(raw)
    xs = np.linspace(-5, 12, 400)
    ys = cal(xs)
    assert np.all(np.diff(ys) >= 0) and ys[0] >= 0 and ys[-1] < 1
    assert cal(np.array([raw.max() + 1]))[0] > cal(np.array([raw.max()]))[0]
    assert threshold_for_fpr(np.linspace(0, 1, 1001), 0.01) == pytest.approx(0.99)


def _user_row(n: int, n_fail: int, outcomes: dict[str, int], risky: bool) -> FeatureRow:
    features = dict.fromkeys(FEATURES["M1-user"], 0.0) | {
        "n": float(n),
        "n_fail": float(n_fail),
        "fail_ratio": n_fail / n,
    }
    context = {"outcomes": outcomes, "risky_success": risky, "countries": ["US", "RO"]}
    return FeatureRow("M1-user", "user:ana", T0, T0 + timedelta(minutes=15), ["ana"], [], [],
                      ["e1"], features, context=context)  # fmt: skip


def test_techniques_tell_spray_targets_from_used_accounts() -> None:
    target = _user_row(3, 1, {"success": 2, "failure": 1}, risky=False)
    assert M1Detector.describe(target)[0] == ["T1110"]
    used = _user_row(3, 1, {"success": 2, "failure": 1}, risky=True)
    assert M1Detector.describe(used)[0] == ["T1078"]
    sprayed = _user_row(4, 4, {"success": 0, "failure": 4}, risky=False)
    assert M1Detector.describe(sprayed)[0] == ["T1110"]
    routine = _user_row(2, 0, {"success": 2, "failure": 0}, risky=False)
    assert M1Detector.describe(routine)[0] == ["T1078"]
