from __future__ import annotations

from datetime import UTC, datetime, timedelta

import numpy as np
import pytest

from agentic_soc.drift import (
    DriftConfig,
    DriftMonitor,
    FeatureReference,
    recent_signins,
    retrain_m1,
)
from agentic_soc.features import FEATURES, FeatureRow

T0 = datetime(2026, 3, 2, tzinfo=UTC)
NAMES = ["a", "b", "c"]


def sample(rng: np.random.Generator, n: int, shift: float = 0.0) -> np.ndarray:
    return np.column_stack(
        [rng.normal(shift, 1, n), rng.poisson(2 + shift, n), rng.binomial(1, 0.1, n)]
    )


def test_psi_and_ks_separate_shifted_distributions() -> None:
    rng = np.random.default_rng(1)
    reference = FeatureReference.fit(NAMES, sample(rng, 5000))
    same = reference.psi(sample(rng, 3000))
    shifted = reference.psi(sample(rng, 3000, shift=1.5))
    assert same.max() < 0.05 and shifted[0] > 0.5 and shifted[1] > 0.25
    assert reference.ks_pvalues(sample(rng, 3000, shift=1.5))[0] < 1e-6
    again = FeatureReference.from_json(reference.to_json())
    probe = sample(rng, 500, shift=0.5)
    assert np.allclose(again.psi(probe), reference.psi(probe)) and again.rows == 5000


def test_constant_reference_features_still_detect_change() -> None:
    reference = FeatureReference.fit(["flag"], np.zeros((1000, 1)))
    assert reference.psi(np.zeros((500, 1)))[0] < 1e-6
    assert reference.psi(np.r_[np.zeros((400, 1)), np.ones((100, 1))])[0] > 0.25


def _rows(X: np.ndarray, kind: str, start: datetime) -> list[FeatureRow]:
    names = FEATURES[kind]
    out = []
    for i, x in enumerate(X):
        t = start + timedelta(minutes=10 * i)
        features = dict.fromkeys(names, 0.0) | dict(zip(names, map(float, x), strict=False))
        out.append(
            FeatureRow(kind, f"user:{i}", t, t + timedelta(minutes=15), [], [], [], [], features)
        )
    return out


def test_monitor_alarms_only_on_sustained_behavioural_shift() -> None:
    kind = "M1-user"
    names = FEATURES[kind]
    rng = np.random.default_rng(3)
    base = rng.normal(0, 1, (4000, len(names)))
    monitor = DriftMonitor(
        {kind: FeatureReference.fit(names, base)}, DriftConfig(window_h=24, min_rows=100)
    )
    calm = rng.normal(0, 1, (288, len(names)))  # two days of 10-minute windows
    monitor.observe(_rows(calm, kind, T0))
    assert not monitor.check(T0 + timedelta(hours=10))  # less than a full window yet
    checks = monitor.check(T0 + timedelta(hours=48))
    assert checks and not checks[0].shifted and not monitor.alarm
    weekend = names.index("weekend")
    calendar = rng.normal(0, 1, (144, len(names)))
    calendar[:, weekend] += 5  # calendar features are ignored
    monitor.observe(_rows(calendar, kind, T0 + timedelta(hours=48)))
    assert not monitor.check(T0 + timedelta(hours=72))[0].shifted
    drifted = rng.normal(0, 1, (144, len(names)))
    drifted[:, :4] += 2.0
    monitor.observe(_rows(drifted, kind, T0 + timedelta(hours=72)))
    first = monitor.check(T0 + timedelta(hours=96))
    assert first[0].shifted and not monitor.alarm  # one shifted check is not enough
    monitor.check(T0 + timedelta(hours=97))
    assert monitor.alarm and monitor.alarm_since == T0 + timedelta(hours=97)
    monitor.reset()
    assert not monitor.alarm and not monitor.history


def test_profiles_update_without_touching_the_original(mini_soc) -> None:
    signins = recent_signins(mini_soc.store, mini_soc.clock, 4)
    assert signins
    before = {k: v.n for k, v in mini_soc.profiles.accounts.items()}
    updated = mini_soc.profiles.updated(signins)
    assert {k: v.n for k, v in mini_soc.profiles.accounts.items()} == before
    account = next(
        e.user_id for e in signins if e.outcome == "success" and e.user_kind != "unknown"
    )
    assert (
        updated.accounts[account].n > mini_soc.profiles.accounts.get(account).n
        if account in before
        else True
    )
    assert updated.known_ips >= mini_soc.profiles.known_ips


def test_retrain_m1_refreshes_baselines_and_skips_the_attack(mini_soc) -> None:
    current = mini_soc.detectors.detectors["M1"]
    assert set(current.references) == {"M1-user", "M1-ip"}
    signins = recent_signins(mini_soc.store, mini_soc.clock, 12)
    new, report = retrain_m1(current, signins, mini_soc.inventory, mini_soc.malicious)
    assert new.version != current.version and report["parent"] == current.version
    assert report["excluded_events"] == len(mini_soc.malicious)
    assert set(new.references) == {"M1-user", "M1-ip"} and all(
        0 < t < 1 for t in new.thresholds.values()
    )
    assert new.profiles is not current.profiles
    with pytest.raises(ValueError):
        retrain_m1(current, [], mini_soc.inventory)


def test_pipeline_monitors_drift_and_swaps_a_retrained_m1(agent_run) -> None:
    pipeline = agent_run.pipeline
    assert pipeline.drift is not None
    old = pipeline.local_m1()
    profiles = pipeline.features.profiles
    report = pipeline.retrain(pipeline.now())
    assert report is not None and report["parent"] == old.version
    new = pipeline.local_m1()
    assert new.version == report["version"] and pipeline.features.profiles is new.profiles
    assert (
        pipeline.features.extractor.profiles is new.profiles
        and pipeline.ctx.profiles is new.profiles
    )
    assert any(e["kind"] == "retrain" for e in pipeline.log)
    pipeline.detectors.detectors.detectors["M1"] = old  # leave the shared run as it was
    pipeline.features.profiles = pipeline.features.extractor.profiles = profiles
    pipeline.ctx.profiles = pipeline.evidence.profiles = profiles
