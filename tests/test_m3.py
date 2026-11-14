from __future__ import annotations

from datetime import UTC, datetime, timedelta

import numpy as np
import pytest

from agentic_soc.detectors.m3 import FLOOR_BITS, M3Detector, PairRarity, window_raw
from agentic_soc.features import FEATURES, FeatureRow

T0 = datetime(2026, 3, 2, 22, tzinfo=UTC)
DAILY_WS = [("explorer.exe", "chrome.exe"), ("chrome.exe", "chrome.exe"), ("userinit.exe", "explorer.exe"),
            ("explorer.exe", "onedrive.exe"), ("svchost.exe", "taskhostw.exe")]  # fmt: skip
DAILY_SRV = [("services.exe", "svchost.exe"), ("svchost.exe", "wmiprvse.exe")]
PATCH_NIGHT = [("services.exe", "psexesvc.exe"), ("psexesvc.exe", "cmd.exe")]


def model() -> PairRarity:
    rarity = PairRarity()
    rng = np.random.default_rng(0)
    for _day in range(7):
        for _host in range(20):
            rarity.add_host_day(
                "ws:sales",
                DAILY_WS + ([("explorer.exe", "powershell.exe")] if rng.random() < 0.05 else []),
            )
        for host in range(4):
            rarity.add_host_day(
                "srv:file", DAILY_SRV + (PATCH_NIGHT if _day == 1 and host < 2 else [])
            )
    return rarity


def windows(rng: np.random.Generator, n: int) -> list[tuple[str, list[tuple[str, str]]]]:
    out = []
    for _ in range(n):
        if rng.random() < 0.7:
            idx = rng.choice(len(DAILY_WS), size=rng.integers(1, 6))
            out.append(("ws:sales", [DAILY_WS[int(i)] for i in idx]))
        else:
            out.append(("srv:file", DAILY_SRV))
    return out


@pytest.fixture(scope="module")
def detector() -> M3Detector:
    rng = np.random.default_rng(1)
    det = M3Detector.fit(model(), windows(rng, 2000))
    det.calibrate(windows(rng, 2000), fpr=0.01)
    return det


def row(host_class: str, host: str, pairs: list[tuple[str, str]], users: list[str]) -> FeatureRow:
    return FeatureRow("M3", f"host:{host}", T0, T0 + timedelta(minutes=10), users=users, hosts=[host], ips=[],
                      event_ids=["p1"], features=dict.fromkeys(FEATURES["M3"], 0.0),
                      context={"host_class": host_class, "pairs": pairs})  # fmt: skip


def test_daily_bursts_are_not_rare_but_unseen_launches_are() -> None:
    rarity = model()
    assert rarity.rarity("ws:sales", "explorer.exe", "onedrive.exe") < FLOOR_BITS
    assert rarity.rarity("srv:file", "services.exe", "psexesvc.exe") > FLOOR_BITS
    unseen = rarity.rarity("ws:sales", "powershell.exe", "rundll32.exe")
    assert unseen > rarity.rarity("srv:file", "services.exe", "psexesvc.exe") > 0
    logon_burst, _ = window_raw(rarity, "ws:sales", DAILY_WS)
    assert logon_burst == 0.0


def test_rare_launches_alert_with_techniques(detector) -> None:
    dump = row("ws:sales", "WS-0007", [("rundll32.exe", "powershell.exe"), ("powershell.exe", "rundll32.exe"),
                                       ("explorer.exe", "chrome.exe")], ["dan.ion"])  # fmt: skip
    lateral = row(
        "srv:file", "SRV-FILE-01", [*PATCH_NIGHT, ("cmd.exe", "7za.exe")], ["adm-ana.pop"]
    )
    normal = row("ws:sales", "WS-0008", DAILY_WS, ["eva.pop"])
    s_dump, s_lateral, s_normal = detector.score([dump, lateral, normal])
    assert s_dump.alert and s_lateral.alert and not s_normal.alert
    assert "T1218.011" in s_dump.techniques and s_dump.top_features[0]["all_host_days"] == 0
    assert {"T1569.002", "T1560.001"} <= set(s_lateral.techniques)
    assert "peer host-days" in s_lateral.summary


def test_save_and_load(detector, tmp_path) -> None:
    detector.save(tmp_path / "m3")
    loaded = M3Detector.load(tmp_path / "m3")
    ws = windows(np.random.default_rng(5), 50)
    assert np.allclose(loaded.window_scores(ws), detector.window_scores(ws))
    assert loaded.thresholds == detector.thresholds and loaded.model.days == detector.model.days
