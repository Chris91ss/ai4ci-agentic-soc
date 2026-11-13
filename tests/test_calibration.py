from __future__ import annotations

import gzip
from datetime import datetime

import numpy as np
import pytest
from typer.testing import CliRunner

from agentic_soc.cli import app
from agentic_soc.simulator.calibration import (
    Calibration,
    calibrate,
    dump_calibration,
    fit_lanl_auth,
    fit_lanl_flows,
    fit_rba,
    load_calibration,
)
from agentic_soc.simulator.distributions import heavy_tailed, hill_alpha, jittered_intervals
from agentic_soc.simulator.seasonality import ActivityProfile, rotate_to_trough, rotate_to_weekend


def test_default_calibration_loads_and_normalises() -> None:
    cal = load_calibration()
    profile = cal.user_profile()
    assert np.isclose(np.mean(profile.hourly), 1.0)
    assert np.isclose(np.mean(profile.weekly), 1.0)
    monday_10 = datetime(2026, 3, 2, 10, 0)
    sunday_3 = datetime(2026, 3, 8, 3, 0)
    assert profile.factor(monday_10) > 10 * profile.factor(sunday_3)


def test_profile_interpolates_between_hours() -> None:
    profile = ActivityProfile.from_lists([1.0] * 12 + [3.0] * 12, [1.0] * 7)
    a = profile.hour_factor(datetime(2026, 3, 2, 11, 0))
    b = profile.hour_factor(datetime(2026, 3, 2, 11, 30))
    c = profile.hour_factor(datetime(2026, 3, 2, 12, 0))
    assert a < b < c


def test_phase_alignment() -> None:
    hourly = np.ones(24)
    hourly[15] = 0.01
    assert int(np.argmin(rotate_to_trough(hourly))) == 3
    daily = np.array([1.0, 1.0, 0.2, 0.2, 1.0, 1.0, 1.0])
    aligned = rotate_to_weekend(daily)
    assert aligned[5] == aligned[6] == 0.2


def test_heavy_tail_sampler_and_hill_estimator() -> None:
    rng = np.random.default_rng(0)
    x = heavy_tailed(
        rng, 200_000, median=4500, sigma=1.2, tail_prob=0.05, tail_alpha=1.3, tail_xmin=4e5
    )
    assert 3000 < np.median(x) < 7000
    assert 1.0 < hill_alpha(x[x >= 4e5]) < 1.6
    intervals = jittered_intervals(rng, 60, 0.2, 1000)
    assert intervals.min() >= 48 and intervals.max() <= 72


def _write_lanl_auth(path, rng) -> None:
    # 21 days, quiet hour at relative 15:00 and quiet days at relative day 2-3.
    hour_w = np.ones(24)
    hour_w[13:18] = 0.05
    day_w = np.ones(7)
    day_w[2:4] = 0.2
    lines = []
    for day in range(21):
        for hour in range(24):
            n = rng.poisson(40 * hour_w[hour] * day_w[day % 7])
            for _ in range(n):
                t = day * 86400 + hour * 3600 + int(rng.integers(3600))
                ok = "Success" if rng.random() > 0.03 else "Fail"
                lines.append(f"{t},U1@DOM1,U1@DOM1,C1,C2,Kerberos,Network,LogOn,{ok}")
    lines.sort(key=lambda s: int(s.split(",")[0]))
    with gzip.open(path, "wt") as f:
        f.write("\n".join(lines) + "\n")


def test_fit_lanl_auth_recovers_seasonality(tmp_path) -> None:
    path = tmp_path / "auth.txt.gz"
    _write_lanl_auth(path, np.random.default_rng(1))
    fitted = fit_lanl_auth(path, max_rows=None)
    hourly = np.asarray(fitted["user_hourly"])
    assert int(np.argmin(np.convolve(np.tile(hourly, 3), np.ones(3), "same")[24:48])) in {2, 3, 4}
    weekly = np.asarray(fitted["weekly"])
    assert set(np.argsort(weekly)[:2]) == {5, 6}
    assert 0.01 < fitted["signin_failure_rate"] < 0.06


def test_fit_lanl_flows_recovers_tail(tmp_path) -> None:
    rng = np.random.default_rng(2)
    sizes = heavy_tailed(rng, 50_000, 4500, 1.4, 0.05, 1.3, 4e5).astype(int)
    path = tmp_path / "flows.txt"
    path.write_text(
        "\n".join(
            f"{i // 10},{int(rng.integers(0, 30))},C1,N1,C2,445,6,10,{s}"
            for i, s in enumerate(sizes)
        )
    )
    fitted = fit_lanl_flows(path, max_rows=None)
    assert 2000 < fitted["flow_bytes"]["median"] < 9000
    assert 0.9 < fitted["flow_bytes"]["tail_alpha"] < 1.8


def test_fit_rba_and_full_calibration(tmp_path) -> None:
    rba = tmp_path / "rba.csv"
    rows = ["index,Login Timestamp,User ID,Country,Device Type,Login Successful"]
    for i in range(1000):
        country = "NO" if i % 50 else "SE"
        rows.append(
            f"{i},2020-02-03 12:00:00.000,{i % 20},{country},{'mobile' if i % 4 == 0 else 'desktop'},{'False' if i % 10 == 0 else 'True'}"
        )
    rba.write_text("\n".join(rows))
    fitted = fit_rba(rba, max_rows=None)
    assert fitted["signin_failure_rate"] == pytest.approx(0.1)
    assert fitted["mobile_share"] == pytest.approx(0.25)
    assert 0 < fitted["new_country_rate"] < 0.05

    cal = calibrate(load_calibration(), rba=rba)
    assert cal.signin_failure_rate == pytest.approx(0.1)
    assert cal.source.startswith("fitted on RBA")
    out = tmp_path / "fitted.yaml"
    dump_calibration(cal, out)
    assert Calibration.model_validate(load_calibration(out).model_dump()) == load_calibration(out)


def test_calibrate_cli(tmp_path) -> None:
    rba = tmp_path / "rba.csv"
    rba.write_text(
        "User ID,Country,Device Type,Login Successful\n1,NO,mobile,True\n1,NO,desktop,False\n"
    )
    out = tmp_path / "cal.yaml"
    result = CliRunner().invoke(app, ["calibrate", "--rba", str(rba), "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert load_calibration(out).signin_failure_rate == pytest.approx(0.5)
    assert CliRunner().invoke(app, ["calibrate"]).exit_code != 0
