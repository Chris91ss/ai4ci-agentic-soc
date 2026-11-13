"""Calibration of the benign activity model on public datasets.

The simulator reads its rates, seasonality and size distributions from a calibration file
(``config/calibration/*.yaml``). ``default.yaml`` ships hand-set priors; ``soc calibrate``
refits the parameters from local copies of

* the LANL "Comprehensive, Multi-Source Cyber-Security Events" data (``auth.txt[.gz]``,
  ``flows.txt[.gz]``, ``proc.txt[.gz]``; Kent 2015), and
* the "Login Data Set for Risk-Based Authentication" (``rba-dataset.csv``; Wiefling et al.
  2022),

streaming at most ``max_rows`` records from each file. LANL uses relative timestamps with an
unknown clock offset, so its diurnal and weekly profiles are phase-aligned (quietest hour at
03:00, quietest two days on the weekend).
"""

from __future__ import annotations

import csv
import gzip
import io
import math
from collections import Counter, defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import numpy as np
import yaml
from pydantic import BaseModel, ConfigDict, Field

from agentic_soc.simulator.distributions import hill_alpha
from agentic_soc.simulator.seasonality import (
    ActivityProfile,
    normalise,
    rotate_to_trough,
    rotate_to_weekend,
)


class SizeDistribution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    median: float = Field(gt=0)
    sigma: float = Field(gt=0)
    tail_prob: float = Field(ge=0, le=0.5)
    tail_alpha: float = Field(gt=0)
    tail_xmin: float = Field(gt=0)


class Calibration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = "default priors"
    user_hourly: list[float] = Field(min_length=24, max_length=24)
    server_hourly: list[float] = Field(min_length=24, max_length=24)
    weekly: list[float] = Field(min_length=7, max_length=7)
    flow_bytes: SizeDistribution
    flow_duration_ms: SizeDistribution
    signin_failure_rate: float = Field(ge=0, le=0.5)
    mobile_share: float = Field(ge=0, le=1)
    new_country_rate: float = Field(ge=0, le=1)
    processes_per_host_hour: float = Field(gt=0)

    def user_profile(self) -> ActivityProfile:
        return ActivityProfile.from_lists(self.user_hourly, self.weekly)

    def server_profile(self) -> ActivityProfile:
        return ActivityProfile.from_lists(self.server_hourly, self.weekly)


def calibration_dir() -> Path:
    from agentic_soc.simulator.config import repo_root

    return repo_root() / "config" / "calibration"


def load_calibration(name_or_path: str | Path = "default") -> Calibration:
    path = Path(name_or_path)
    if not path.suffix:
        path = calibration_dir() / f"{name_or_path}.yaml"
    return Calibration.model_validate(yaml.safe_load(path.read_text()))


# ------------------------------------------------------------------------- readers


def _open_text(path: Path) -> io.TextIOBase:
    if path.suffix == ".gz":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def _rows(path: Path, max_rows: int | None, skip_header: bool = False) -> Iterator[list[str]]:
    with _open_text(path) as handle:
        reader = csv.reader(handle)
        if skip_header:
            next(reader, None)
        for i, row in enumerate(reader):
            if max_rows is not None and i >= max_rows:
                break
            yield row


def _profiles_from_times(times: np.ndarray) -> tuple[list[float], list[float] | None]:
    hourly = np.bincount(((times % 86400) // 3600).astype(int), minlength=24)[:24].astype(float)
    hourly = rotate_to_trough(hourly + 1e-9)
    days = (times // 86400).astype(int)
    weekly: list[float] | None = None
    if days.max() - days.min() >= 13:  # at least two full weeks for a weekly profile
        per_day = np.bincount(days - days.min()).astype(float)
        full_weeks = len(per_day) // 7
        by_weekday = per_day[: full_weeks * 7].reshape(full_weeks, 7).sum(axis=0)
        weekly = list(normalise(rotate_to_weekend(by_weekday + 1e-9)))
    return list(normalise(hourly)), weekly


def _size_distribution(values: np.ndarray, tail_prob: float = 0.05) -> dict[str, float]:
    values = values[values > 0].astype(float)
    xmin = float(np.quantile(values, 1 - tail_prob))
    body = values[values < xmin]
    logs = np.log(body)
    return {
        "median": float(math.exp(np.median(logs))),
        "sigma": float(max(np.std(logs), 1e-3)),
        "tail_prob": tail_prob,
        "tail_alpha": float(hill_alpha(values[values >= xmin], k=None)),
        "tail_xmin": xmin,
    }


def fit_lanl_auth(path: Path, max_rows: int | None = 5_000_000) -> dict[str, Any]:
    """Diurnal/weekly user activity and failure rate from LANL ``auth.txt``."""
    times, failures, total = [], 0, 0
    for row in _rows(path, max_rows):
        if len(row) < 9:
            continue
        times.append(int(row[0]))
        total += 1
        failures += row[8].strip().lower() == "fail"
    hourly, weekly = _profiles_from_times(np.asarray(times, dtype=np.int64))
    out: dict[str, Any] = {"user_hourly": hourly, "signin_failure_rate": failures / max(total, 1)}
    if weekly:
        out["weekly"] = weekly
    out["_auth_events"] = total
    return out


def fit_lanl_flows(path: Path, max_rows: int | None = 5_000_000) -> dict[str, Any]:
    """Server-side load profile and heavy-tailed byte/duration distributions from ``flows.txt``."""
    times, durations, byte_counts = [], [], []
    for row in _rows(path, max_rows):
        if len(row) < 9:
            continue
        times.append(int(row[0]))
        durations.append(int(row[1]) * 1000)
        byte_counts.append(int(row[8]))
    times_arr = np.asarray(times, dtype=np.int64)
    hourly, weekly = _profiles_from_times(times_arr)
    durations_arr = np.asarray(durations, dtype=float)
    durations_arr = durations_arr[durations_arr > 0]
    out: dict[str, Any] = {
        "server_hourly": hourly,
        "flow_bytes": _size_distribution(np.asarray(byte_counts)),
        "_flow_events": len(times),
    }
    if len(durations_arr) > 100:
        out["flow_duration_ms"] = _size_distribution(durations_arr)
    if weekly:
        out["weekly"] = weekly
    return out


def fit_lanl_proc(path: Path, max_rows: int | None = 5_000_000) -> dict[str, Any]:
    """Average process starts per host and hour from ``proc.txt``."""
    starts: Counter[str] = Counter()
    first, last = math.inf, -math.inf
    for row in _rows(path, max_rows):
        if len(row) < 5 or row[4].strip().lower() != "start":
            continue
        t = int(row[0])
        first, last = min(first, t), max(last, t)
        starts[row[2]] += 1
    hours = max((last - first) / 3600.0, 1.0)
    per_host = np.asarray(list(starts.values()), dtype=float) / hours
    return {"processes_per_host_hour": float(np.median(per_host)) if len(per_host) else 30.0}


def fit_rba(path: Path, max_rows: int | None = 5_000_000) -> dict[str, Any]:
    """Login failure rate, mobile share and per-user new-country rate from the RBA dataset."""
    seen: dict[str, set[str]] = defaultdict(set)
    total = failures = mobile = new_country = repeat_logins = 0
    with _open_text(path) as handle:
        reader = csv.DictReader(handle)
        for i, row in enumerate(reader):
            if max_rows is not None and i >= max_rows:
                break
            total += 1
            failures += str(row.get("Login Successful", "")).strip().lower() in {"false", "0"}
            mobile += str(row.get("Device Type", "")).strip().lower() == "mobile"
            user, country = row.get("User ID", ""), row.get("Country", "")
            if seen[user]:
                repeat_logins += 1
                new_country += country not in seen[user]
            seen[user].add(country)
    return {
        "signin_failure_rate": failures / max(total, 1),
        "mobile_share": mobile / max(total, 1),
        "new_country_rate": new_country / max(repeat_logins, 1),
        "_rba_logins": total,
    }


def calibrate(
    base: Calibration,
    lanl_auth: Path | None = None,
    lanl_flows: Path | None = None,
    lanl_proc: Path | None = None,
    rba: Path | None = None,
    max_rows: int | None = 5_000_000,
) -> Calibration:
    """Refit the parameters available from the given files on top of ``base``."""
    data = base.model_dump()
    notes: list[str] = []
    for label, path, fit in [
        ("LANL auth", lanl_auth, fit_lanl_auth),
        ("LANL flows", lanl_flows, fit_lanl_flows),
        ("LANL proc", lanl_proc, fit_lanl_proc),
        ("RBA", rba, fit_rba),
    ]:
        if path is None:
            continue
        fitted = fit(Path(path), max_rows)
        counts = {k: v for k, v in fitted.items() if k.startswith("_")}
        data.update({k: v for k, v in fitted.items() if not k.startswith("_")})
        notes.append(f"{label} ({next(iter(counts.values()), 'n/a')} records)")
    if notes:
        data["source"] = "fitted on " + ", ".join(notes) + f"; other values from {base.source}"
    return Calibration.model_validate(data)


def dump_calibration(calibration: Calibration, path: Path) -> None:
    payload = calibration.model_dump()
    for key in ("user_hourly", "server_hourly", "weekly"):
        payload[key] = [round(v, 4) for v in payload[key]]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False, width=100))
