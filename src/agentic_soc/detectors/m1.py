"""M1: sign-in anomaly detection with Isolation Forests (Liu, Ting and Zhou, 2008).

Two unsupervised forests learn benign behaviour from history: one over per-account windows
(novel countries, ASNs, devices, hours and logon types against the account's own baseline)
and one over external source-IP windows (password spraying across many accounts). The
per-account baselines are part of the model artifact and are frozen while serving.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from agentic_soc.detectors.base import (
    Detector,
    RobustStats,
    Score,
    TailCalibrator,
    matrix,
    new_version,
    threshold_for_fpr,
)
from agentic_soc.features import FEATURES, FeatureRow, Profiles

LOG_FEATURES = {
    "M1-user": {"n", "n_fail", "n_ips", "n_countries", "n_remote_interactive", "n_dst_hosts", "n_mfa_denied", "geo_km_max"},
    "M1-ip": {"n", "n_fail", "n_users", "n_unknown_users", "n_users_failed", "n_success_after_fail", "n_apps", "n_user_agents"},
}  # fmt: skip
DEFAULT_FPR = {"M1-user": 0.002, "M1-ip": 0.005}


def _transform(kind: str, X: np.ndarray) -> np.ndarray:
    X = np.array(X, dtype=float, copy=True)
    for j, name in enumerate(FEATURES[kind]):
        if name in LOG_FEATURES[kind]:
            X[:, j] = np.log1p(np.maximum(X[:, j], 0))
    return X


class M1Detector(Detector):
    name: ClassVar[str] = "M1"
    kinds: ClassVar[tuple[str, ...]] = ("M1-user", "M1-ip")

    def __init__(
        self,
        forests: dict[str, IsolationForest],
        calibrators: dict[str, TailCalibrator],
        stats: dict[str, RobustStats],
        profiles: Profiles,
        version: str,
        thresholds: dict[str, float],
        meta: dict[str, Any],
    ) -> None:
        super().__init__(version, thresholds, meta)
        self.forests = forests
        self.calibrators = calibrators
        self.stats = stats
        self.profiles = profiles

    # ------------------------------------------------------------------ training
    @classmethod
    def fit(
        cls,
        train: dict[str, np.ndarray],
        profiles: Profiles,
        seed: int = 0,
        n_estimators: int = 300,
    ) -> M1Detector:
        forests, calibrators, stats = {}, {}, {}
        for kind in cls.kinds:
            X = _transform(kind, train[kind])
            forest = IsolationForest(
                n_estimators=n_estimators,
                max_samples=min(512, len(X)),
                random_state=seed,
                n_jobs=-1,
            )
            forest.fit(X)
            raw = -forest.score_samples(X)
            forests[kind] = forest
            calibrators[kind] = TailCalibrator.fit(raw)
            stats[kind] = RobustStats.fit(FEATURES[kind], train[kind])
        meta = {"training_rows": {k: len(v) for k, v in train.items()}, "seed": seed}
        thresholds = {kind: 0.999 for kind in cls.kinds}
        return cls(forests, calibrators, stats, profiles, new_version("m1"), thresholds, meta)

    def raw_scores(self, kind: str, X: np.ndarray) -> np.ndarray:
        if len(X) == 0:
            return np.zeros(0)
        return self.calibrators[kind](-self.forests[kind].score_samples(_transform(kind, X)))

    def calibrate(
        self, benign: dict[str, np.ndarray], fpr: dict[str, float] | None = None
    ) -> dict[str, float]:
        """Set thresholds at a target false-positive rate on benign validation windows."""
        fpr = fpr or DEFAULT_FPR
        for kind in self.kinds:
            self.thresholds[kind] = threshold_for_fpr(
                self.raw_scores(kind, benign[kind]), fpr[kind]
            )
        self.meta["threshold_fpr"] = fpr
        return self.thresholds

    # ------------------------------------------------------------------ scoring
    def score(self, rows: list[FeatureRow]) -> list[Score]:
        out: list[Score | None] = [None] * len(rows)
        for kind in self.kinds:
            idx = [i for i, r in enumerate(rows) if r.detector == kind]
            if not idx:
                continue
            X = matrix([rows[i] for i in idx], kind)
            scores = self.raw_scores(kind, X)
            for j, i in enumerate(idx):
                row = rows[i]
                score = Score(
                    detector=self.name,
                    kind=kind,
                    score=float(scores[j]),
                    threshold=self.thresholds[kind],
                    top_features=self.stats[kind].explain(X[j]),
                )
                if score.alert:
                    score.techniques, score.summary = self.describe(row)
                out[i] = score
        return [s for s in out if s is not None]

    @staticmethod
    def describe(row: FeatureRow) -> tuple[list[str], str]:
        f, ctx = row.features, row.context
        if row.detector == "M1-ip":
            ip = row.ips[0] if row.ips else row.key
            where = ", ".join(str(x) for x in (ctx.get("org"), ctx.get("country")) if x)
            techniques = ["T1110.003"] if f["n_users_failed"] >= 3 else ["T1110"]
            if f["n_success_after_fail"] > 0:
                techniques.append("T1078")
            summary = (
                f"{int(f['n'])} sign-ins for {int(f['n_users'])} accounts from {ip}"
                f"{f' ({where})' if where else ''}: {int(f['n_fail'])} failed, "
                f"{int(f['n_unknown_users'])} unknown usernames, {int(f['n_success_after_fail'])} succeeded after failing"
            )
            return techniques, summary
        account = row.users[0] if row.users else row.key
        techniques = []
        succeeded = ctx.get("outcomes", {}).get("success", 0) > 0
        if (f["n_fail"] >= 3 and f["fail_ratio"] > 0.5) or not succeeded:
            techniques.append("T1110")
        if succeeded:
            techniques.append("T1078")
        if "vpn" in ctx.get("logon_types", []) and (
            f["new_country_share"] > 0 or f["hosting_share"] > 0
        ):
            techniques.append("T1133")
        if f["n_remote_interactive"] > 0 and f["new_dst_host_share"] > 0:
            techniques.append("T1021.001")
        novel = [
            label
            for name, label in (
                ("new_country_share", "new country"),
                ("new_asn_share", "new network"),
                ("new_device_share", "new device"),
                ("new_logon_type_share", "new logon type"),
                ("new_dst_host_share", "new target host"),
            )
            if f[name] > 0
        ]
        countries = ", ".join(ctx.get("countries", []))
        summary = (
            f"Unusual sign-ins for {account}: {int(f['n'])} attempts ({int(f['n_fail'])} failed)"
            f"{' from ' + countries if countries else ''}"
            f"{'; ' + ', '.join(novel) if novel else ''}"
            f"{'; hosting/anonymizer source' if f['hosting_share'] > 0 else ''}"
            f"{'; unusual hour' if f['hour_surprise'] > 6 else ''}"
        )
        return techniques or ["T1078"], summary

    # ------------------------------------------------------------------ persistence
    def save(self, directory: Path) -> None:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.forests, directory / "forests.joblib")
        self.profiles.save(directory / "profiles.json")
        extra = {
            "calibrators": {k: c.to_json() for k, c in self.calibrators.items()},
            "stats": {k: s.to_json() for k, s in self.stats.items()},
        }
        self._write_meta(directory, extra)

    @classmethod
    def load(cls, directory: Path) -> M1Detector:
        directory = Path(directory)
        meta = json.loads((directory / "meta.json").read_text())
        forests = joblib.load(directory / "forests.joblib")
        calibrators = {k: TailCalibrator.from_json(v) for k, v in meta.pop("calibrators").items()}
        stats = {k: RobustStats.from_json(v) for k, v in meta.pop("stats").items()}
        profiles = Profiles.load(directory / "profiles.json")
        version, thresholds = meta.pop("version"), meta.pop("thresholds")
        meta.pop("detector", None)
        return cls(forests, calibrators, stats, profiles, version, thresholds, meta)
