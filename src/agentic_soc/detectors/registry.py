"""Versioned model registry: ``models/<detector>/<version>/`` plus a ``current.json`` pointer.

Retraining writes a new version next to the old ones; promotion is an explicit, audited step,
so a bad model can be rolled back by promoting the previous version.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentic_soc.detectors.base import Detector, Score
from agentic_soc.detectors.m1 import M1Detector
from agentic_soc.detectors.m2 import M2Detector
from agentic_soc.detectors.m3 import M3Detector
from agentic_soc.features import FeatureRow, Profiles

CLASSES: dict[str, type[Detector]] = {"M1": M1Detector, "M2": M2Detector, "M3": M3Detector}
KIND_TO_DETECTOR = {"M1-user": "M1", "M1-ip": "M1", "M2": "M2", "M3": "M3"}


class ModelRegistry:
    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or os.environ.get("SOC_MODELS", "models"))

    def save(self, detector: Detector, promote: bool = True) -> Path:
        path = self.root / detector.name / detector.version
        detector.save(path)
        if promote or self.current(detector.name) is None:
            self.promote(detector.name, detector.version)
        return path

    def promote(self, name: str, version: str) -> None:
        if not (self.root / name / version / "meta.json").exists():
            raise FileNotFoundError(f"{name} version {version} not found in {self.root}")
        pointer = {"version": version, "promoted_at": datetime.now(UTC).isoformat()}
        (self.root / name / "current.json").write_text(json.dumps(pointer) + "\n")

    def current(self, name: str) -> str | None:
        pointer = self.root / name / "current.json"
        if not pointer.exists():
            return None
        return json.loads(pointer.read_text())["version"]

    def versions(self, name: str) -> list[dict[str, Any]]:
        out = []
        current = self.current(name)
        for meta_path in sorted((self.root / name).glob("*/meta.json")):
            meta = json.loads(meta_path.read_text())
            out.append(
                {
                    "version": meta["version"],
                    "current": meta["version"] == current,
                    "thresholds": meta.get("thresholds"),
                    "validation": meta.get("validation"),
                }
            )
        return out

    def load(self, name: str, version: str | None = None) -> Detector:
        version = version or self.current(name)
        if version is None:
            raise FileNotFoundError(f"no promoted {name} model in {self.root}; run `soc train`")
        return CLASSES[name].load(self.root / name / version)  # type: ignore[attr-defined]

    def load_set(self) -> DetectorSet:
        return DetectorSet({name: self.load(name) for name in CLASSES})


@dataclass
class DetectorSet:
    """The promoted M1-M3 models, dispatching feature rows by kind."""

    detectors: dict[str, Detector]

    @property
    def profiles(self) -> Profiles:
        return self.detectors["M1"].profiles  # type: ignore[attr-defined]

    @property
    def versions(self) -> dict[str, str]:
        return {name: d.version for name, d in self.detectors.items()}

    def thresholds(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for detector in self.detectors.values():
            out.update(detector.thresholds)
        return out

    def score(self, rows: list[FeatureRow]) -> list[tuple[FeatureRow, Score]]:
        by_detector: dict[str, list[FeatureRow]] = {}
        for row in rows:
            by_detector.setdefault(KIND_TO_DETECTOR[row.detector], []).append(row)
        out: list[tuple[FeatureRow, Score]] = []
        for name, detector_rows in by_detector.items():
            scores = self.detectors[name].score(detector_rows)
            out.extend(zip(detector_rows, scores, strict=True))
        return out
