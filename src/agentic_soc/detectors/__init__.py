"""Detectors M1 (sign-in anomaly), M2 (flow classifier) and M3 (process rarity)."""

from agentic_soc.detectors.base import Detector, Score
from agentic_soc.detectors.m1 import M1Detector
from agentic_soc.detectors.m2 import M2Detector
from agentic_soc.detectors.m3 import M3Detector

__all__ = ["Detector", "M1Detector", "M2Detector", "M3Detector", "Score"]
