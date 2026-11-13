"""Diurnal and weekly activity profiles."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import numpy as np


def normalise(values: list[float] | np.ndarray) -> tuple[float, ...]:
    """Scale a profile to mean 1 so that it only shapes, never changes, the average rate."""
    arr = np.asarray(values, dtype=float)
    if arr.min() < 0 or arr.sum() == 0:
        raise ValueError("profile values must be non-negative and not all zero")
    return tuple(float(v) for v in arr / arr.mean())


def rotate_to_trough(hourly: np.ndarray, trough_hour: int = 3) -> np.ndarray:
    """Phase-align a 24-bin profile whose clock offset is unknown (e.g. LANL relative time).

    The smoothed minimum of the profile is moved to ``trough_hour`` local time.
    """
    smooth = np.convolve(np.tile(hourly, 3), [0.25, 0.5, 0.25], mode="same")[24:48]
    shift = (trough_hour - int(np.argmin(smooth))) % 24
    return np.roll(hourly, shift)


def rotate_to_weekend(daily: np.ndarray) -> np.ndarray:
    """Phase-align a 7-bin profile so that its two quietest consecutive days are Sat and Sun."""
    pair = daily + np.roll(daily, -1)
    first_quiet = int(np.argmin(pair))
    return np.roll(daily, (5 - first_quiet) % 7)


@dataclass(frozen=True, slots=True)
class ActivityProfile:
    """Rate multiplier ``hourly(local hour, linearly interpolated) * weekly(weekday)``."""

    hourly: tuple[float, ...]
    weekly: tuple[float, ...]

    def __post_init__(self) -> None:
        if len(self.hourly) != 24 or len(self.weekly) != 7:
            raise ValueError("need 24 hourly and 7 weekly values")

    @classmethod
    def from_lists(cls, hourly: list[float], weekly: list[float]) -> ActivityProfile:
        return cls(normalise(hourly), normalise(weekly))

    def hour_factor(self, local: datetime) -> float:
        h = local.hour
        frac = local.minute / 60.0
        return self.hourly[h] * (1.0 - frac) + self.hourly[(h + 1) % 24] * frac

    def factor(self, local: datetime) -> float:
        return self.hour_factor(local) * self.weekly[local.weekday()]
