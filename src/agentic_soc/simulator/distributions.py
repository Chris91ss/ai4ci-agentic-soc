"""Random distributions used by the generators: heavy tails, jittered periods, tail estimates."""

from __future__ import annotations

import math

import numpy as np


def lognormal(rng: np.random.Generator, median: float, sigma: float, size: int | None = None):
    """Log-normal draws parameterised by their median."""
    return rng.lognormal(math.log(median), sigma, size)


def pareto(rng: np.random.Generator, alpha: float, xmin: float, size: int | None = None):
    """Classical Pareto(alpha, xmin): P(X > x) = (xmin / x) ** alpha for x >= xmin."""
    u = rng.random(size)
    return xmin * (1.0 - u) ** (-1.0 / alpha)


def heavy_tailed(
    rng: np.random.Generator,
    size: int,
    median: float,
    sigma: float,
    tail_prob: float,
    tail_alpha: float,
    tail_xmin: float,
    cap: float = 5e10,
) -> np.ndarray:
    """Log-normal body with a Pareto tail (self-similar traffic, Leland et al. 1994)."""
    body = lognormal(rng, median, sigma, size)
    tail_mask = rng.random(size) < tail_prob
    n_tail = int(tail_mask.sum())
    if n_tail:
        body[tail_mask] = pareto(rng, tail_alpha, tail_xmin, n_tail)
    return np.minimum(body, cap)


def jittered_intervals(
    rng: np.random.Generator, period: float, jitter: float, size: int
) -> np.ndarray:
    """Beacon-style intervals: ``period * U(1 - jitter, 1 + jitter)``."""
    return period * rng.uniform(1.0 - jitter, 1.0 + jitter, size)


def hill_alpha(values: np.ndarray, k: int | None = None) -> float:
    """Hill estimator of the tail index from the ``k`` largest observations."""
    x = np.sort(np.asarray(values, dtype=float))[::-1]
    x = x[x > 0]
    if k is None:
        k = max(10, len(x) // 20)
    k = min(k, len(x) - 1)
    if k < 2:
        return float("nan")
    logs = np.log(x[:k]) - math.log(x[k])
    return float(k / logs.sum()) if logs.sum() > 0 else float("nan")


def poisson_count(rng: np.random.Generator, rate_per_s: float, dt_s: float) -> int:
    """Events of a (piecewise constant) Poisson process within one tick."""
    lam = rate_per_s * dt_s
    return int(rng.poisson(lam)) if lam > 0 else 0
