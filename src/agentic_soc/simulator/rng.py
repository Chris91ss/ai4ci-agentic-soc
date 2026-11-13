"""Deterministic random streams derived from the run seed and stable keys."""

from __future__ import annotations

import hashlib

import numpy as np


def stable_hash(*parts: object) -> int:
    """Process-independent 64-bit hash (``hash()`` of str is salted per process)."""
    digest = hashlib.blake2b("\x1f".join(map(str, parts)).encode(), digest_size=8).digest()
    return int.from_bytes(digest, "little")


def rng_for(seed: int, *keys: object) -> np.random.Generator:
    """Independent generator for (seed, keys): stable regardless of call order elsewhere."""
    return np.random.Generator(np.random.PCG64(np.random.SeedSequence([seed, stable_hash(*keys)])))
