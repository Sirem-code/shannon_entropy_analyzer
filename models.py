from __future__ import annotations

from dataclasses import dataclass


@dataclass
class EntropyResult:
    symbol_count: int
    sample_count: int
    entropy_bits: float
    max_entropy_bits: float
    normalized_entropy: float
    probabilities: list[tuple[str, float]]


@dataclass
class RefreshSnapshot:
    tick: int
    elapsed_seconds: float
    total_packets: int
    new_packets: int
    dominant_symbol: str
    success_probability: float
    binary_entropy_bits: float
    shannon_entropy_bits: float
