from __future__ import annotations

from dataclasses import dataclass, field


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
    packet_rate: float = 0.0
    baseline_shannon_bits: float = 0.0
    baseline_packet_rate: float = 0.0
    dominant_share_delta: float = 0.0
    shift_score: float = 0.0
    alert_level: str = "NONE"
    alert_reasons: list[str] = field(default_factory=list)
