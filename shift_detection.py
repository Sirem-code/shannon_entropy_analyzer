from __future__ import annotations

from dataclasses import dataclass
from statistics import median

from models import RefreshSnapshot


@dataclass
class ShiftAssessment:
    score: float
    level: str
    reasons: list[str]
    baseline_shannon_bits: float
    baseline_packet_rate: float
    dominant_share_delta: float


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _std(values: list[float], mean_value: float) -> float:
    if len(values) <= 1:
        return 0.0
    variance = sum((value - mean_value) ** 2 for value in values) / (len(values) - 1)
    return variance ** 0.5


def detect_shift(
    history: list[RefreshSnapshot],
    current_shannon_bits: float,
    current_packet_rate: float,
    current_dominant_share: float,
    window_size: int = 8,
    min_baseline_points: int = 5,
) -> ShiftAssessment:
    baseline = history[-window_size:] if len(history) > window_size else history
    if len(baseline) < min_baseline_points:
        return ShiftAssessment(
            score=0.0,
            level="NONE",
            reasons=[],
            baseline_shannon_bits=0.0,
            baseline_packet_rate=0.0,
            dominant_share_delta=0.0,
        )

    shannon_values = [item.shannon_entropy_bits for item in baseline]
    packet_rates = [item.packet_rate for item in baseline]
    dominant_shares = [item.success_probability for item in baseline]

    mean_shannon = _mean(shannon_values)
    std_shannon = _std(shannon_values, mean_shannon)
    median_packet_rate = median(packet_rates)
    mean_dominant_share = _mean(dominant_shares)

    reasons: list[str] = []
    score = 0.0

    shannon_delta = current_shannon_bits - mean_shannon
    if std_shannon > 0 and abs(shannon_delta) > 2.5 * std_shannon:
        score += 2.0
        reasons.append(
            f"Shannon entropy shift: {shannon_delta:+.3f} bits vs baseline mean {mean_shannon:.3f}"
        )
    elif abs(shannon_delta) > 0.7:
        score += 1.0
        reasons.append(f"Entropy moved by {shannon_delta:+.3f} bits from baseline")

    dominant_share_delta = current_dominant_share - mean_dominant_share
    if abs(dominant_share_delta) > 0.15:
        score += 2.0
        reasons.append(
            f"Dominant share changed by {dominant_share_delta:+.2%} vs baseline {mean_dominant_share:.2%}"
        )

    if median_packet_rate > 0 and current_packet_rate > 2.0 * median_packet_rate:
        score += 2.0
        reasons.append(
            f"Packet rate spike: {current_packet_rate:.2f}/s vs baseline median {median_packet_rate:.2f}/s"
        )

    if score >= 4.0:
        level = "CRITICAL"
    elif score >= 2.0:
        level = "WARNING"
    elif score > 0.0:
        level = "INFO"
    else:
        level = "NONE"

    return ShiftAssessment(
        score=score,
        level=level,
        reasons=reasons,
        baseline_shannon_bits=mean_shannon,
        baseline_packet_rate=median_packet_rate,
        dominant_share_delta=dominant_share_delta,
    )
