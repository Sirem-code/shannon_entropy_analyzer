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
    new_protocols: set[str] = None,
    window_size: int = 8,
    min_baseline_points: int = 5,
    shannon_drop_tolerance: float = 0.7,
    dominant_share_tolerance: float = 0.15,
    packet_rate_multiplier: float = 2.0,
    flood_packet_rate_multiplier: float = 3.0,
    flood_entropy_ceiling: float = 1.0,
    scan_entropy_floor: float = 3.0,
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
    elif abs(shannon_delta) > shannon_drop_tolerance:
        score += 1.0
        reasons.append(f"Entropy moved by {shannon_delta:+.3f} bits from baseline")

    dominant_share_delta = current_dominant_share - mean_dominant_share
    if abs(dominant_share_delta) > dominant_share_tolerance:
        score += 2.0
        reasons.append(
            f"Dominant share changed by {dominant_share_delta:+.2%} vs baseline {mean_dominant_share:.2%}"
        )

    if median_packet_rate > 0 and current_packet_rate > packet_rate_multiplier * median_packet_rate:
        score += 2.0
        reasons.append(
            f"Packet rate spike: {current_packet_rate:.2f}/s vs baseline median {median_packet_rate:.2f}/s"
        )

    # Compound Heuristic Alerts
    packet_rate_ratio = current_packet_rate / median_packet_rate if median_packet_rate > 0 else 1.0
    is_high_packet_rate = packet_rate_ratio > flood_packet_rate_multiplier

    if is_high_packet_rate and current_shannon_bits < flood_entropy_ceiling:
        score += 5.0
        reasons.append(
            f"[!] HEURISTIC ALERT: Possible DoS/Flood Attack! High packet rate ({current_packet_rate:.1f}/s) with extremely low entropy ({current_shannon_bits:.2f} bits)."
        )
    elif is_high_packet_rate and current_shannon_bits > scan_entropy_floor and shannon_delta > 0.5:
        score += 5.0
        reasons.append(
            f"[!] HEURISTIC ALERT: Possible Port Scan/Reconnaissance! High packet rate ({current_packet_rate:.1f}/s) with high/spiking entropy ({current_shannon_bits:.2f} bits)."
        )
    elif shannon_delta > 1.5 and current_shannon_bits > 4.0 and not is_high_packet_rate:
        score += 4.0
        reasons.append(
            f"[!] HEURISTIC ALERT: Possible Data Exfiltration/Tunneling! Sudden extreme entropy spike ({current_shannon_bits:.2f} bits) indicating encrypted or random traffic."
        )

    # 1. Entropy Volatility (Jitter) Warning
    if std_shannon > 1.0:
        score += 3.0
        reasons.append(
            f"[!] VOLATILITY ALERT: High Entropy Jitter! Standard deviation is very high ({std_shannon:.2f}), indicating an unstable network state."
        )

    # 2. Sustained State Warning (Sustained low entropy)
    if all(item.shannon_entropy_bits < flood_entropy_ceiling for item in baseline) and len(baseline) >= 5:
        score += 4.0
        reasons.append(
            f"[!] SUSTAINED ALERT: Entropy has remained critically low (< {flood_entropy_ceiling:.2f}) for {len(baseline)} ticks (Possible continuous Broadcast Storm or Monoculture)."
        )

    # 3. New Species / Unknown Protocol Alert
    if new_protocols:
        score += 3.0
        reasons.append(
            f"[!] ANOMALY ALERT: New protocol(s) detected: {', '.join(new_protocols)}"
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
