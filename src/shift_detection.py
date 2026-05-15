from __future__ import annotations
"""
# Shift Detection: Anomaly Detection Engine

This module is the **intelligence layer** of the Shannon Entropy Analyzer. It
takes the current network metrics and compares them against a **rolling
historical baseline** to detect when something has significantly changed and
to classify *what kind* of change it might be.

## The Core Idea: Baseline Comparison

Normal network traffic has a relatively stable "personality": a predictable mix
of protocols, a steady packet rate, and a consistent entropy level. When
something abnormal happens, such as an attack, a misconfiguration, or a new application
starting, these metrics shift.

This module quantifies that shift by computing:

1. **Mean and Standard Deviation** of recent Shannon Entropy values
2. **Median** of recent packet rates
3. **Mean** of recent dominant protocol shares

Then it checks whether the *current* values deviate significantly from these
baselines.

## Detection Rules (Layered Approach)

The detection system uses three layers of rules, from simple to compound:

### Layer 1: Simple Deviation Checks
| Check                     | Trigger Condition                                    | Score |
|---------------------------|------------------------------------------------------|-------|
| Entropy Z-score           | Current H(X) is >2.5σ from the baseline mean         | +2.0  |
| Entropy drop              | H(X) dropped by more than the tolerance threshold    | +1.0  |
| Dominant share jump       | One protocol's share spiked by >15% (configurable)   | +2.0  |
| Packet rate spike         | Rate exceeds 2× the baseline median                  | +2.0  |

### Layer 2: Compound Heuristic Alerts
These combine multiple signals to identify *specific* attack patterns:

| Heuristic                  | Conditions                                           | Score |
|----------------------------|------------------------------------------------------|-------|
| **DoS/Flood Attack**       | Very high packet rate + very low entropy             | +5.0  |
| **Port Scan/Recon**        | Very high packet rate + high/spiking entropy         | +5.0  |
| **Data Exfiltration**      | Extreme entropy spike + normal packet rate           | +4.0  |

### Layer 3: Contextual Warnings
| Warning                    | Conditions                                           | Score |
|----------------------------|------------------------------------------------------|-------|
| **Entropy Volatility**     | Standard deviation of entropy >1.0 (unstable)        | +3.0  |
| **Sustained Low Entropy**  | Entropy below ceiling for ≥5 consecutive ticks       | +4.0  |
| **New Protocol Species**   | Previously unseen protocol appears                   | +3.0  |

## Alert Levels

The total score determines the alert level:

| Score Range  | Level      | Meaning                                           |
|-------------|------------|---------------------------------------------------|
| 0           | `NONE`     | System normal, no anomalies detected              |
| 0.1 – 1.9  | `INFO`     | Minor deviation, worth noting                     |
| 2.0 – 3.9  | `WARNING`  | Significant deviation, investigate                |
| 4.0+        | `CRITICAL` | Major anomaly, possible attack or failure         |

## Why "Shift" Detection?

The name comes from the statistical concept of a **distribution shift**, which occurs when
the underlying probability distribution of your data changes. In our case, the
"distribution" is the protocol mix. A shift means the network's behavior has
fundamentally changed, which is often the first sign of trouble.

## Key Parameters (All Configurable in the UI)

- `window_size`: How many past ticks to include in the baseline (default: 8)
- `shannon_drop_tolerance`: How much entropy can drop before alerting (default: 0.7)
- `dominant_share_tolerance`: How much a protocol's share can jump (default: 15%)
- `packet_rate_multiplier`: How much faster than baseline triggers an alert (default: 2×)
- `flood_packet_rate_multiplier`: Multiplier for the DoS heuristic (default: 3×)
- `flood_entropy_ceiling`: Maximum entropy for a flood classification (default: 1.0)
- `scan_entropy_floor`: Minimum entropy for a scan classification (default: 3.0)
"""

from dataclasses import dataclass
from statistics import median

from src.models import RefreshSnapshot


@dataclass
class ShiftAssessment:
    """
    Holds the computed results of the anomaly detection scan.
    """
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
    window_size: int = 15,
    min_baseline_points: int = 10,
    shannon_drop_tolerance: float = 1.2,
    dominant_share_tolerance: float = 0.25,
    packet_rate_multiplier: float = 3.0,
    flood_packet_rate_multiplier: float = 4.0,
    flood_entropy_ceiling: float = 0.8,
    scan_entropy_floor: float = 3.5,
) -> ShiftAssessment:
    """
    Analyzes the current network metrics against a rolling historical baseline
    to identify sudden shifts, volatility, and compound heuristics (like DoS attacks).
    
    Args:
        history: The list of past network snapshots.
        current_shannon_bits: Current Shannon entropy H(X).
        current_packet_rate: Current packets per second.
        current_dominant_share: The probability share of the single most common protocol.
        new_protocols: A set of protocol symbols seen in this tick that were never seen before.
        window_size: Number of past ticks to include in the baseline computation.
        min_baseline_points: Minimum ticks required before shift detection engages.
        shannon_drop_tolerance: Alert if entropy suddenly drops by this amount.
        dominant_share_tolerance: Alert if a single protocol's share jumps by this percentage.
        packet_rate_multiplier: Alert if the packet rate spikes by this factor vs the median.
        flood_packet_rate_multiplier: Multiplier threshold for DoS heuristic.
        flood_entropy_ceiling: Maximum allowed entropy during a flood heuristic check.
        scan_entropy_floor: Minimum required entropy during a scan heuristic check.
        
    Returns:
        A ShiftAssessment object containing the anomaly score and descriptive reasons.
    """
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
    if std_shannon > 0 and abs(shannon_delta) > 3.0 * std_shannon:
        score += 1.5
        reasons.append(
            f"Significant entropy shift: {shannon_delta:+.3f} bits vs baseline mean {mean_shannon:.3f}"
        )
    elif abs(shannon_delta) > shannon_drop_tolerance:
        score += 0.5
        reasons.append(f"Entropy moved by {shannon_delta:+.3f} bits from baseline")

    dominant_share_delta = current_dominant_share - mean_dominant_share
    if abs(dominant_share_delta) > dominant_share_tolerance:
        score += 1.0
        reasons.append(
            f"Dominant share changed by {dominant_share_delta:+.2%} vs baseline {mean_dominant_share:.2%}"
        )

    if median_packet_rate > 0 and current_packet_rate > packet_rate_multiplier * median_packet_rate:
        score += 1.5
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
