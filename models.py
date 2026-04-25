from __future__ import annotations
"""
# Data Models: Core Structures

This module defines the shared **data structures** that flow through the entire
Shannon Entropy Analyzer pipeline. Every other module reads from or writes to
these structures.

## Why Dataclasses?

Python's `@dataclass` decorator automatically generates `__init__`, `__repr__`,
and `__eq__` methods from type-annotated class fields. This keeps our data
containers concise and self-documenting. You can read the fields and immediately
understand what data each object carries.

## The Three Core Models

| Model             | Purpose                                      | Created By          | Consumed By                    |
|--------------------|----------------------------------------------|---------------------|--------------------------------|
| `EntropyResult`   | Output of a single entropy calculation       | `analysis.py`       | `formatters.py`, `app.py`      |
| `RefreshSnapshot` | Point-in-time capture of all network metrics | `app.py`            | `shift_detection.py`, `exporters.py`, `formatters.py` |
| `WarningEvent`    | An escalated anomaly alert                   | `app.py`            | `formatters.py`                |

## Data Flow

```
capture.py → symbols → analysis.py → EntropyResult
                                          ↓
                                    app.py builds RefreshSnapshot
                                          ↓
                                shift_detection.py → ShiftAssessment
                                          ↓
                                    app.py builds WarningEvent (if needed)
                                          ↓
                                formatters.py → display strings
```
"""

from dataclasses import dataclass, field


@dataclass
class EntropyResult:
    """
    Holds the result of a Shannon Entropy calculation on a sample of network packets.
    Includes both the raw bits of entropy and the normalized entropy relative to the maximum possible.
    """
    symbol_count: int
    sample_count: int
    entropy_bits: float
    max_entropy_bits: float
    normalized_entropy: float
    probabilities: list[tuple[str, float]]


@dataclass
class RefreshSnapshot:
    """
    Represents a point-in-time snapshot of the network state.
    These are collected at regular intervals and used to calculate rolling baselines
    for the Shift Detection algorithms.
    """
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


@dataclass
class WarningEvent:
    """
    An escalated network event generated when the Shift Detection algorithm
    flags anomalous behavior (e.g. DoS, Exfiltration, Port Scan).
    """
    tick: int
    elapsed_seconds: float
    level: str
    score: float
    reasons: list[str]
    status: str = "NEW"
