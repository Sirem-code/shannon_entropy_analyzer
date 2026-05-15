from __future__ import annotations
"""
# Analysis Engine: Shannon Entropy and Visualization

This is the **mathematical heart** of the Shannon Entropy Analyzer. It contains
the core information-theory functions that transform a stream of protocol symbols
into quantified metrics about network diversity.

## Key Concepts for Students

### Shannon Entropy: H(X)
Given a discrete random variable X with possible values {x₁, x₂, ..., xₙ},
Shannon Entropy is:

    H(X) = −Σ p(xᵢ) · log₂(p(xᵢ))

- **Unit**: bits (because we use log base 2)
- **Minimum**: 0 bits (only one symbol exists, no uncertainty)
- **Maximum**: log₂(n) bits (all n symbols are equally likely)

### Binary Entropy: Hb(p)
A special case with only two outcomes (success/failure):

    Hb(p) = −p·log₂(p) − (1−p)·log₂(1−p)

This is useful for tracking how dominant the most common protocol is. It peaks
at exactly 1.0 bit when p = 0.5 (perfectly balanced).

### Bernoulli Process
We model the dominant protocol as a Bernoulli trial: each packet is either
the dominant protocol (1) or something else (0). The running success rate
shows how this probability evolves over time.

## Functions in This Module

| Function                    | Purpose                                              |
|-----------------------------|------------------------------------------------------|
| `compute_shannon_entropy()` | Main H(X) calculation from a symbol sequence         |
| `binary_entropy()`          | Hb(p) for a single probability value                 |
| `dominant_symbol()`         | Finds the most frequent symbol                       |
| `to_bernoulli_from_symbol_stream()` | Converts symbols into 1/0 binary sequence  |
| `running_success_rate()`    | Computes cumulative p(success) over time             |
| `braille_sparkline()`       | High-resolution terminal chart using Braille chars   |
| `downsample()`              | Reduces data resolution to fit chart width           |
| `ascii_series_plot()`       | Wrapper for generating Braille-based time series     |
| `ascii_rate_plot()`         | Convenience plot with 0.0–1.0 Y-axis range           |

## Example: Computing Entropy

```python
from src.analysis import compute_shannon_entropy

# A sample of captured protocol symbols
symbols = ["TCP", "TCP", "UDP", "DNS/UDP", "TCP", "ARP", "TCP"]
result = compute_shannon_entropy(symbols)

print(f"Entropy: {result.entropy_bits:.4f} bits")
print(f"Normalized: {result.normalized_entropy:.2%}")
print(f"Unique symbols: {result.symbol_count}")
```
"""

from collections import Counter
from math import log2
from typing import Iterable

from src.models import EntropyResult


def compute_shannon_entropy(symbols: Iterable[str]) -> EntropyResult:
    """
    Computes the Shannon Entropy (H) for a given sequence of symbols.
    Calculates the distribution of symbols, the raw entropy bits, and 
    a normalized entropy score relative to the maximum possible entropy.
    
    Args:
        symbols: An iterable of symbol strings (e.g., protocols like 'TCP', 'UDP').
        
    Returns:
        EntropyResult containing the calculated entropy metrics.
    """
    # Filter out any None values to prevent sorting errors
    symbol_list = [str(s) for s in symbols if s is not None]
    if not symbol_list:
        return EntropyResult(0, 0, 0.0, 0.0, 0.0, [])

    counts = Counter(symbol_list)
    total = sum(counts.values())
    symbol_count = len(counts)

    probabilities: list[tuple[str, float]] = []
    entropy = 0.0

    for symbol, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        probability = count / total
        probabilities.append((symbol, probability))
        entropy -= probability * log2(probability)

    max_entropy = log2(symbol_count) if symbol_count > 1 else 0.0
    normalized = entropy / max_entropy if max_entropy > 0 else 0.0

    return EntropyResult(
        symbol_count=symbol_count,
        sample_count=total,
        entropy_bits=entropy,
        max_entropy_bits=max_entropy,
        normalized_entropy=normalized,
        probabilities=probabilities,
    )


def dominant_symbol(symbols: list[str]) -> str:
    """
    Identifies the most frequently occurring symbol in a sequence.
    
    Args:
        symbols: A list of symbol strings.
        
    Returns:
        The single most frequent symbol.
    """
    if not symbols:
        raise ValueError("No network symbols were provided.")
    counts = Counter(symbols)
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def to_bernoulli_from_symbol_stream(symbols: list[str], success_symbol: str) -> list[int]:
    if not symbols:
        return []
    target = success_symbol.strip()
    if not target:
        raise ValueError("Target event symbol cannot be empty.")
    return [1 if symbol == target else 0 for symbol in symbols]


def binary_entropy(p_success: float) -> float:
    """
    Calculates the binary entropy (Hb) for a given probability of success.
    
    Args:
        p_success: The probability (0.0 to 1.0) of the dominant event occurring.
        
    Returns:
        The binary entropy in bits (peaks at 1.0 when p_success is 0.5).
    """
    if p_success <= 0.0 or p_success >= 1.0:
        return 0.0
    p_failure = 1.0 - p_success
    return -(p_success * log2(p_success) + p_failure * log2(p_failure))


def running_success_rate(sequence: list[int]) -> list[float]:
    rates: list[float] = []
    successes = 0
    for idx, value in enumerate(sequence, start=1):
        successes += value
        rates.append(successes / idx)
    return rates


def downsample(values: list[float], width: int) -> list[float]:
    if len(values) <= width:
        return values

    bucket_size = len(values) / width
    sampled: list[float] = []
    for i in range(width):
        start = int(i * bucket_size)
        end = int((i + 1) * bucket_size)
        if end <= start:
            end = start + 1
        bucket = values[start:end]
        sampled.append(sum(bucket) / len(bucket))
    return sampled


def braille_sparkline(values: list[float], width: int = 60, height: int = 4) -> str:
    """
    Generates a high-resolution text-based sparkline chart using Braille characters.
    
    Args:
        values: A sequence of float values to plot.
        width: The maximum character width of the plot.
        height: The character height of the plot (each character supports 4 vertical dots).
        
    Returns:
        A multiline string containing the Braille sparkline chart and Y-axis labels.
    """
    if not values:
        return "(no data)"

    sampled = downsample(values, width)
    # Braille cells are 2x4 dots. Vertical resolution = height * 4.
    v_res = height * 4
    local_min = min(sampled)
    local_max = max(sampled)
    if local_max <= local_min:
        local_max = local_min + 1.0
    v_range = local_max - local_min

    # Create a grid of bits (dots)
    dots = [[False for _ in range(len(sampled))] for _ in range(v_res)]
    for x, val in enumerate(sampled):
        norm = (val - local_min) / v_range
        y = int(round((1 - norm) * (v_res - 1)))
        y = max(0, min(v_res - 1, y))
        dots[y][x] = True

    # Convert dots to Braille characters
    lines = []
    for row in range(0, v_res, 4):
        line_chars = []
        for col in range(len(sampled)):
            # Braille dot mapping (standard)
            # 1 4
            # 2 5
            # 3 6
            # 7 8
            code = 0x2800
            if dots[row][col]: code |= 0x01
            if dots[row+1][col] if row+1 < v_res else False: code |= 0x02
            if dots[row+2][col] if row+2 < v_res else False: code |= 0x04
            if dots[row+3][col] if row+3 < v_res else False: code |= 0x40
            # We only use one column of dots per Braille char for simple width mapping
            line_chars.append(chr(code))
        
        label_val = local_max - ((row / v_res) * v_range)
        lines.append(f"{label_val:>4.2f} | {''.join(line_chars)}")

    lines.append("     + " + "-" * len(sampled))
    return "\n".join(lines)


def ascii_series_plot(
    values: list[float],
    width: int = 60,
    height: int = 2, # Braille height is 4 dots per char, so height=2 is 8 vertical dots
    y_min: float | None = None,
    y_max: float | None = None,
) -> str:
    # We'll use the braille_sparkline for better resolution
    return braille_sparkline(values, width=width, height=height)


def ascii_rate_plot(values: list[float], width: int = 60, height: int = 10) -> str:
    return ascii_series_plot(values, width=width, height=height, y_min=0.0, y_max=1.0)
