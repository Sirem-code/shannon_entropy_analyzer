from __future__ import annotations

from collections import Counter
from math import log2
from typing import Iterable

from models import EntropyResult


def compute_shannon_entropy(symbols: Iterable[str]) -> EntropyResult:
    symbol_list = list(symbols)
    if not symbol_list:
        raise ValueError("No network symbols were provided.")

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


def ascii_rate_plot(values: list[float], width: int = 60, height: int = 10) -> str:
    if not values:
        return "(no data to plot)"

    sampled = downsample(values, width)
    plot_width = len(sampled)
    grid = [[" " for _ in range(plot_width)] for _ in range(height)]

    for x, value in enumerate(sampled):
        y = int(round((1 - value) * (height - 1)))
        y = max(0, min(height - 1, y))
        grid[y][x] = "*"

    lines: list[str] = []
    for row in range(height):
        label_value = 1 - (row / (height - 1)) if height > 1 else 1.0
        lines.append(f"{label_value:>4.2f} | {''.join(grid[row])}")

    lines.append("     + " + "-" * plot_width)
    lines.append("       tick index ->")
    return "\n".join(lines)
