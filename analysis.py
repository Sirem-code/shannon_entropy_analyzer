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


def braille_sparkline(values: list[float], width: int = 60, height: int = 4) -> str:
    """Generates a high-resolution sparkline using Braille patterns."""
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
