from __future__ import annotations

from analysis import ascii_rate_plot, running_success_rate
from models import EntropyResult, RefreshSnapshot


def format_entropy_summary(result: EntropyResult) -> str:
    return "\n".join(
        [
            "Entropy Result",
            "--------------",
            f"H(X): {result.entropy_bits:.6f} bits",
            f"Normalized H(X): {result.normalized_entropy:.2%}",
        ]
    )


def format_entropy_report(result: EntropyResult) -> str:
    lines = [
        "Shannon Entropy Report",
        "----------------------",
        f"Samples: {result.sample_count}",
        f"Unique symbols: {result.symbol_count}",
        f"Entropy H(X): {result.entropy_bits:.6f} bits",
        f"Max entropy: {result.max_entropy_bits:.6f} bits",
        f"Normalized entropy: {result.normalized_entropy:.2%}",
        "",
        "Symbol probabilities:",
    ]

    for symbol, probability in result.probabilities:
        lines.append(f"  {symbol:<16} p={probability:.4f}")

    return "\n".join(lines)


def format_capture_report(
    interface: str,
    elapsed_seconds: float,
    refresh_seconds: float,
    packet_count: int,
) -> str:
    return "\n".join(
        [
            "Capture Session",
            "---------------",
            f"Interface: {interface}",
            f"Elapsed listening time: {elapsed_seconds:.2f} seconds",
            f"Refresh interval: every {refresh_seconds:.2f} seconds",
            f"Captured packets: {packet_count}",
        ]
    )


def format_bernoulli_report(sequence: list[int], success_symbol: str) -> str:
    if not sequence:
        return "Bernoulli Process\n-----------------\nNo Bernoulli sequence provided."

    rates = running_success_rate(sequence)
    success_probability = sum(sequence) / len(sequence)
    head = " ".join(str(v) for v in sequence[:50])
    tail = "" if len(sequence) <= 50 else f" ... ({len(sequence)} trials total)"

    lines = [
        "Bernoulli Process",
        "-----------------",
        f"Projection rule: 1 if symbol == '{success_symbol}', else 0",
        f"Trials: {len(sequence)}",
        f"Estimated p(success): {success_probability:.6f}",
        f"Sequence (first 50): {head}{tail}",
        "",
        "Running success-rate plot:",
        ascii_rate_plot(rates),
    ]
    return "\n".join(lines)


def format_binary_entropy_timeline(history: list[RefreshSnapshot]) -> str:
    if not history:
        return "Binary Entropy Timeline\n-----------------------\nNo refresh snapshots yet."

    values = [snapshot.binary_entropy_bits for snapshot in history]
    current = history[-1]
    lines = [
        "Binary Entropy Timeline",
        "-----------------------",
        "Definition: Hb(p) = -p log2(p) - (1-p) log2(1-p)",
        f"Current dominant symbol: {current.dominant_symbol}",
        f"Current p(success): {current.success_probability:.6f}",
        f"Current Hb(p): {current.binary_entropy_bits:.6f} bits",
        "",
        "Hb(p) over refresh ticks:",
        ascii_rate_plot(values),
    ]
    return "\n".join(lines)


def format_refresh_history(history: list[RefreshSnapshot]) -> str:
    if not history:
        return "Refresh History\n---------------\nNo snapshots yet."

    lines = [
        "Refresh History",
        "---------------",
        "tick | time(s) | total | +new | dominant   | p(success) | Hb(p)  | H(X)",
    ]
    for snapshot in history:
        lines.append(
            f"{snapshot.tick:>4} | "
            f"{snapshot.elapsed_seconds:>7.2f} | "
            f"{snapshot.total_packets:>5} | "
            f"{snapshot.new_packets:>4} | "
            f"{snapshot.dominant_symbol:<10} | "
            f"{snapshot.success_probability:>10.4f} | "
            f"{snapshot.binary_entropy_bits:>6.4f} | "
            f"{snapshot.shannon_entropy_bits:>4.2f}"
        )
    return "\n".join(lines)


def about_text() -> str:
    return "\n".join(
        [
            "What this app calculates",
            "------------------------",
            "From live captured packets, the app builds symbol classes (TCP, DNS/UDP, ARP, etc.).",
            "It computes Shannon entropy in bits:",
            "H(X) = -sum_i p_i log2(p_i)",
            "where p_i is the observed probability of symbol i.",
            "",
            "How to read it",
            "--------------",
            "Low H(X): traffic mix is concentrated and more predictable.",
            "High H(X): traffic mix is diverse and less predictable.",
            "Normalized H(X) is also shown for easier comparison across sessions.",
            "Binary entropy Hb(p) is plotted per refresh (0 to 1 bits).",
            "",
            "Why useful",
            "----------",
            "Provides a compact traffic-diversity fingerprint over time.",
            "Helps flag abrupt protocol-mix shifts for deeper investigation.",
            "",
            "Controls",
            "--------",
            "Start begins capture immediately. Refresh duration controls update cadence.",
            "Stop ends capture and keeps the latest report on screen.",
            "Refresh History preserves all timeframe snapshots for retrospective review.",
            "",
            "Packet capture may require Administrator privileges and Npcap on Windows.",
            "",
            "[link=\"https://en.wikipedia.org/wiki/Entropy_(information_theory)\"]Shannon entropy on Wikipedia[/link]",
        ]
    )
