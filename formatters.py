from __future__ import annotations

from collections import Counter

from analysis import ascii_rate_plot, ascii_series_plot, running_success_rate
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
    previous_packets = history[-2].total_packets if len(history) > 1 else 0
    packet_delta = current.total_packets - previous_packets
    avg_new_packets = sum(snapshot.new_packets for snapshot in history) / len(history)
    packet_rate = (current.total_packets / current.elapsed_seconds) if current.elapsed_seconds > 0 else 0.0
    hb_delta = (
        current.binary_entropy_bits - history[-2].binary_entropy_bits if len(history) > 1 else 0.0
    )
    trend_label = "rising" if hb_delta > 0 else "falling" if hb_delta < 0 else "stable"
    lines = [
        "Binary Entropy Timeline",
        "-----------------------",
        f"Elapsed time: {current.elapsed_seconds:.2f} s",
        f"Packets observed: {current.total_packets}",
        f"Packets since last tick: {packet_delta}",
        f"Current p(success): {current.success_probability:.6f}",
        f"Current Hb(p): {current.binary_entropy_bits:.6f} bits",
        "",
        "Hb(p) over refresh ticks:",
        ascii_rate_plot(values),
        "",
        "Networking context:",
        f"Approx packet rate: {packet_rate:.2f} packets/s",
        f"Avg packets per refresh: {avg_new_packets:.2f}",
        f"Last refresh packet burst: {current.new_packets}",
        f"Dominant traffic share: {current.success_probability:.2%}",
        f"Binary entropy trend vs last tick: {hb_delta:+.4f} bits ({trend_label})",
    ]
    return "\n".join(lines)


def format_trends_metrics(history: list[RefreshSnapshot]) -> str:
    if not history:
        return "Key Metrics\n-----------\nNo metrics yet. Start capture to populate trends."

    current = history[-1]
    previous_packets = history[-2].total_packets if len(history) > 1 else 0
    packet_delta = current.total_packets - previous_packets
    avg_new_packets = sum(snapshot.new_packets for snapshot in history) / len(history)
    packet_rate = (current.total_packets / current.elapsed_seconds) if current.elapsed_seconds > 0 else 0.0
    hb_delta = current.binary_entropy_bits - history[-2].binary_entropy_bits if len(history) > 1 else 0.0
    trend_label = "rising" if hb_delta > 0 else "falling" if hb_delta < 0 else "stable"

    return "\n".join(
        [
            "Key Metrics",
            "-----------",
            f"Time: {current.elapsed_seconds:.2f}s | Total packets: {current.total_packets} | New packets: {packet_delta}",
            f"Packet rate: {packet_rate:.2f}/s | Avg new/refresh: {avg_new_packets:.2f}",
            f"H(X): {current.shannon_entropy_bits:.4f} bits | Hb(p): {current.binary_entropy_bits:.4f} bits",
            f"Dominant share p(success): {current.success_probability:.2%} | Hb trend: {hb_delta:+.4f} ({trend_label})",
        ]
    )


def format_shannon_entropy_timeline(history: list[RefreshSnapshot]) -> str:
    if not history:
        return "Shannon Entropy Timeline\n-----------------------\nNo refresh snapshots yet."

    values = [snapshot.shannon_entropy_bits for snapshot in history]
    current = history[-1]
    max_value = max(values)
    y_max = max(2.0, max_value * 1.15)
    lines = [
        "Shannon Entropy Timeline",
        "-----------------------",
        f"Current H(X): {current.shannon_entropy_bits:.6f} bits",
        "",
        "H(X) over refresh ticks:",
        ascii_series_plot(values, y_min=0.0, y_max=y_max),
    ]
    return "\n".join(lines)


def format_packet_analysis(symbols: list[str], elapsed_seconds: float) -> str:
    if not symbols:
        return "Packet Analysis\n---------------\nNo packets captured yet."

    counts = Counter(symbols)
    total = len(symbols)
    unique = len(counts)
    top_items = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    dominant_symbol, dominant_count = top_items[0]
    dominant_share = dominant_count / total
    packet_rate = total / elapsed_seconds if elapsed_seconds > 0 else 0.0

    # Herfindahl-Hirschman-style concentration index for protocol mix intensity.
    concentration = sum((count / total) ** 2 for count in counts.values())
    diversity = 1.0 - concentration

    lines = [
        "Packet Analysis",
        "---------------",
        f"Total packets: {total}",
        f"Observed protocol classes: {unique}",
        f"Approx packet rate: {packet_rate:.2f} packets/s",
        f"Dominant protocol: {dominant_symbol} ({dominant_share:.2%})",
        f"Protocol concentration index: {concentration:.4f}",
        f"Protocol diversity score: {diversity:.4f}",
        "",
        "Protocol distribution:",
    ]

    for symbol, count in top_items:
        share = count / total
        lines.append(f"  {symbol:<12} count={count:>6}  share={share:>7.2%}")

    return "\n".join(lines)


def format_investigation_report(history: list[RefreshSnapshot]) -> str:
    if not history:
        return "Investigation\n-------------\nNo refresh snapshots yet."

    current = history[-1]
    alerts = [item for item in history if item.alert_level != "NONE"]
    recent = history[-12:]

    lines = [
        "Investigation",
        "-------------",
        f"Current alert level: {current.alert_level}",
        f"Current shift score: {current.shift_score:.2f}",
        "",
        "Before/after baseline comparison:",
        f"H(X): {current.shannon_entropy_bits:.4f} vs baseline {current.baseline_shannon_bits:.4f}",
        f"Packet rate: {current.packet_rate:.2f}/s vs baseline {current.baseline_packet_rate:.2f}/s",
        f"Dominant share delta: {current.dominant_share_delta:+.2%}",
    ]

    if current.alert_reasons:
        lines.append("")
        lines.append("Current trigger reasons:")
        for reason in current.alert_reasons:
            lines.append(f"- {reason}")

    lines.append("")
    lines.append("Alert timeline (recent ticks):")
    lines.append("tick | time(s) | level    | score")
    for item in recent:
        lines.append(
            f"{item.tick:>4} | {item.elapsed_seconds:>7.2f} | {item.alert_level:<8} | {item.shift_score:>5.2f}"
        )

    lines.append("")
    lines.append(f"Active alerts in session: {len(alerts)}")
    if alerts:
        latest = alerts[-1]
        lines.append(
            f"Latest alert: tick {latest.tick} ({latest.alert_level}, score {latest.shift_score:.2f})"
        )

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
            "Important terms",
            "---------------",
            "H(X): Shannon entropy of captured protocol symbols; higher means more diverse mix.",
            "Hb(p): Binary entropy of Bernoulli projection; tracks uncertainty of success/failure mapping.",
            "p(success): Share of packets belonging to the currently dominant protocol class.",
            "Dominant share: Same as p(success); if very high, traffic is concentrated in one protocol.",
            "Dominant protocol: Protocol class with the highest packet count at the current refresh tick.",
            "Protocol concentration index: Sum of squared protocol shares; higher means less mixing.",
            "Protocol diversity score: 1 - concentration index; higher means stronger protocol mixing.",
            "Refresh tick: One analysis update cycle based on the selected refresh interval.",
            "Packet burst: Number of new packets observed since the previous refresh tick.",
            "",
            "Packet capture may require Administrator privileges and Npcap on Windows.",
            "",
            "[link=\"https://en.wikipedia.org/wiki/Entropy_(information_theory)\"]Shannon entropy on Wikipedia[/link]",
        ]
    )
