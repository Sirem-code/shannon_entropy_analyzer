from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from math import log2
from typing import Iterable, List

from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Button, Footer, Header, Input, Label, Static


@dataclass
class EntropyResult:
    symbol_count: int
    sample_count: int
    entropy_bits: float
    max_entropy_bits: float
    normalized_entropy: float
    probabilities: list[tuple[str, float]]


def parse_symbol_stream(raw: str) -> list[str]:
    cleaned = raw.replace(",", " ").strip()
    if not cleaned:
        return []
    return [token for token in cleaned.split() if token]


def parse_bernoulli_stream(raw: str) -> list[int]:
    tokens = parse_symbol_stream(raw)
    if not tokens:
        return []

    values: list[int] = []
    for token in tokens:
        if token not in {"0", "1"}:
            raise ValueError(f"Invalid Bernoulli token '{token}'. Use only 0 or 1.")
        values.append(int(token))
    return values


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


def ascii_rate_plot(rates: list[float], width: int = 60, height: int = 10) -> str:
    if not rates:
        return "(no Bernoulli data to plot)"

    sampled = downsample(rates, width)
    plot_width = len(sampled)

    grid = [[" " for _ in range(plot_width)] for _ in range(height)]

    for x, rate in enumerate(sampled):
        y = int(round((1 - rate) * (height - 1)))
        y = max(0, min(height - 1, y))
        grid[y][x] = "*"

    lines: list[str] = []
    for row in range(height):
        label_value = 1 - (row / (height - 1)) if height > 1 else 1.0
        lines.append(f"{label_value:>4.2f} | {''.join(grid[row])}")

    lines.append("     + " + "-" * plot_width)
    lines.append("       trial index ->")
    return "\n".join(lines)


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


def format_bernoulli_report(sequence: list[int]) -> str:
    if not sequence:
        return "Bernoulli Process\n-----------------\nNo Bernoulli sequence provided."

    rates = running_success_rate(sequence)
    success_probability = sum(sequence) / len(sequence)

    head = " ".join(str(v) for v in sequence[:50])
    tail = "" if len(sequence) <= 50 else f" ... ({len(sequence)} trials total)"

    lines = [
        "Bernoulli Process",
        "-----------------",
        f"Trials: {len(sequence)}",
        f"Estimated p(success): {success_probability:.6f}",
        f"Sequence (first 50): {head}{tail}",
        "",
        "Running success-rate plot:",
        ascii_rate_plot(rates),
    ]
    return "\n".join(lines)


class ShannonEntropyApp(App[None]):
    TITLE = "Shannon Entropy + Bernoulli Chart"
    SUB_TITLE = "Textual TUI"

    CSS = """
    Screen {
        align: center middle;
    }

    #main {
        width: 90%;
        height: 90%;
        border: round gray;
        padding: 1 2;
    }

    .block-title {
        margin: 1 0 0 0;
    }

    Input {
        margin: 0 0 1 0;
    }

    #compute {
        margin: 1 0;
        width: 100%;
    }

    #output {
        height: 1fr;
        border: round green;
        padding: 1;
        overflow: auto;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="main"):
            yield Label("Network symbol stream (comma/space-separated)", classes="block-title")
            yield Input(
                value="SYN ACK ACK FIN SYN PSH ACK RST SYN ACK",
                placeholder="Example: SYN ACK ACK FIN",
                id="symbols",
            )

            yield Label("Bernoulli stream (0/1, comma/space-separated)", classes="block-title")
            yield Input(
                value="1 1 0 1 0 0 1 1 1 0 1 0",
                placeholder="Example: 1 0 1 1 0",
                id="bernoulli",
            )

            yield Button("Compute Entropy + Chart", variant="primary", id="compute")
            yield Static("Press the button to calculate.", id="output")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "compute":
            return

        symbols_input = self.query_one("#symbols", Input).value
        bernoulli_input = self.query_one("#bernoulli", Input).value
        output = self.query_one("#output", Static)

        try:
            symbols = parse_symbol_stream(symbols_input)
            entropy_result = compute_shannon_entropy(symbols)

            bernoulli_sequence = parse_bernoulli_stream(bernoulli_input)
            bernoulli_report = format_bernoulli_report(bernoulli_sequence)

            output.update(
                format_entropy_report(entropy_result)
                + "\n\n"
                + bernoulli_report
            )
        except ValueError as exc:
            output.update(f"Input error:\n{exc}")


if __name__ == "__main__":
    ShannonEntropyApp().run()
