from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from math import log2
from typing import Iterable

from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Button, Footer, Header, Input, Label, Static

try:
    from scapy.all import ARP, ICMP, IP, IPv6, TCP, UDP, conf, sniff
except Exception:  # pragma: no cover - import failure is handled at runtime
    ARP = ICMP = IP = IPv6 = TCP = UDP = conf = sniff = None


@dataclass
class EntropyResult:
    symbol_count: int
    sample_count: int
    entropy_bits: float
    max_entropy_bits: float
    normalized_entropy: float
    probabilities: list[tuple[str, float]]


@dataclass
class CaptureResult:
    interface: str
    duration_seconds: float
    symbols: list[str]


def to_bernoulli_from_symbol_stream(symbols: list[str], success_symbol: str) -> list[int]:
    if not symbols:
        return []
    if not success_symbol.strip():
        raise ValueError("Target event symbol cannot be empty.")
    target = success_symbol.strip()
    return [1 if symbol == target else 0 for symbol in symbols]


def detect_default_interface() -> str:
    if conf is None:
        return "unknown"
    return str(conf.iface)


def packet_to_symbol(packet: object) -> str:
    if ARP is not None and packet.haslayer(ARP):
        return "ARP"

    if IP is not None and packet.haslayer(IP):
        if TCP is not None and packet.haslayer(TCP):
            tcp = packet[TCP]
            ports = {int(tcp.sport), int(tcp.dport)}
            if 443 in ports:
                return "TLS/TCP"
            if 80 in ports:
                return "HTTP/TCP"
            return "TCP"
        if UDP is not None and packet.haslayer(UDP):
            udp = packet[UDP]
            ports = {int(udp.sport), int(udp.dport)}
            if 53 in ports:
                return "DNS/UDP"
            if 67 in ports or 68 in ports:
                return "DHCP/UDP"
            return "UDP"
        if ICMP is not None and packet.haslayer(ICMP):
            return "ICMP"
        return "IP-OTHER"

    if IPv6 is not None and packet.haslayer(IPv6):
        return "IPv6"

    return "OTHER"


def capture_network_symbols(duration_seconds: float, interface: str) -> CaptureResult:
    if sniff is None:
        raise RuntimeError(
            "Scapy is unavailable. Install dependencies from requirements.txt first."
        )

    if duration_seconds <= 0:
        raise ValueError("Listening duration must be greater than zero.")

    iface = interface.strip() or detect_default_interface()
    packets = sniff(iface=iface, timeout=duration_seconds, store=True)

    symbols: list[str] = []
    for packet in packets:
        symbols.append(packet_to_symbol(packet))

    return CaptureResult(interface=iface, duration_seconds=duration_seconds, symbols=symbols)


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


def format_capture_report(capture: CaptureResult) -> str:
    return "\n".join(
        [
            "Capture Session",
            "---------------",
            f"Interface: {capture.interface}",
            f"Listening duration: {capture.duration_seconds:.2f} seconds",
            f"Captured packets: {len(capture.symbols)}",
        ]
    )


class ShannonEntropyApp(App[None]):
    TITLE = "Shannon Entropy + Bernoulli Chart"
    SUB_TITLE = "Live Network Listener"

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
            yield Label("Listening duration (seconds)", classes="block-title")
            yield Input(
                value="10",
                placeholder="Example: 10",
                id="duration",
            )

            yield Label("Interface (optional, blank = default active interface)", classes="block-title")
            yield Input(
                value="",
                placeholder=f"Default: {detect_default_interface()}",
                id="interface",
            )

            yield Label("Target event symbol for Bernoulli projection", classes="block-title")
            yield Input(
                value="TCP",
                placeholder="Example: TCP",
                id="target_symbol",
            )

            yield Button("Listen And Analyze", variant="primary", id="compute")
            yield Static("Set duration and press Listen And Analyze.", id="output")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "compute":
            return

        duration_input = self.query_one("#duration", Input).value
        interface_input = self.query_one("#interface", Input).value
        target_symbol = self.query_one("#target_symbol", Input).value
        output = self.query_one("#output", Static)

        try:
            duration_seconds = float(duration_input)
            output.update(
                f"Listening on interface '{interface_input.strip() or detect_default_interface()}' "
                f"for {duration_seconds:.2f} seconds..."
            )

            capture = capture_network_symbols(duration_seconds, interface_input)
            if not capture.symbols:
                raise ValueError(
                    "No packets were captured in the selected duration. "
                    "Increase listening time or generate network activity."
                )

            entropy_result = compute_shannon_entropy(capture.symbols)

            bernoulli_sequence = to_bernoulli_from_symbol_stream(capture.symbols, target_symbol)
            bernoulli_report = format_bernoulli_report(bernoulli_sequence, target_symbol.strip())

            output.update(
                format_capture_report(capture)
                + "\n\n"
                + format_entropy_report(entropy_result)
                + "\n\n"
                + bernoulli_report
            )
        except PermissionError:
            output.update(
                "Capture permission error:\n"
                "Packet sniffing may require elevated privileges. "
                "Run terminal as Administrator and ensure Npcap is installed."
            )
        except OSError as exc:
            output.update(
                "Capture error:\n"
                f"{exc}\n"
                "Check interface name and verify packet capture support is installed."
            )
        except ValueError as exc:
            output.update(f"Input error:\n{exc}")
        except RuntimeError as exc:
            output.update(f"Runtime error:\n{exc}")


if __name__ == "__main__":
    ShannonEntropyApp().run()
