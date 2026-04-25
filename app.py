from __future__ import annotations

import importlib
from threading import Lock
from time import monotonic
from collections import Counter
from dataclasses import dataclass
from math import log2
from typing import Any, Iterable

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal
from textual.widgets import Button, Footer, Header, Input, Label, Static, TabbedContent, TabPane

try:
    scapy_all = importlib.import_module("scapy.all")
except Exception:  # pragma: no cover - import failure is handled at runtime
    scapy_all = None

ARP = getattr(scapy_all, "ARP", None)
ICMP = getattr(scapy_all, "ICMP", None)
IP = getattr(scapy_all, "IP", None)
IPv6 = getattr(scapy_all, "IPv6", None)
TCP = getattr(scapy_all, "TCP", None)
UDP = getattr(scapy_all, "UDP", None)
conf = getattr(scapy_all, "conf", None)
sniff = getattr(scapy_all, "sniff", None)
AsyncSniffer = getattr(scapy_all, "AsyncSniffer", None)


@dataclass
class EntropyResult:
    symbol_count: int
    sample_count: int
    entropy_bits: float
    max_entropy_bits: float
    normalized_entropy: float
    probabilities: list[tuple[str, float]]


def to_bernoulli_from_symbol_stream(symbols: list[str], success_symbol: str) -> list[int]:
    if not symbols:
        return []
    if not success_symbol.strip():
        raise ValueError("Target event symbol cannot be empty.")
    target = success_symbol.strip()
    return [1 if symbol == target else 0 for symbol in symbols]


def dominant_symbol(symbols: list[str]) -> str:
    if not symbols:
        raise ValueError("No network symbols were provided.")
    counts = Counter(symbols)
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def detect_default_interface() -> str:
    if conf is None:
        return "unknown"
    return str(conf.iface)


def packet_to_symbol(packet: Any) -> str:
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


def format_entropy_summary(result: EntropyResult) -> str:
    return "\n".join(
        [
            "Entropy Result",
            "--------------",
            f"H(X): {result.entropy_bits:.6f} bits",
            f"Normalized H(X): {result.normalized_entropy:.2%}",
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

    #status {
        margin: 0 0 1 0;
    }

    #controls {
        height: auto;
        width: auto;
        align-horizontal: left;
    }

    #start_capture {
        width: 18;
        margin-right: 1;
    }

    #stop_capture {
        width: 18;
    }

    #output {
        height: 1fr;
        border: round green;
        padding: 1;
        overflow: auto;
    }

    #about_text {
        border: round gray;
        padding: 1;
        height: 1fr;
        overflow: auto;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self.capture_lock = Lock()
        self.captured_symbols: list[str] = []
        self.capture_interface = ""
        self.refresh_seconds = 10.0
        self.capture_started_at = 0.0
        self.is_listening = False
        self.sniffer: Any = None
        self.refresh_timer: Any = None
        self.last_output_text = ""

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="main"):
            with TabbedContent(initial="analyzer"):
                with TabPane("Analyzer", id="analyzer"):
                    yield Label("Refresh duration (seconds)", classes="block-title")
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

                    with Horizontal(id="controls"):
                        yield Button("Start Listening", variant="primary", id="start_capture")
                        yield Button("Stop", variant="warning", id="stop_capture", disabled=True)

                    yield Label("Status: Idle", id="status")
                    yield Static("Press Start Listening to begin live capture and periodic analysis.", id="output")

                with TabPane("About", id="about"):
                    yield Static(
                        "\n".join(
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
                                "",
                                "Packet capture may require Administrator privileges and Npcap on Windows.",
                                "",
                                "[link=\"https://en.wikipedia.org/wiki/Entropy_(information_theory)\"]Shannon entropy on Wikipedia[/link]",
                            ]
                        ),
                        id="about_text",
                    )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start_capture":
            self.start_capture()
            return
        if event.button.id == "stop_capture":
            self.stop_capture(user_requested=True)

    def on_unmount(self) -> None:
        self.stop_capture(user_requested=False)

    def start_capture(self) -> None:
        output = self.query_one("#output", Static)
        status = self.query_one("#status", Label)

        if self.is_listening:
            status.update("Status: Already listening")
            return

        if AsyncSniffer is None:
            status.update("Status: Error")
            output.update(
                "Runtime error:\nScapy AsyncSniffer is unavailable. "
                "Install dependencies from requirements.txt first."
            )
            return

        try:
            duration_input = self.query_one("#duration", Input).value
            interface_input = self.query_one("#interface", Input).value
            duration_seconds = float(duration_input)
            if duration_seconds <= 0:
                raise ValueError("Refresh duration must be greater than zero.")

            iface = interface_input.strip() or detect_default_interface()
            self.refresh_seconds = duration_seconds
            self.capture_interface = iface
            self.capture_started_at = monotonic()
            with self.capture_lock:
                self.captured_symbols = []

            self.sniffer = AsyncSniffer(iface=iface, prn=self._on_packet, store=False)
            self.sniffer.start()
            self.is_listening = True

            self.refresh_timer = self.set_interval(self.refresh_seconds, self.refresh_live_report)
            self.update_control_state()

            status.update("Status: Listening...")
            output.update(
                f"Live capture started on '{iface}'.\n"
                f"Refreshing analysis every {self.refresh_seconds:.2f} seconds."
            )
            self.refresh_live_report()
        except PermissionError:
            status.update("Status: Error")
            output.update(
                "Capture permission error:\n"
                "Packet sniffing may require elevated privileges. "
                "Run terminal as Administrator and ensure Npcap is installed."
            )
        except OSError as exc:
            status.update("Status: Error")
            output.update(
                "Capture error:\n"
                f"{exc}\n"
                "Check interface name and verify packet capture support is installed."
            )
        except ValueError as exc:
            status.update("Status: Error")
            output.update(f"Input error:\n{exc}")

    def stop_capture(self, user_requested: bool) -> None:
        if not self.is_listening and not self.sniffer:
            return

        output = self.query_one("#output", Static)
        status = self.query_one("#status", Label)

        if self.refresh_timer is not None:
            self.refresh_timer.stop()
            self.refresh_timer = None

        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None

        self.is_listening = False
        self.update_control_state()
        self.refresh_live_report()

        if user_requested:
            status.update("Status: Stopped")
            output.update(self.last_output_text + "\n\nCapture stopped by user.")
        else:
            status.update("Status: Idle")

    def update_control_state(self) -> None:
        start_btn = self.query_one("#start_capture", Button)
        stop_btn = self.query_one("#stop_capture", Button)
        start_btn.disabled = self.is_listening
        stop_btn.disabled = not self.is_listening

    def _on_packet(self, packet: Any) -> None:
        symbol = packet_to_symbol(packet)
        with self.capture_lock:
            self.captured_symbols.append(symbol)

    def refresh_live_report(self) -> None:
        output = self.query_one("#output", Static)
        status = self.query_one("#status", Label)

        with self.capture_lock:
            symbols = list(self.captured_symbols)

        elapsed = max(0.0, monotonic() - self.capture_started_at) if self.capture_started_at else 0.0

        if not symbols:
            report_text = (
                format_capture_report(
                    self.capture_interface or detect_default_interface(),
                    elapsed,
                    self.refresh_seconds,
                    0,
                )
                + "\n\nAwaiting packets. Generate network activity or wait for next refresh."
            )
            self.last_output_text = report_text
            output.update(report_text)
            if self.is_listening:
                status.update("Status: Listening...")
            return

        entropy_result = compute_shannon_entropy(symbols)
        projection_symbol = dominant_symbol(symbols)
        bernoulli_sequence = to_bernoulli_from_symbol_stream(symbols, projection_symbol)
        bernoulli_report = format_bernoulli_report(bernoulli_sequence, projection_symbol)

        report_text = (
            format_entropy_summary(entropy_result)
            + "\n\n"
            + format_capture_report(
                self.capture_interface or detect_default_interface(),
                elapsed,
                self.refresh_seconds,
                len(symbols),
            )
            + "\n\n"
            + format_entropy_report(entropy_result)
            + "\n\n"
            + bernoulli_report
        )
        self.last_output_text = report_text
        output.update(report_text)

        if self.is_listening:
            status.update("Status: Listening...")
        else:
            status.update("Status: Done")


if __name__ == "__main__":
    ShannonEntropyApp().run()
