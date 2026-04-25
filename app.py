from __future__ import annotations

from pathlib import Path
from threading import Lock
from time import monotonic
from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal
from textual.widgets import Button, Footer, Header, Input, Label, Static, TabbedContent, TabPane

from analysis import binary_entropy, compute_shannon_entropy, dominant_symbol, to_bernoulli_from_symbol_stream
from capture import AsyncSniffer, detect_default_interface, packet_to_symbol
from exporters import export_refresh_history_csv, export_refresh_history_matlab_m
from formatters import (
    about_text,
    format_bernoulli_report,
    format_binary_entropy_timeline,
    format_capture_report,
    format_entropy_report,
    format_entropy_summary,
    format_refresh_history,
    format_shannon_entropy_timeline,
)
from models import RefreshSnapshot


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

    #trend_controls {
        height: auto;
        width: auto;
        align-horizontal: left;
        margin: 0 0 1 0;
    }

    #export_csv,
    #export_matlab {
        width: 18;
        margin-right: 1;
    }

    #analyzer_output,
    #trends_output,
    #about_text {
        height: 1fr;
        border: round green;
        padding: 1;
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
        self.last_analyzer_text = ""
        self.last_trends_text = ""
        self.refresh_history: list[RefreshSnapshot] = []
        self.last_snapshot_packet_count = 0

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="main"):
            with TabbedContent(initial="analyzer"):
                with TabPane("Analyzer", id="analyzer"):
                    yield Label("Refresh duration (seconds)", classes="block-title")
                    yield Input(value="10", placeholder="Example: 10", id="duration")

                    yield Label("Interface (optional, blank = default active interface)", classes="block-title")
                    yield Input(value="", placeholder=f"Default: {detect_default_interface()}", id="interface")

                    with Horizontal(id="controls"):
                        yield Button("Start Listening", variant="primary", id="start_capture")
                        yield Button("Stop", variant="warning", id="stop_capture", disabled=True)

                    yield Label("Status: Idle", id="status")
                    yield Static(
                        "Press Start Listening to begin live capture and periodic analysis.",
                        id="analyzer_output",
                    )

                with TabPane("Trends", id="trends"):
                    with Horizontal(id="trend_controls"):
                        yield Button("Export CSV", id="export_csv")
                        yield Button("Export MATLAB", id="export_matlab")
                    yield Static(
                        "Binary entropy chart and refresh history will appear here after capture starts.",
                        id="trends_output",
                    )

                with TabPane("About", id="about"):
                    yield Static(about_text(), id="about_text")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start_capture":
            self.start_capture()
            return
        if event.button.id == "stop_capture":
            self.stop_capture(user_requested=True)
            return
        if event.button.id == "export_csv":
            self.export_history_csv()
            return
        if event.button.id == "export_matlab":
            self.export_history_matlab()

    def on_unmount(self) -> None:
        self.stop_capture(user_requested=False)

    def start_capture(self) -> None:
        analyzer_output = self.query_one("#analyzer_output", Static)
        status = self.query_one("#status", Label)

        if self.is_listening:
            status.update("Status: Already listening")
            return

        if AsyncSniffer is None:
            status.update("Status: Error")
            analyzer_output.update(
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

            self.refresh_history = []
            self.last_snapshot_packet_count = 0
            self.last_analyzer_text = ""
            self.last_trends_text = ""

            self.sniffer = AsyncSniffer(iface=iface, prn=self._on_packet, store=False)
            self.sniffer.start()
            self.is_listening = True

            self.refresh_timer = self.set_interval(self.refresh_seconds, self.refresh_live_report)
            self.update_control_state()

            status.update("Status: Listening...")
            analyzer_output.update(
                f"Live capture started on '{iface}'.\n"
                f"Refreshing analysis every {self.refresh_seconds:.2f} seconds."
            )
            self.refresh_live_report()
        except PermissionError:
            status.update("Status: Error")
            analyzer_output.update(
                "Capture permission error:\n"
                "Packet sniffing may require elevated privileges. "
                "Run terminal as Administrator and ensure Npcap is installed."
            )
        except OSError as exc:
            status.update("Status: Error")
            analyzer_output.update(
                "Capture error:\n"
                f"{exc}\n"
                "Check interface name and verify packet capture support is installed."
            )
        except ValueError as exc:
            status.update("Status: Error")
            analyzer_output.update(f"Input error:\n{exc}")

    def stop_capture(self, user_requested: bool) -> None:
        if not self.is_listening and not self.sniffer:
            return

        analyzer_output = self.query_one("#analyzer_output", Static)
        trends_output = self.query_one("#trends_output", Static)
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
            analyzer_output.update(self.last_analyzer_text + "\n\nCapture stopped by user.")
            trends_output.update(self.last_trends_text + "\n\nCapture stopped by user.")
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

    def export_history_csv(self) -> None:
        trends_output = self.query_one("#trends_output", Static)
        if not self.refresh_history:
            trends_output.update(self.last_trends_text + "\n\nExport skipped: no refresh history to export.")
            return

        output_path = export_refresh_history_csv(self.refresh_history, output_dir=str(Path.cwd()))
        trends_output.update(self.last_trends_text + f"\n\nExported CSV: {output_path}")

    def export_history_matlab(self) -> None:
        trends_output = self.query_one("#trends_output", Static)
        if not self.refresh_history:
            trends_output.update(self.last_trends_text + "\n\nExport skipped: no refresh history to export.")
            return

        output_path = export_refresh_history_matlab_m(self.refresh_history, output_dir=str(Path.cwd()))
        trends_output.update(self.last_trends_text + f"\n\nExported MATLAB .m: {output_path}")

    def refresh_live_report(self) -> None:
        analyzer_output = self.query_one("#analyzer_output", Static)
        trends_output = self.query_one("#trends_output", Static)
        status = self.query_one("#status", Label)

        with self.capture_lock:
            symbols = list(self.captured_symbols)

        elapsed = max(0.0, monotonic() - self.capture_started_at) if self.capture_started_at else 0.0
        interface = self.capture_interface or detect_default_interface()

        if not symbols:
            analyzer_text = (
                format_capture_report(interface, elapsed, self.refresh_seconds, 0)
                + "\n\nAwaiting packets. Generate network activity or wait for next refresh."
            )
            trends_text = "No trend data yet. Capture is active but no packets have been observed."
            self.last_analyzer_text = analyzer_text
            self.last_trends_text = trends_text
            analyzer_output.update(analyzer_text)
            trends_output.update(trends_text)
            if self.is_listening:
                status.update("Status: Listening...")
            return

        entropy_result = compute_shannon_entropy(symbols)
        projection_symbol = dominant_symbol(symbols)
        bernoulli_sequence = to_bernoulli_from_symbol_stream(symbols, projection_symbol)
        bernoulli_report = format_bernoulli_report(bernoulli_sequence, projection_symbol)

        success_probability = sum(bernoulli_sequence) / len(bernoulli_sequence)
        binary_entropy_bits = binary_entropy(success_probability)
        total_packets = len(symbols)
        new_packets = max(0, total_packets - self.last_snapshot_packet_count)
        self.last_snapshot_packet_count = total_packets

        self.refresh_history.append(
            RefreshSnapshot(
                tick=len(self.refresh_history) + 1,
                elapsed_seconds=elapsed,
                total_packets=total_packets,
                new_packets=new_packets,
                dominant_symbol=projection_symbol,
                success_probability=success_probability,
                binary_entropy_bits=binary_entropy_bits,
                shannon_entropy_bits=entropy_result.entropy_bits,
            )
        )

        analyzer_text = (
            format_entropy_summary(entropy_result)
            + "\n\n"
            + format_capture_report(interface, elapsed, self.refresh_seconds, total_packets)
            + "\n\n"
            + format_entropy_report(entropy_result)
        )

        trends_text = (
            format_shannon_entropy_timeline(self.refresh_history)
            + "\n\n"
            format_binary_entropy_timeline(self.refresh_history)
            + "\n\n"
            + format_refresh_history(self.refresh_history)
            + "\n\n"
            + bernoulli_report
        )

        self.last_analyzer_text = analyzer_text
        self.last_trends_text = trends_text
        analyzer_output.update(analyzer_text)
        trends_output.update(trends_text)

        if self.is_listening:
            status.update("Status: Listening...")
        else:
            status.update("Status: Done")


if __name__ == "__main__":
    ShannonEntropyApp().run()
