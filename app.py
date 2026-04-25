from __future__ import annotations

from pathlib import Path
from threading import Lock
from time import monotonic
from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
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
    format_investigation_report,
    format_packet_analysis,
    format_refresh_history,
    format_shannon_entropy_timeline,
    format_trends_metrics,
    format_warning_queue,
)
from models import RefreshSnapshot, WarningEvent
from shift_detection import detect_shift


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
    #export_matlab,
    #clear_charts,
    #see_warnings {
        width: 18;
        margin-right: 1;
    }

    #analyzer_output,
    #trends_output,
    #packet_output,
    #investigate_output,
    #warnings_output,
    #about_text {
        height: auto;
        border: round green;
        padding: 1;
        overflow: auto;
    }

    #analyzer_scroll,
    #trends_scroll,
    #packet_scroll,
    #investigate_scroll,
    #warnings_scroll,
    #about_scroll {
        height: 1fr;
        overflow: auto;
    }

    #trends_metrics {
        height: auto;
        border: round cyan;
        padding: 1;
        margin: 0 0 1 0;
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
        self.last_packet_text = ""
        self.last_investigate_text = ""
        self.last_warnings_text = ""
        self.refresh_history: list[RefreshSnapshot] = []
        self.warning_events: list[WarningEvent] = []
        self.last_snapshot_packet_count = 0
        self.warning_cooldown_ticks = 2
        self.last_warning_tick = -9999
        self.consecutive_warning_ticks = 0

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="main"):
            with TabbedContent(initial="analyzer"):
                with TabPane("Analyzer", id="analyzer"):
                    with VerticalScroll(id="analyzer_scroll"):
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
                    with VerticalScroll(id="trends_scroll"):
                        with Horizontal(id="trend_controls"):
                            yield Button("Export CSV", id="export_csv")
                            yield Button("Export MATLAB", id="export_matlab")
                            yield Button("Clear Charts", id="clear_charts")
                        yield Static("Key metrics will appear here.", id="trends_metrics")
                        yield Static(
                            "Binary entropy chart and refresh history will appear here after capture starts.",
                            id="trends_output",
                        )

                with TabPane("Packet Analysis", id="packet_analysis"):
                    with VerticalScroll(id="packet_scroll"):
                        yield Static(
                            "Protocol distribution and mixing metrics will appear here after capture starts.",
                            id="packet_output",
                        )

                with TabPane("Investigate", id="investigate"):
                    with VerticalScroll(id="investigate_scroll"):
                        with Horizontal(id="trend_controls"):
                            yield Button("See Warnings", id="see_warnings")
                        yield Static(
                            "Shift detection alerts and investigation timeline will appear here.",
                            id="investigate_output",
                        )

                with TabPane("Warnings", id="warnings"):
                    with VerticalScroll(id="warnings_scroll"):
                        yield Static(
                            "WARNING/CRITICAL queue appears here.",
                            id="warnings_output",
                        )

                with TabPane("About", id="about"):
                    with VerticalScroll(id="about_scroll"):
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
            return
        if event.button.id == "clear_charts":
            self.clear_charts()
            return
        if event.button.id == "see_warnings":
            tabs = self.query_one(TabbedContent)
            tabs.active = "warnings"

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
            self.last_packet_text = ""
            self.last_investigate_text = ""
            self.last_warnings_text = ""
            self.warning_events = []
            self.last_warning_tick = -9999
            self.consecutive_warning_ticks = 0

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
        packet_output = self.query_one("#packet_output", Static)
        investigate_output = self.query_one("#investigate_output", Static)
        warnings_output = self.query_one("#warnings_output", Static)
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
            packet_output.update(self.last_packet_text + "\n\nCapture stopped by user.")
            investigate_output.update(self.last_investigate_text + "\n\nCapture stopped by user.")
            warnings_output.update(self.last_warnings_text + "\n\nCapture stopped by user.")
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
        status = self.query_one("#status", Label)
        trends_output = self.query_one("#trends_output", Static)
        if not self.refresh_history:
            trends_output.update(self.last_trends_text + "\n\nExport skipped: no refresh history to export.")
            return

        export_dir = Path.cwd() / "exports"
        try:
            output_path = export_refresh_history_csv(self.refresh_history, output_dir=str(export_dir)).resolve()
            trends_output.update(
                self.last_trends_text
                + "\n\nExport complete."
                + f"\nFile: {output_path}"
                + f"\nFolder: {output_path.parent}"
            )
            self.notify_export(output_path)
            status.update("Status: Exported CSV")
        except OSError as exc:
            trends_output.update(self.last_trends_text + f"\n\nExport failed: {exc}")
            self.notify_error(f"Export failed: {exc}")
            status.update("Status: Export error")

    def export_history_matlab(self) -> None:
        status = self.query_one("#status", Label)
        trends_output = self.query_one("#trends_output", Static)
        if not self.refresh_history:
            trends_output.update(self.last_trends_text + "\n\nExport skipped: no refresh history to export.")
            return

        export_dir = Path.cwd() / "exports"
        try:
            output_path = export_refresh_history_matlab_m(self.refresh_history, output_dir=str(export_dir)).resolve()
            trends_output.update(
                self.last_trends_text
                + "\n\nExport complete."
                + f"\nFile: {output_path}"
                + f"\nFolder: {output_path.parent}"
            )
            self.notify_export(output_path)
            status.update("Status: Exported MATLAB")
        except OSError as exc:
            trends_output.update(self.last_trends_text + f"\n\nExport failed: {exc}")
            self.notify_error(f"Export failed: {exc}")
            status.update("Status: Export error")

    def notify_export(self, output_path: Path) -> None:
        message = f"File exported: {output_path}"
        try:
            self.notify(message, title="Export Complete", timeout=6)
        except Exception:
            pass

    def notify_error(self, message: str) -> None:
        try:
            self.notify(message, title="Export Error", severity="error", timeout=8)
        except Exception:
            pass

    def clear_charts(self) -> None:
        trends_metrics = self.query_one("#trends_metrics", Static)
        trends_output = self.query_one("#trends_output", Static)
        status = self.query_one("#status", Label)
        with self.capture_lock:
            current_packet_count = len(self.captured_symbols)

        self.refresh_history = []
        self.last_snapshot_packet_count = current_packet_count
        self.last_trends_text = "Charts and refresh history were cleared."
        trends_metrics.update("Key Metrics\n-----------\nCharts were cleared. Waiting for new refresh data.")
        trends_output.update(self.last_trends_text)

        if self.is_listening:
            status.update("Status: Listening... (charts reset)")
        else:
            status.update("Status: Idle (charts cleared)")

    def refresh_live_report(self) -> None:
        trends_metrics = self.query_one("#trends_metrics", Static)
        analyzer_output = self.query_one("#analyzer_output", Static)
        trends_output = self.query_one("#trends_output", Static)
        packet_output = self.query_one("#packet_output", Static)
        investigate_output = self.query_one("#investigate_output", Static)
        warnings_output = self.query_one("#warnings_output", Static)
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
            packet_text = "No packet analysis yet. Capture is active but no packets have been observed."
            investigate_text = "No investigation data yet. Capture is active but no packets have been observed."
            warnings_text = "Warnings window\n---------------\nNo WARNING/CRITICAL events have been queued."
            self.last_analyzer_text = analyzer_text
            self.last_trends_text = trends_text
            self.last_packet_text = packet_text
            self.last_investigate_text = investigate_text
            self.last_warnings_text = warnings_text
            analyzer_output.update(analyzer_text)
            trends_metrics.update("Key Metrics\n-----------\nAwaiting packets...")
            trends_output.update(trends_text)
            packet_output.update(packet_text)
            investigate_output.update(investigate_text)
            warnings_output.update(warnings_text)
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
        packet_rate = total_packets / elapsed if elapsed > 0 else 0.0
        shift = detect_shift(
            history=self.refresh_history,
            current_shannon_bits=entropy_result.entropy_bits,
            current_packet_rate=packet_rate,
            current_dominant_share=success_probability,
        )

        tick = len(self.refresh_history) + 1
        final_level = shift.level
        final_score = shift.score
        final_reasons = list(shift.reasons)

        if shift.level == "WARNING":
            if tick - self.last_warning_tick <= self.warning_cooldown_ticks:
                self.consecutive_warning_ticks += 1
            else:
                self.consecutive_warning_ticks = 1
            if self.consecutive_warning_ticks >= 3:
                final_level = "CRITICAL"
                final_score = max(final_score, 4.0)
                final_reasons.append("Escalated: repeated WARNING events in short interval")
        elif shift.level == "CRITICAL":
            self.consecutive_warning_ticks += 1
        else:
            self.consecutive_warning_ticks = 0

        self.refresh_history.append(
            RefreshSnapshot(
                tick=tick,
                elapsed_seconds=elapsed,
                total_packets=total_packets,
                new_packets=new_packets,
                dominant_symbol=projection_symbol,
                success_probability=success_probability,
                binary_entropy_bits=binary_entropy_bits,
                shannon_entropy_bits=entropy_result.entropy_bits,
                packet_rate=packet_rate,
                baseline_shannon_bits=shift.baseline_shannon_bits,
                baseline_packet_rate=shift.baseline_packet_rate,
                dominant_share_delta=shift.dominant_share_delta,
                shift_score=final_score,
                alert_level=final_level,
                alert_reasons=final_reasons,
            )
        )

        if final_level in {"WARNING", "CRITICAL"}:
            if (tick - self.last_warning_tick > self.warning_cooldown_ticks) or final_level == "CRITICAL":
                self.warning_events.append(
                    WarningEvent(
                        tick=tick,
                        elapsed_seconds=elapsed,
                        level=final_level,
                        score=final_score,
                        reasons=final_reasons,
                    )
                )
                self.last_warning_tick = tick

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
            + format_binary_entropy_timeline(self.refresh_history)
            + "\n\n"
            + format_refresh_history(self.refresh_history)
            + "\n\n"
            + bernoulli_report
        )

        packet_text = format_packet_analysis(symbols, elapsed)
        investigate_text = format_investigation_report(self.refresh_history)
        warnings_text = format_warning_queue(self.warning_events)

        self.last_analyzer_text = analyzer_text
        self.last_trends_text = trends_text
        self.last_packet_text = packet_text
        self.last_investigate_text = investigate_text
        self.last_warnings_text = warnings_text
        analyzer_output.update(analyzer_text)
        trends_metrics.update(format_trends_metrics(self.refresh_history))
        trends_output.update(trends_text)
        packet_output.update(packet_text)
        investigate_output.update(investigate_text)
        warnings_output.update(warnings_text)

        if self.is_listening:
            status.update("Status: Listening...")
        else:
            status.update("Status: Done")


if __name__ == "__main__":
    ShannonEntropyApp().run()
