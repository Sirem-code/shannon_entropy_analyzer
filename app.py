from __future__ import annotations

from pathlib import Path
from threading import Lock
from time import monotonic
from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Button, Footer, Header, Input, Label, Static, TabbedContent, TabPane, DataTable, Collapsible, Switch, Select, RadioSet, RadioButton

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


class ProtocolLog(Static):
    """A widget that shows a rolling log of captured protocols."""
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.log_items: list[str] = []

    def add_protocol(self, protocol: str) -> None:
        self.log_items.append(protocol)
        if len(self.log_items) > 20:
            self.log_items.pop(0)
        self.update("\n".join(f"[dim]>[/] {p}" for p in reversed(self.log_items)))

class ActivityMeter(Static):
    """A widget that shows packet signal intensity."""

    def on_mount(self) -> None:
        self.intensity = 0.0
        self.set_interval(0.1, self.decay)

    def pulse(self) -> None:
        self.intensity = 1.0
        self.render_meter()

    def decay(self) -> None:
        if self.intensity > 0:
            self.intensity = max(0.0, self.intensity - 0.2)
            self.render_meter()

    def render_meter(self) -> None:
        bar_len = int(self.intensity * 20)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        self.update(f"[#00e5ff]{bar}[/]")


class ShannonEntropyApp(App[None]):
    """A Shannon Entropy calculator for network traffic."""

    BINDINGS = [
        ("ctrl+q", "quit", "Quit"),
        ("ctrl+a", "toggle_analyze", "Analyze"),
        ("ctrl+e", "export_csv", "Export CSV"),
        ("ctrl+m", "export_matlab", "Export MATLAB"),
        ("f1", "show_about", "About"),
    ]
    TITLE = "Shannon Entropy Analyzer"
    SUB_TITLE = "Advanced Network Diagnostics"

    CSS = """
    $background: #0a0c10;
    $surface: #161b22;
    $surface-lighten-1: #21262d;
    $primary: #00e5ff;
    $primary-light: #b8ffff;
    $primary-dark: #00b2cc;
    $secondary: #ffab00;
    $error: #ff5252;
    $success: #00e676;
    $border: #333333;
    $text: #eceff1;
    $text-muted: #90a4ae;

    Screen {
        background: $background;
        color: $text;
        align: center middle;
    }

    #main {
        width: 100%;
        height: 100%;
        padding: 1 2;
    }

    Tabs {
        background: $surface;
        color: $primary;
        text-style: bold;
    }

    /* Target both Tab and ContentTab for compatibility */
    Tab, ContentTab {
        color: $primary;
    }

    Tab:hover, ContentTab:hover {
        color: $primary-light;
        background: $surface-lighten-1;
    }

    /* The active state often uses --active or -active */
    Tab.--active, Tab.-active, ContentTab.-active, ContentTab.--active {
        color: #ffffff !important;
        background: $surface !important;
        text-style: bold;
    }

    /* Style the animated underline to match the primary color */
    Underline > .underline--bar {
        color: $primary !important;
        background: $primary 20% !important;
    }

    /* Specifically target the Analyzer tab by its generated ID */
    #--content-tab-analyzer {
        color: $primary;
    }

    #--content-tab-analyzer.--active, #--content-tab-analyzer.-active {
        color: #ffffff !important;
    }

    TabbedContent {
        height: 1fr;
    }

    TabPane {
        padding: 1 2;
    }

    #status {
        color: $primary;
        text-style: bold;
        margin-top: 1;
    }

    .block-title {
        color: $primary;
        text-style: bold;
        margin: 1 0 0 0;
    }

    Input {
        background: $surface;
        border: tall $border;
        color: $text;
        margin: 0 0 1 0;
        padding: 0 1;
    }

    Input:focus {
        border: tall $primary;
    }

    #status {
        margin: 1 0;
        padding: 0 1;
        background: $surface;
        color: $primary;
        text-style: bold;
        border-left: tall $primary;
    }

    #controls {
        height: auto;
        width: 100%;
        margin: 1 0;
    }

    Button {
        width: 20;
        margin-right: 1;
        border: none;
        text-style: bold;
        background: $surface;
        color: $text;
    }

    #start_capture.btn-start {
        background: $success;
        color: #000000;
    }

    #start_capture.btn-start:hover {
        background: #69f0ae;
    }

    #start_capture.btn-stop {
        background: $error;
        color: #ffffff;
    }

    #start_capture.btn-stop:hover {
        background: #ff8a80;
    }

    #trend_controls {
        height: auto;
        width: 100%;
        margin: 0 0 1 0;
    }

    #analyzer_output,
    #trends_output,
    #packet_output,
    #investigate_output,
    #warnings_output,
    #about_text {
        height: auto;
        background: $surface;
        border: solid $border;
        padding: 1;
        margin-top: 1;
    }

    #analyzer_scroll,
    #trends_scroll,
    #packet_scroll,
    #investigate_scroll,
    #warnings_scroll,
    #about_scroll {
        height: 1fr;
    }

    #trends_metrics {
        height: auto;
        background: $surface;
        border-left: tall $primary;
        padding: 1;
        margin: 0 0 1 0;
        color: $primary;
    }

    ActivityMeter {
        width: 100%;
        height: 1;
        margin: 1 0;
    }

    .activity-label {
        color: $text-muted;
        margin-bottom: 0;
    }

    #packet_counter {
        color: $success;
        text-style: bold;
    }
    #protocol_log {
        height: 10;
        background: $surface;
        border: solid $border;
        padding: 0 1;
        margin-top: 1;
        color: $primary-light;
        overflow: hidden;
    }

    .config-row {
        height: auto;
        margin-bottom: 1;
        align: left middle;
    }

    .config-label {
        width: 14;
        color: $text-muted;
    }

    #filter {
        width: 35;
        margin-right: 2;
    }

    #filter_preset {
        width: 25;
    }

    #duration_select {
        layout: vertical;
        height: auto;
        width: 20;
        border: solid $border;
        background: $surface;
        padding: 0 1;
        margin-left: 1;
    }

    #duration {
        width: 10;
    }

    #interval_mode {
        margin-right: 2;
    }

    .hidden {
        display: none;
    }

    .rule-label {
        width: 28;
        color: $text-muted;
    }

    .rule-input {
        width: 15;
    }

    .block-title {
        color: $secondary;
        text-style: bold;
        margin: 1 0;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self.capture_lock = Lock()
        self.captured_symbols: list[str] = []
        self.capture_interface = ""
        self.capture_filter = ""
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
        self.total_packets_count = 0

    def on_mount(self) -> None:
        self.query_one(TabbedContent).hide_tab("warnings")

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="main"):
            with TabbedContent(initial="analyzer"):
                with TabPane("Analyzer", id="analyzer"):
                    with VerticalScroll(id="analyzer_scroll"):
                        with Horizontal(classes="config-row"):
                            yield Label("BPF Filter:", classes="config-label")
                            yield Input(value="", placeholder="e.g. tcp, udp, icmp", id="filter")
                            yield Label("Presets:", classes="config-label")
                            yield Select(
                                [
                                    ("All Traffic", ""),
                                    ("TCP Only", "tcp"),
                                    ("UDP Only", "udp"),
                                    ("Web (80/443)", "tcp port 80 or tcp port 443"),
                                    ("DNS (53)", "port 53"),
                                    ("ICMP", "icmp"),
                                    ("ARP", "arp"),
                                ],
                                id="filter_preset",
                                prompt="Choose Preset..."
                            )
                        
                        with Horizontal(classes="config-row"):
                            yield Label("Interval Mode:", classes="config-label")
                            yield Switch(id="interval_mode", value=False)
                            yield Label("Speed:", id="duration_label", classes="config-label hidden")
                            with RadioSet(id="duration_select", classes="hidden"):
                                yield RadioButton("Slow (10s)", id="speed_10")
                                yield RadioButton("Mid (5s)", id="speed_5", value=True)
                                yield RadioButton("Fast (2s)", id="speed_2")

                        with Horizontal(id="controls"):
                            yield Button("Start Listening", variant="primary", id="start_capture", classes="btn-start")

                        yield Label("Packet Activity", classes="activity-label")
                        yield ActivityMeter(id="activity_meter")
                        yield Label("Live Counter: [b]0[/b] packets captured", id="packet_counter")

                        yield Label("Live Protocol Log (last 20)", classes="activity-label")
                        yield ProtocolLog(id="protocol_log")

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
                        with Collapsible(title="Refresh History DataTable", collapsed=False):
                            yield DataTable(id="history_table")
                        yield Static(
                            "Visual charts will appear here.",
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
                        with Horizontal(id="trend_controls"):
                            yield Button("Back", id="back_to_investigate")
                        yield Static(
                            "WARNING/CRITICAL queue appears here.",
                            id="warnings_output",
                        )

                with TabPane("Alert Rules", id="alert_rules"):
                    with VerticalScroll(id="rules_scroll"):
                        yield Label("Base Shift Detection Thresholds", classes="block-title")
                        with Horizontal(classes="config-row"):
                            yield Label("Entropy Drop Tolerance:", classes="rule-label")
                            yield Input(value="0.7", id="rule_shannon_drop", classes="rule-input")
                        with Horizontal(classes="config-row"):
                            yield Label("Dominant Share Delta:", classes="rule-label")
                            yield Input(value="0.15", id="rule_dominant_share", classes="rule-input")
                        with Horizontal(classes="config-row"):
                            yield Label("Packet Rate Multiplier:", classes="rule-label")
                            yield Input(value="2.0", id="rule_packet_rate", classes="rule-input")
                        
                        yield Label("Compound Heuristic Multipliers", classes="block-title")
                        with Horizontal(classes="config-row"):
                            yield Label("Flood Packet Rate Mul:", classes="rule-label")
                            yield Input(value="3.0", id="rule_flood_rate", classes="rule-input")
                        with Horizontal(classes="config-row"):
                            yield Label("Flood Entropy Ceiling:", classes="rule-label")
                            yield Input(value="1.0", id="rule_flood_entropy", classes="rule-input")
                        with Horizontal(classes="config-row"):
                            yield Label("Scan Entropy Floor:", classes="rule-label")
                            yield Input(value="3.0", id="rule_scan_entropy", classes="rule-input")

                with TabPane("About", id="about"):
                    with VerticalScroll(id="about_scroll"):
                        yield Static(about_text(), id="about_text")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start_capture":
            if self.is_listening:
                self.stop_capture(user_requested=True)
            else:
                self.start_capture()
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
            return
        if event.button.id == "back_to_investigate":
            tabs = self.query_one(TabbedContent)
            tabs.active = "investigate"
            return

    def action_toggle_analyze(self) -> None:
        if self.is_listening:
            self.stop_capture(user_requested=True)
        else:
            self.query_one(TabbedContent).active = "analyzer"
            self.start_capture()

    def action_export_csv(self) -> None:
        self.export_history_csv()

    def action_export_matlab(self) -> None:
        self.export_history_matlab()

    def action_show_about(self) -> None:
        self.query_one(TabbedContent).active = "about"

    def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id == "interval_mode":
            is_active = event.value
            self.query_one("#duration_label").set_class(not is_active, "hidden")
            self.query_one("#duration_select").set_class(not is_active, "hidden")

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "filter_preset" and event.value is not Select.BLANK:
            self.query_one("#filter", Input).value = str(event.value)

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
            filter_input = self.query_one("#filter", Input).value
            interval_mode = self.query_one("#interval_mode", Switch).value
            
            if interval_mode:
                duration_select = self.query_one("#duration_select", RadioSet)
                pressed = duration_select.pressed_button
                if pressed is None or pressed.id == "speed_5":
                    duration_seconds = 5.0
                elif pressed.id == "speed_10":
                    duration_seconds = 10.0
                else:
                    duration_seconds = 2.0
            else:
                # "Live" mode: High-frequency refresh
                duration_seconds = 0.2

            iface = None # Hardcoded to Auto for stability
            bpf_filter = filter_input.strip() or None

            self.refresh_seconds = duration_seconds
            self.capture_interface = "Default (Auto)"
            self.capture_filter = bpf_filter or "all traffic"
            self.capture_started_at = monotonic()

            # Initialize DataTable
            table = self.query_one("#history_table", DataTable)
            table.clear(columns=True)
            table.add_columns("Tick", "Time", "Total", "+New", "Dominant", "p(s)", "H(X)")
            
            with self.capture_lock:
                self.captured_symbols = []
                self.total_packets_count = 0

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

            self.sniffer = AsyncSniffer(iface=iface, filter=bpf_filter, prn=self._on_packet, store=False)
            self.sniffer.start()
            self.is_listening = True

            self.refresh_timer = self.set_interval(self.refresh_seconds, self.refresh_live_report)
            self.update_control_state()

            status.update("Status: Listening...")
            analyzer_output.update(
                f"Live capture started on [b]{iface}[/b].\n"
                f"Filter: [b]{self.capture_filter}[/b]\n"
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
        if self.is_listening:
            start_btn.label = "Stop"
            start_btn.remove_class("btn-start")
            start_btn.add_class("btn-stop")
        else:
            start_btn.label = "Start Listening"
            start_btn.remove_class("btn-stop")
            start_btn.add_class("btn-start")

    def _on_packet(self, packet: Any) -> None:
        symbol = packet_to_symbol(packet)
        with self.capture_lock:
            self.captured_symbols.append(symbol)
            self.total_packets_count += 1
            count = self.total_packets_count
        
        # Update live counter, activity meter, and protocol log
        self.call_from_thread(self._update_live_ui, count, symbol)

    def _update_live_ui(self, count: int, protocol: str) -> None:
        try:
            counter = self.query_one("#packet_counter", Label)
            counter.update(f"Live Counter: [b]{count}[/b] packets captured")
            
            meter = self.query_one("#activity_meter", ActivityMeter)
            meter.pulse()

            log = self.query_one("#protocol_log", ProtocolLog)
            log.add_protocol(protocol)
        except Exception:
            pass

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
        self.known_protocols = set()
        self.last_trends_text = "Charts and refresh history were cleared."
        trends_metrics.update("Key Metrics\n-----------\nCharts were cleared. Waiting for new refresh data.")
        trends_output.update(self.last_trends_text)

        if self.is_listening:
            status.update("Status: Listening... (charts reset)")
        else:
            status.update("Status: Idle (charts cleared)")

    def get_float_input(self, input_id: str, default: float) -> float:
        try:
            return float(self.query_one(f"#{input_id}", Input).value)
        except Exception:
            return default

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

        current_protocols = set(symbols)
        if not hasattr(self, 'known_protocols'):
            self.known_protocols = set(symbols)
        
        new_protocols = current_protocols - self.known_protocols
        self.known_protocols.update(new_protocols)

        shift = detect_shift(
            history=self.refresh_history,
            current_shannon_bits=entropy_result.entropy_bits,
            current_packet_rate=packet_rate,
            current_dominant_share=success_probability,
            new_protocols=new_protocols,
            shannon_drop_tolerance=self.get_float_input("rule_shannon_drop", 0.7),
            dominant_share_tolerance=self.get_float_input("rule_dominant_share", 0.15),
            packet_rate_multiplier=self.get_float_input("rule_packet_rate", 2.0),
            flood_packet_rate_multiplier=self.get_float_input("rule_flood_rate", 3.0),
            flood_entropy_ceiling=self.get_float_input("rule_flood_entropy", 1.0),
            scan_entropy_floor=self.get_float_input("rule_scan_entropy", 3.0),
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
            + f"\nFilter: [b]{self.capture_filter}[/b]"
            + "\n\n"
            + format_entropy_report(entropy_result)
        )

        trends_text = (
            format_shannon_entropy_timeline(self.refresh_history)
            + "\n\n"
            + format_binary_entropy_timeline(self.refresh_history)
        )

        # Update DataTable
        table = self.query_one("#history_table", DataTable)
        last = self.refresh_history[-1]
        table.add_row(
            str(last.tick),
            f"{last.elapsed_seconds:.1f}s",
            str(last.total_packets),
            str(last.new_packets),
            last.dominant_symbol,
            f"{last.success_probability:.4f}",
            f"{last.shannon_entropy_bits:.2f}"
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
