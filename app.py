from __future__ import annotations
"""
# Application: Terminal User Interface and Orchestration

This module is the **orchestration layer** that ties all other modules together
into a live, interactive terminal application. It is built with
[Textual](https://textual.textualize.io/), a modern Python framework for
building rich terminal user interfaces.

## Architecture: How the TUI Works

### The Textual Framework
Textual provides a widget-based UI system similar to web frameworks. Key concepts:

- **App**: The root application class (`ShannonEntropyApp`) that manages the
  entire lifecycle
- **Widgets**: Reusable UI components (buttons, labels, tabs, inputs)
- **CSS**: Textual uses a CSS-like styling system for layout and theming
- **Events**: User interactions (clicks, key presses) are handled via event methods
- **Compose**: The `compose()` method defines the widget tree (similar to HTML)

### Threading Model
Network packet capture runs in a **background thread** managed by Scapy's
`AsyncSniffer`. This is critical because:

1. The TUI runs on the **main thread** (Textual's event loop)
2. Packet capture is **blocking I/O** and must run in a separate thread.
3. A `threading.Lock` protects the shared `captured_symbols` list from
   race conditions when both threads access it simultaneously
4. `call_from_thread()` is used to safely update UI widgets from the
   capture thread

### The Refresh Cycle
The app runs on a configurable timer (0.2s to 10s per tick):

```
Timer fires → Lock packet buffer → Snapshot current symbols
    → compute_shannon_entropy()    → EntropyResult
    → binary_entropy()             → Hb(p)
    → detect_shift()               → ShiftAssessment
    → Create RefreshSnapshot       → Append to history
    → Format all panels            → Update UI widgets
    → (If alert) Create WarningEvent
```

## UI Structure (Tab Layout)

| Tab               | Purpose                                            |
|-------------------|----------------------------------------------------|
| **Analyzer**      | Main control panel: BPF filter, start/stop, live log |
| **Trends**        | Time-series charts for entropy, binary entropy, rates |
| **Packet Analysis** | Protocol distribution table and diversity metrics |
| **Investigate**   | Shift detection alerts and baseline comparisons    |
| **Warnings**      | Queue of WARNING/CRITICAL events                   |
| **Alert Rules**   | Configure detection thresholds in real-time        |
| **About**         | Application credits and feature summary            |

## Custom Widgets

- `ProtocolLog`: A rolling log that shows the last 20 captured protocol symbols
- `ActivityMeter`: A visual pulse bar that lights up when packets arrive

## Key Bindings

| Shortcut   | Action                  |
|------------|-------------------------|
| `Ctrl+Q`   | Quit the application    |
| `Ctrl+A`   | Toggle capture on/off   |
| `Ctrl+E`   | Export data as CSV       |
| `Ctrl+M`   | Export data as MATLAB    |
| `F1`       | Show the About tab       |
"""

from collections import deque
from pathlib import Path
from threading import Lock
import time
from time import monotonic
from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Footer, Header, Input, Label, Static, TabbedContent, TabPane, DataTable, Collapsible, Switch, Select, RadioSet, RadioButton

from analysis import binary_entropy, compute_shannon_entropy, dominant_symbol, to_bernoulli_from_symbol_stream
from capture import AsyncSniffer, detect_default_interface, packet_to_symbol, packet_to_summary
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
    format_protocol_bars,
    format_entropy_meter,
    format_refresh_history,
    format_shannon_entropy_timeline,
    format_trends_metrics,
    format_warning_queue,
)

from models import RefreshSnapshot, WarningEvent, PacketSummary
from shift_detection import detect_shift

from threats import ThreatScanner, format_threat_summary
from lookup import lookup_ip, IPLookupResult
from textual.screen import ModalScreen





class IPLookupScreen(ModalScreen):
    """A modal screen that displays IP geolocation information."""

    def __init__(self, ip: str) -> None:
        super().__init__()
        self.ip = ip

    def compose(self) -> ComposeResult:
        with Vertical(id="lookup_modal"):
            yield Label(f"IP Lookup: {self.ip}", id="lookup_title")
            yield Static("Fetching data...", id="lookup_status")
            yield Static("", id="lookup_results")
            yield Button("Close", id="close_lookup", variant="primary")

    def on_mount(self) -> None:
        self.run_worker(self.perform_lookup, thread=True)

    def perform_lookup(self) -> None:
        result = lookup_ip(self.ip)
        self.app.call_from_thread(self.update_results, result)

    def update_results(self, result: IPLookupResult) -> None:
        if result.status == "success":
            self.query_one("#lookup_status").update("[green]Success[/]")
            report = (
                f"[b]Hostname:[/b] {result.hostname}\n"
                f"[b]Location:[/b] {result.city}, {result.region_name}, {result.country} ({result.zip})\n"
                f"[b]ISP:[/b]      {result.isp}\n"
                f"[b]Org:[/b]      {result.org}\n"
                f"[b]AS:[/b]       {result.as_name}"
            )
            self.query_one("#lookup_results").update(report)
        else:
            self.query_one("#lookup_status").update(f"[red]Failed: {result.message}[/]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close_lookup":
            self.dismiss()


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
    $background: #0d1117;
    $surface: #161b22;
    $surface-lighten-1: #21262d;
    $primary: #58a6ff;
    $primary-light: #79c0ff;
    $primary-dark: #1f6feb;
    $secondary: #d29922;
    $error: #f85149;
    $success: #3fb950;
    $border: #30363d;
    $text: #c9d1d9;
    $text-muted: #8b949e;

    Screen {
        background: $background;
        color: $text;
    }

    #main {
        width: 100%;
        height: 100%;
        padding: 0;
    }

    Header {
        background: $surface;
        color: $primary;
        text-style: bold;
        border-bottom: solid $border;
    }

    Footer {
        background: $surface;
    }

    Tabs {
        background: $surface;
        border-bottom: solid $border;
        height: 3;
    }

    Tab, ContentTab {
        color: $text-muted;
        padding: 0 2;
    }

    Tab:hover, ContentTab:hover {
        color: $text;
        background: $surface-lighten-1;
    }

    Tab.--active, Tab.-active, ContentTab.-active, ContentTab.--active {
        color: $primary !important;
        background: $background !important;
        text-style: bold;
    }

    TabPane {
        padding: 0;
        height: 1fr;
    }

    TabbedContent {
        height: 1fr;
    }

    .dashboard-container {
        height: 1fr;
    }


    .sidebar {
        width: 32;
        height: 100%;
        background: $surface;
        border-right: solid $border;
        padding: 1;
    }

    .main-panel {
        width: 1fr;
        height: 100%;
        padding: 1;
    }

    .section-title {
        color: $primary-light;
        text-style: bold;
        margin-top: 1;
        margin-bottom: 1;
    }


    .card {
        background: $background;
        border: solid $border;
        padding: 0 1;
        margin-bottom: 1;
        height: auto;
    }

    .compact-row {
        height: auto;
        margin-bottom: 1;
        align: left middle;
    }

    .label-muted {
        color: $text-muted;
        width: 1fr;
    }

    Input {
        background: $surface;
        border: solid $border;
        color: $text;
        height: 3;
        margin-bottom: 1;
    }

    Input:focus {
        border: solid $primary;
    }

    Select {
        background: $surface;
        border: solid $border;
        height: 3;
        margin-bottom: 1;
    }

    Button {
        width: 100%;
        height: 3;
        border: round $primary;
        background: rgba(88, 166, 255, 0.1);
        color: $text;
        margin-bottom: 1;
        text-style: bold;
    }

    Button:hover {
        background: rgba(88, 166, 255, 0.2);
        border: round $primary-light;
        color: $primary-light;
    }

    .btn-small {
        width: 20;
        height: 3;
        margin-bottom: 1;
    }

    #start_capture.btn-start {
        background: rgba(63, 185, 80, 0.1);
        color: $success;
        border: round $success;
    }
    #start_capture.btn-stop {
        background: rgba(248, 81, 73, 0.1);
        color: $error;
        border: round $error;
    }



    #status {
        color: $secondary;
        text-style: italic;
        margin-top: 1;
    }

    #packet_counter {
        color: $success;
        text-style: bold;
        margin-bottom: 1;
    }

    ActivityMeter {
        width: 100%;
        height: 1;
        margin-bottom: 1;
    }

    #protocol_log {
        height: 10;
        background: $background;
        border: solid $border;
        padding: 0 1;
        color: $primary-light;
    }


    .scroll-box {
        height: 1fr;
        overflow-y: scroll;
    }

    #analyzer_output, #trends_output, #packet_output, #investigate_output, #warnings_output {
        background: $surface;
        border: solid $border;
        padding: 1;
        margin-top: 1;
        height: auto;
        min-height: 5;
    }


    #duration_container {
        border: solid $border;
        background: $surface-lighten-1;
        padding: 0 1;
        margin-bottom: 1;
        height: auto;
    }

    .hidden {
        display: none;
    }

    .rule-label { width: 24; color: $text-muted; }
    .rule-input { width: 12; }


    .tips-collapsible {
        margin-top: 1;
        background: $surface;
        border: solid $border;
    }

    DataTable {
        height: 1fr;
        max-height: 100%;
        background: $background;
        border: solid $border;
    }

    #inspector_table {
        height: 1fr;
        min-height: 10;
    }

    #inspector_details_container {
        height: 1fr;
        border: solid $border;
        background: $background;
    }

    #lookup_modal {
        width: 60;
        height: auto;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
        align: center middle;
    }

    #lookup_title {
        width: 100%;
        text-align: center;
        text-style: bold;
        color: $primary-light;
        margin-bottom: 1;
    }

    #lookup_results {
        margin: 1 0;
        padding: 1;
        background: $background;
        border: solid $border;
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
        self.packet_summaries: deque[PacketSummary] = deque(maxlen=1000)
        self.total_packets_captured = 0
        self.inspector_freeze = False
        self.threat_scanner = ThreatScanner()
        self.selected_source_ip = ""
        self.selected_dest_ip = ""



    def on_mount(self) -> None:
        """Hides the warnings tab on application initialization."""
        self.query_one(TabbedContent).hide_tab("warnings")
        self._closing = False
        
        # Initialize Security Table
        sec_table = self.query_one("#security_events_table", DataTable)
        sec_table.cursor_type = "row"
        sec_table.add_columns("Time", "Severity", "Type", "Source IP", "Description")

        # Initialize Inspector Table
        table = self.query_one("#inspector_table", DataTable)
        table.cursor_type = "row"
        table.add_columns("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")




    def on_unmount(self) -> None:
        """Cleans up resources upon app destruction."""
        self._closing = True
        self.stop_capture(user_requested=False)

    def compose(self) -> ComposeResult:
        """Yields the main UI layout widgets."""
        yield Header()
        with Container(id="main"):
            with TabbedContent(initial="analyzer"):
                with TabPane("Analyzer", id="analyzer"):
                    with Horizontal(classes="dashboard-container"):
                        with Vertical(classes="sidebar"):
                            yield Label("Control Panel", classes="section-title")
                            yield Button("Start Listening", variant="primary", id="start_capture", classes="btn-start")
                            yield Label("Status: Idle", id="status")
                            
                            yield Label("Configuration", classes="section-title")
                            yield Label("BPF Filter:", classes="label-muted")
                            yield Input(value="", placeholder="e.g. tcp, udp", id="filter")
                            
                            yield Label("Quick Presets:", classes="label-muted")
                            yield Select(
                                [
                                    ("All Traffic", ""),
                                    ("TCP Only", "tcp"),
                                    ("UDP Only", "udp"),
                                    ("Web (80/443)", "tcp port 80 or tcp port 443"),
                                    ("DNS (53)", "port 53"),
                                ],
                                id="filter_preset",
                                prompt="Select..."
                            )
                            with Horizontal(classes="compact-row"):
                                yield Label("Interval Mode", classes="label-muted")
                                yield Switch(id="interval_mode", value=False)



                            
                            with Vertical(id="duration_container", classes="hidden"):
                                yield Label("Capture Speed:", classes="label-muted")
                                with RadioSet(id="duration_select"):
                                    yield RadioButton("Slow (10s)", id="speed_10")
                                    yield RadioButton("Mid (5s)", id="speed_5", value=True)
                                    yield RadioButton("Fast (2s)", id="speed_2")

                            yield Label("Statistics", classes="section-title")
                            yield ActivityMeter(id="activity_meter")
                            yield Label("Packets: [b]0[/b]", id="packet_counter")

                        with VerticalScroll(classes="main-panel"):
                            yield Label("Live Protocol Stream", classes="section-title")
                            yield ProtocolLog(id="protocol_log")
                            
                            yield Label("Top Protocols", classes="section-title")
                            yield Static("Awaiting protocol distribution data...", id="protocol_distribution_bars", classes="card")
                            
                            yield Label("Diversity Pulse", classes="section-title")
                            yield Static("Awaiting diversity metrics...", id="entropy_meter", classes="card")

                            yield Label("Entropy Result", classes="section-title")
                            yield Static(
                                "Waiting for capture...",
                                id="analyzer_output",
                            )
                            
                            yield Label("Security Alerts", classes="section-title")
                            yield Static("No threats detected.", id="threat_alerts_summary", classes="card")





                with TabPane("Trends", id="trends"):
                    with Horizontal(classes="dashboard-container"):
                        with Vertical(classes="sidebar"):
                            yield Label("Summary Stats", classes="section-title")
                            yield Static("Capture idle.", id="trends_metrics")
                            
                            yield Label("Actions", classes="section-title")
                            yield Button("Export CSV", id="export_csv")
                            yield Button("Export MATLAB", id="export_matlab")
                            yield Button("Clear History", id="clear_charts")

                        with Vertical(classes="main-panel scroll-box"):
                            yield Label("Historical Trends", classes="section-title")
                            yield Static("Visual charts appear here.", id="trends_output")
                            yield Label("Dominant Process (Success Share)", classes="section-title")
                            yield Static("Start capture to view Bernoulli sequence.", id="bernoulli_output")

                            with Collapsible(title="Data Table View", collapsed=True):
                                yield DataTable(id="history_table")
                            with Collapsible(title="💡 Interpretation Tips", collapsed=True, classes="tips-collapsible"):
                                yield Static(
                                    "[b]Entropy H(X):[/b] Diversity score. High = mixed traffic, Low = flood/monoculture.\n"
                                    "[b]Binary Hb(p):[/b] Success-rate concentration metric.\n"
                                    "[b]Success Rate:[/b] Percentage of the most frequent protocol."
                                )

                with TabPane("Security", id="security_scanner"):
                    with Horizontal(classes="dashboard-container"):
                        with Vertical(classes="sidebar"):
                            yield Label("Security Pulse", classes="section-title")
                            yield Static("Scanning for threats...", id="security_status_label", classes="card")
                            
                            yield Label("Threat Distribution", classes="section-title")
                            yield Static("Waiting for data...", id="threat_distribution_bars", classes="card")
                            
                            yield Label("Top Offenders (IP)", classes="section-title")
                            yield Static("No offenders identified.", id="ip_watchlist", classes="card")

                        with Vertical(classes="main-panel scroll-box"):
                            yield Label("Live Security Events", classes="section-title")
                            yield DataTable(id="security_events_table")
                            
                            with Collapsible(title="💡 Response Procedures", collapsed=True, classes="tips-collapsible"):
                                yield Static(
                                    "[b]Signature Match (Critical):[/b] Isolate the source host immediately. Check for web shell or RCE attempt.\n"
                                    "[b]Port Scan (Medium):[/b] Typical reconnaissance. Monitor for follow-up attempts on open ports.\n"
                                    "[b]SYN Flood (High):[/b] Implement rate limiting or block the source IP at the firewall."
                                )

                with TabPane("Inspector", id="packet_inspector"):

                    with Horizontal(classes="dashboard-container"):
                        with Vertical(classes="sidebar"):
                            yield Label("Feed Control", classes="section-title")
                            yield Switch(id="inspector_freeze", value=False)
                            yield Label("Freeze Feed", classes="label-muted")
                            yield Button("Clear Feed", id="clear_inspector")
                            
                            yield Label("Selection", classes="section-title")
                            yield Static("Select a packet to see details.", id="inspector_selection_info")
                            yield Static("", id="inspector_hostname_info")
                            yield Button("Resolve Hostnames", id="resolve_hostnames", disabled=True)
                            
                            yield Label("Geographic Lookup", classes="section-title")
                            yield Button("Lookup Source IP", id="lookup_src", disabled=True)
                            yield Button("Lookup Dest IP", id="lookup_dst", disabled=True)
                            
                        with Vertical(classes="main-panel"):
                            yield Label("Live Packet Feed (Wireshark-style)", classes="section-title")
                            yield DataTable(id="inspector_table")
                            yield Label("Packet Details", classes="section-title")
                            with VerticalScroll(id="inspector_details_container"):
                                yield Static("Click a packet above to decode its layers.", id="inspector_details")



                with TabPane("Investigate", id="investigate"):
                    with Horizontal(classes="dashboard-container"):
                        with Vertical(classes="sidebar"):
                            yield Label("Alert Center", classes="section-title")
                            yield Button("View Warning Log", id="see_warnings")
                        with Vertical(classes="main-panel"):
                            yield Label("Anomaly Detection", classes="section-title")
                            yield Static("System normal.", id="investigate_output")

                with TabPane("Warnings", id="warnings"):
                    with VerticalScroll(classes="main-panel"):
                        yield Button("← Back", id="back_to_investigate", classes="btn-small")
                        yield Label("Event Queue", classes="section-title")
                        yield Static("No warnings.", id="warnings_output")

                with TabPane("Rules", id="alert_rules"):
                    with Horizontal(classes="dashboard-container"):
                        with Vertical(classes="sidebar"):
                            yield Label("Configuration", classes="section-title")
                            yield Label("Thresholds determine how sensitive the shift detection is to entropy changes.", classes="label-muted")
                            
                        with Vertical(classes="main-panel scroll-box"):
                            yield Label("Detection Thresholds", classes="section-title")
                            with Horizontal(classes="compact-row"):
                                yield Label("Entropy Drop:", classes="rule-label")
                                yield Input(value="0.7", id="rule_shannon_drop", classes="rule-input", tooltip="Alerts if entropy drops abruptly.")
                            with Horizontal(classes="compact-row"):
                                yield Label("Dominant Delta:", classes="rule-label")
                                yield Input(value="0.15", id="rule_dominant_share", classes="rule-input", tooltip="Alerts if a protocol share jumps.")
                            with Horizontal(classes="compact-row"):
                                yield Label("Rate Multiplier:", classes="rule-label")
                                yield Input(value="2.0", id="rule_packet_rate", classes="rule-input", tooltip="Alerts if rate exceeds baseline.")
                            
                            yield Label("Heuristics", classes="section-title")
                            with Horizontal(classes="compact-row"):
                                yield Label("Flood Rate:", classes="rule-label")
                                yield Input(value="3.0", id="rule_flood_rate", classes="rule-input", tooltip="Multiplier for Flood assessment.")
                            with Horizontal(classes="compact-row"):
                                yield Label("Scan Entropy:", classes="rule-label")
                                yield Input(value="3.0", id="rule_scan_entropy", classes="rule-input", tooltip="Min entropy for Scan assessment.")

                with TabPane("About", id="about"):
                    with VerticalScroll(classes="main-panel"):
                        yield Static(about_text(), id="about_text")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handles application button events."""
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
        if event.button.id == "lookup_src":
            if self.selected_source_ip:
                self.push_screen(IPLookupScreen(self.selected_source_ip))
            return
        if event.button.id == "lookup_dst":
            if self.selected_dest_ip:
                self.push_screen(IPLookupScreen(self.selected_dest_ip))
            return
        if event.button.id == "resolve_hostnames":
            self.query_one("#inspector_hostname_info").update("[dim]Resolving...[/]")
            self.run_worker(self.perform_hostname_resolution, thread=True)
            return
        if event.button.id == "clear_inspector":
            self.clear_inspector()
            return

    def action_toggle_analyze(self) -> None:
        """Toggles packet capture session."""
        if self.is_listening:
            self.stop_capture(user_requested=True)
        else:
            self.query_one(TabbedContent).active = "analyzer"
            self.start_capture()

    def action_export_csv(self) -> None:
        """Triggers CSV export action."""
        self.export_history_csv()

    def action_export_matlab(self) -> None:
        """Triggers MATLAB export action."""
        self.export_history_matlab()

    def action_show_about(self) -> None:
        """Navigates to the About tab."""
        self.query_one(TabbedContent).active = "about"

    def on_switch_changed(self, event: Switch.Changed) -> None:
        """Handles configuration switch interactions."""
        if event.switch.id == "interval_mode":
            is_active = event.value
            self.query_one("#duration_container").set_class(not is_active, "hidden")
        elif event.switch.id == "inspector_freeze":
            self.inspector_freeze = event.value


    def on_select_changed(self, event: Select.Changed) -> None:
        """Handles selection changes for presets and UI settings."""
        if event.select.id == "filter_preset":
            if event.value != Select.BLANK:
                self.query_one("#filter", Input).value = str(event.value)



    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Shows full packet details when a row is selected in the inspector."""
        if event.data_table.id == "inspector_table":
            try:
                idx = int(event.row_key.value)
                # Find the summary in our deque
                target = next((p for p in self.packet_summaries if p.index == idx), None)
                if target:
                    self.query_one("#inspector_details", Static).update(target.raw_details)
                    self.query_one("#inspector_selection_info", Static).update(f"Packet #{idx} selected.")
                    
                    self.selected_source_ip = target.source
                    self.selected_dest_ip = target.destination
                    
                    self.query_one("#lookup_src", Button).disabled = False
                    self.query_one("#lookup_dst", Button).disabled = False
                    self.query_one("#resolve_hostnames", Button).disabled = False
                    self.query_one("#inspector_hostname_info").update("")
            except Exception:
                pass

    def on_unmount(self) -> None:

        """Cleans up resources upon app destruction."""
        self.stop_capture(user_requested=False)

    def start_capture(self) -> None:
        """
        Initializes and starts the Scapy AsyncSniffer in a background thread.
        Prepares the internal state, sets up the update timer, and begins polling
        the active interface for packets matching the user-defined BPF filter.
        """
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

            # Initialize DataTables
            history_table = self.query_one("#history_table", DataTable)
            history_table.clear(columns=True)
            history_table.add_columns("Tick", "Time", "Total", "+New", "Dominant", "p(s)", "H(X)")

            inspector_table = self.query_one("#inspector_table", DataTable)
            inspector_table.clear(columns=True)
            inspector_table.add_columns("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
            
            self.selected_source_ip = ""
            self.selected_dest_ip = ""
            self.query_one("#lookup_src", Button).disabled = True
            self.query_one("#lookup_dst", Button).disabled = True
            self.query_one("#resolve_hostnames", Button).disabled = True
            self.query_one("#inspector_hostname_info").update("")
            
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

        try:
            analyzer_output = self.query_one("#analyzer_output", Static)
            trends_output = self.query_one("#trends_output", Static)
            investigate_output = self.query_one("#investigate_output", Static)
            warnings_output = self.query_one("#warnings_output", Static)
            status = self.query_one("#status", Label)
        except Exception:
            return


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

            # DPI Threat Scanning
            p_index = self.total_packets_captured
            threats = self.threat_scanner.scan_packet(packet, p_index)
            if threats:
                for threat in threats:
                    if threat.severity in {"HIGH", "CRITICAL"}:
                        self.warning_events.append(
                            WarningEvent(
                                tick=len(self.refresh_history),
                                elapsed_seconds=(time.monotonic() - self.capture_started_at) if self.capture_started_at else 0,
                                level=threat.severity,
                                score=5.0 if threat.severity == "CRITICAL" else 3.0,
                                reasons=[threat.description],
                                status="ACTIVE"
                            )
                        )

            self.total_packets_captured += 1

            idx = self.total_packets_captured
            summary = packet_to_summary(packet, idx)
            self.packet_summaries.append(summary)
            
            self.captured_symbols.append(symbol)
            self.total_packets_count += 1
            count = self.total_packets_count
        
        # Update live counter, activity meter, protocol log, and inspector table
        self.call_from_thread(self._update_live_ui, count, symbol, summary)

    def _update_live_ui(self, count: int, protocol: str, summary: PacketSummary) -> None:
        """Updates UI components from the capture thread safely."""
        if getattr(self, "_closing", False):
            return

        try:
            counter = self.query_one("#packet_counter", Label)
            counter.update(f"Counter: [b]{count}[/b] packets")
            
            meter = self.query_one("#activity_meter", ActivityMeter)
            meter.pulse()
            
            log = self.query_one("#protocol_log", ProtocolLog)
            log.add_protocol(protocol)
            
            # Update Inspector Table
            if not self.inspector_freeze:
                table = self.query_one("#inspector_table", DataTable)
                table.add_row(
                    str(summary.index),
                    summary.timestamp,
                    summary.source,
                    summary.destination,
                    summary.protocol,
                    str(summary.length),
                    summary.info,
                    key=str(summary.index)
                )
                # Auto-scroll and prune
                if table.row_count > 500:
                    table.remove_row(list(table.rows.keys())[0])
                table.scroll_to_row(table.row_count - 1)
        except Exception:
            # Handle cases where widgets are being unmounted during updates
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
        """
        The core analysis loop. Triggered periodically by the update_timer.
        It pulls captured packets, calculates current Shannon/Binary entropy,
        invokes the shift_detection algorithms to find anomalies, appends the
        results to the historical snapshot list, and updates all visual UI components.
        """
        if self._closing:
            return

        try:
            trends_metrics = self.query_one("#trends_metrics", Static)
            analyzer_output = self.query_one("#analyzer_output", Static)
            trends_output = self.query_one("#trends_output", Static)
            investigate_output = self.query_one("#investigate_output", Static)
            warnings_output = self.query_one("#warnings_output", Static)
            status = self.query_one("#status", Label)
            activity_meter = self.query_one("#activity_meter", ActivityMeter)
            packet_counter = self.query_one("#packet_counter", Label)
            protocol_log = self.query_one("#protocol_log", ProtocolLog)
        except Exception:
            return


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
            investigate_text = "No investigation data yet. Capture is active but no packets have been observed."
            warnings_text = "Warnings window\n---------------\nNo WARNING/CRITICAL events have been queued."

            self.last_analyzer_text = analyzer_text
            self.last_trends_text = trends_text
            self.last_investigate_text = investigate_text
            self.last_warnings_text = warnings_text
            analyzer_output.update(analyzer_text)
            self.query_one("#protocol_distribution_bars", Static).update("Awaiting protocols...")
            self.query_one("#entropy_meter", Static).update("Awaiting metrics...")
            trends_metrics.update("Key Metrics\n-----------\nAwaiting packets...")

            trends_output.update(trends_text)
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
        )
        self.query_one("#protocol_distribution_bars", Static).update(format_protocol_bars(symbols))
        self.query_one("#entropy_meter", Static).update(format_entropy_meter(entropy_result))
        self.query_one("#threat_alerts_summary", Static).update(format_threat_summary(self.threat_scanner.alerts))

        
        # Update Trends
        trends_text = (
            format_shannon_entropy_timeline(self.refresh_history)
            + "\n\n"
            + format_binary_entropy_timeline(self.refresh_history)
        )



        self.query_one("#bernoulli_output", Static).update(bernoulli_report)


        # Update Security Tab
        sec_status = "SECURE"
        if any(a.severity in {"HIGH", "CRITICAL"} for a in self.threat_scanner.alerts):
            sec_status = "[b red]ALERT[/b red]"
        self.query_one("#security_status_label", Static).update(f"Status: {sec_status}\nTotal Alerts: {len(self.threat_scanner.alerts)}")
        
        # Update Security Table (only add new ones)
        sec_table = self.query_one("#security_events_table", DataTable)
        # For simplicity in this TUI, we'll clear and re-add or just keep track of count
        if len(self.threat_scanner.alerts) > sec_table.row_count:
            # Add only the newest alerts
            for i in range(sec_table.row_count, len(self.threat_scanner.alerts)):
                alert = self.threat_scanner.alerts[i]
                t_str = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
                severity_style = {
                    "INFO": "blue",
                    "MEDIUM": "yellow",
                    "HIGH": "orange",
                    "CRITICAL": "red"
                }.get(alert.severity, "white")
                
                sec_table.add_row(
                    t_str,
                    f"[{severity_style}]{alert.severity}[/{severity_style}]",
                    alert.threat_type,
                    alert.source_ip,
                    alert.description
                )
        
        # Update IP Watchlist and Distribution
        from collections import Counter
        ip_counts = Counter(a.source_ip for a in self.threat_scanner.alerts)
        type_counts = Counter(a.threat_type for a in self.threat_scanner.alerts)
        
        watchlist_lines = []
        for ip, count in ip_counts.most_common(5):
            watchlist_lines.append(f"{ip:<15} {count:>3} alerts")
        self.query_one("#ip_watchlist", Static).update("\n".join(watchlist_lines) if watchlist_lines else "No offenders.")
        
        dist_lines = []
        for t_type, count in type_counts.most_common(5):
            bar = "█" * min(10, count)
            dist_lines.append(f"{t_type:<12} {bar} {count}")
        self.query_one("#threat_distribution_bars", Static).update("\n".join(dist_lines) if dist_lines else "Waiting for threats...")

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
        investigate_output.update(investigate_text)
        warnings_output.update(warnings_text)


        if self.is_listening:
            status.update("Status: Listening...")
        else:
            status.update("Status: Done")


    def perform_hostname_resolution(self) -> None:
        """Resolves hostnames for current selection in a background thread."""
        import socket
        src_host = "Unknown"
        dst_host = "Unknown"
        
        if self.selected_source_ip:
            try:
                src_host = socket.gethostbyaddr(self.selected_source_ip)[0]
            except Exception:
                src_host = "N/A"
        
        if self.selected_dest_ip:
            try:
                dst_host = socket.gethostbyaddr(self.selected_dest_ip)[0]
            except Exception:
                dst_host = "N/A"
        
        self.app.call_from_thread(self._update_hostname_info, src_host, dst_host)

    def _update_hostname_info(self, src: str, dst: str) -> None:
        info = f"[b]Source:[/b] [cyan]{src}[/]\n[b]Dest:[/b]   [cyan]{dst}[/]"
        self.query_one("#inspector_hostname_info").update(info)

    def clear_inspector(self) -> None:
        """Clears the packet inspector table and internal summary buffer."""
        table = self.query_one("#inspector_table", DataTable)
        table.clear()
        self.packet_summaries.clear()
        
        self.selected_source_ip = ""
        self.selected_dest_ip = ""
        self.query_one("#lookup_src", Button).disabled = True
        self.query_one("#lookup_dst", Button).disabled = True
        self.query_one("#resolve_hostnames", Button).disabled = True
        self.query_one("#inspector_hostname_info").update("")
        self.query_one("#inspector_details", Static).update("Click a packet above to decode its layers.")
        self.query_one("#inspector_selection_info", Static).update("Select a packet to see details.")


if __name__ == "__main__":
    ShannonEntropyApp().run()
