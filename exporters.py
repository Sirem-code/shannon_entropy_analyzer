from __future__ import annotations
"""
# Exporters: Data Persistence and Post-Analysis

This module is the **persistence layer** of the Shannon Entropy Analyzer. It
saves captured network analysis data to disk in formats that can be consumed
by external tools for further analysis, visualization, and reporting.

## Why Export Data?

The TUI provides real-time visualization, but for serious analysis you often need
to work with the data *after* the capture session ends. Common workflows include:

- **Statistical analysis** in Python (pandas), R, or Excel using CSV exports
- **Publication-quality plots** in MATLAB or GNU Octave using `.m` script exports
- **Incident response** documentation: saved CSV files serve as evidence logs.
- **Longitudinal studies**: compare entropy baselines across different days or weeks.

## Supported Export Formats

### CSV (Comma-Separated Values)
The `export_refresh_history_csv()` function creates a standard CSV file with
one row per refresh tick. All numeric metrics (entropy, packet rates, shift
scores) are included alongside categorical data (dominant symbol, alert level).

**Output columns:**
`tick`, `elapsed_seconds`, `total_packets`, `new_packets`, `dominant_symbol`,
`success_probability`, `binary_entropy_bits`, `shannon_entropy_bits`,
`packet_rate`, `baseline_shannon_bits`, `baseline_packet_rate`,
`dominant_share_delta`, `shift_score`, `alert_level`, `alert_reasons`

**Usage with pandas:**
```python
import pandas as pd
df = pd.read_csv("refresh_history_20260425_120000.csv")
df.plot(x="elapsed_seconds", y="shannon_entropy_bits")
```

### MATLAB/Octave Script (.m)
The `export_refresh_history_matlab_m()` function generates an executable `.m`
script that, when run in MATLAB or Octave, will:

1. Load all numeric data into a matrix called `refresh_history`
2. Extract convenience column vectors (e.g., `tick`, `shannon_entropy_bits`)
3. Store alert metadata in cell arrays
4. Auto-generate a 3-panel subplot figure showing:
   - Shannon Entropy over time
   - Binary Entropy and success probability
   - Packet rate vs. baseline median

**Usage:** Simply open the file in MATLAB/Octave and press Run (F5).

## File Naming Convention
All exported files are timestamped with the format `refresh_history_YYYYMMDD_HHMMSS`
to prevent overwriting previous exports and to provide a clear audit trail.
"""

import csv
from datetime import datetime
from pathlib import Path

from models import RefreshSnapshot


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def export_refresh_history_csv(history: list[RefreshSnapshot], output_dir: str = ".") -> Path:
    """
    Exports the recorded network snapshot history to a CSV file.
    
    Args:
        history: A list of RefreshSnapshot objects containing the metrics over time.
        output_dir: The directory path where the CSV file should be created.
        
    Returns:
        The exact Path object pointing to the newly created CSV file.
    """
    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    path = output_dir_path / f"refresh_history_{_timestamp()}.csv"
    with path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(
            [
                "tick",
                "elapsed_seconds",
                "total_packets",
                "new_packets",
                "dominant_symbol",
                "success_probability",
                "binary_entropy_bits",
                "shannon_entropy_bits",
                "packet_rate",
                "baseline_shannon_bits",
                "baseline_packet_rate",
                "dominant_share_delta",
                "shift_score",
                "alert_level",
                "alert_reasons",
            ]
        )
        for row in history:
            writer.writerow(
                [
                    row.tick,
                    f"{row.elapsed_seconds:.6f}",
                    row.total_packets,
                    row.new_packets,
                    row.dominant_symbol,
                    f"{row.success_probability:.12f}",
                    f"{row.binary_entropy_bits:.12f}",
                    f"{row.shannon_entropy_bits:.12f}",
                    f"{row.packet_rate:.12f}",
                    f"{row.baseline_shannon_bits:.12f}",
                    f"{row.baseline_packet_rate:.12f}",
                    f"{row.dominant_share_delta:.12f}",
                    f"{row.shift_score:.12f}",
                    row.alert_level,
                    " | ".join(row.alert_reasons),
                ]
            )
    return path


def export_refresh_history_matlab_m(history: list[RefreshSnapshot], output_dir: str = ".") -> Path:
    """
    Exports the recorded network snapshot history to an executable MATLAB/Octave script (.m).
    Running the generated script in MATLAB will automatically load the data into variables
    and generate three subplots showing Shannon Entropy, Binary Entropy, and Packet Rates.
    
    Args:
        history: A list of RefreshSnapshot objects containing the metrics over time.
        output_dir: The directory path where the MATLAB file should be created.
        
    Returns:
        The exact Path object pointing to the newly created .m script.
    """
    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    path = output_dir_path / f"refresh_history_{_timestamp()}.m"
    lines = [
        "% Auto-generated refresh history for MATLAB",
        "% Numeric columns: tick, elapsed_seconds, total_packets, new_packets, success_probability, binary_entropy_bits, shannon_entropy_bits, packet_rate, baseline_shannon_bits, baseline_packet_rate, dominant_share_delta, shift_score",
        "refresh_history = [",
    ]

    for row in history:
        lines.append(
            "  "
            f"{row.tick} "
            f"{row.elapsed_seconds:.12f} "
            f"{row.total_packets} "
            f"{row.new_packets} "
            f"{row.success_probability:.12f} "
            f"{row.binary_entropy_bits:.12f} "
            f"{row.shannon_entropy_bits:.12f} "
            f"{row.packet_rate:.12f} "
            f"{row.baseline_shannon_bits:.12f} "
            f"{row.baseline_packet_rate:.12f} "
            f"{row.dominant_share_delta:.12f} "
            f"{row.shift_score:.12f};"
        )

    lines.extend(
        [
            "];",
            "",
            "% Optional convenience vectors",
            "tick = refresh_history(:,1);",
            "elapsed_seconds = refresh_history(:,2);",
            "total_packets = refresh_history(:,3);",
            "new_packets = refresh_history(:,4);",
            "success_probability = refresh_history(:,5);",
            "binary_entropy_bits = refresh_history(:,6);",
            "shannon_entropy_bits = refresh_history(:,7);",
            "packet_rate = refresh_history(:,8);",
            "baseline_shannon_bits = refresh_history(:,9);",
            "baseline_packet_rate = refresh_history(:,10);",
            "dominant_share_delta = refresh_history(:,11);",
            "shift_score = refresh_history(:,12);",
            "",
            "% Alert metadata (cell arrays)",
            "alert_level = {",
        ]
    )

    for row in history:
        lines.append(f"  '{row.alert_level}'")

    lines.append("};")
    lines.append("alert_reasons = {")

    for row in history:
        reason_text = " | ".join(row.alert_reasons).replace("'", "''")
        lines.append(f"  '{reason_text}'")

    lines.append("};")
    lines.extend(
        [
            "",
            "% Plot section (MATLAB/Octave compatible)",
            "figure('Name', 'Network Entropy Investigation', 'NumberTitle', 'off');",
            "subplot(3,1,1);",
            "plot(tick, shannon_entropy_bits, '-o', 'LineWidth', 1.4);",
            "grid on;",
            "ylabel('H(X) bits');",
            "title('Shannon Entropy Over Refresh Ticks');",
            "",
            "subplot(3,1,2);",
            "plot(tick, binary_entropy_bits, '-o', 'LineWidth', 1.4); hold on;",
            "stairs(tick, success_probability, '--', 'LineWidth', 1.2);",
            "grid on;",
            "ylabel('Hb(p) / p(success)');",
            "title('Running success-rate plot');",
            "legend('Hb(p)', 'p(success)', 'Location', 'best');",
            "",
            "subplot(3,1,3);",
            "plot(tick, packet_rate, '-o', 'LineWidth', 1.4); hold on;",
            "plot(tick, baseline_packet_rate * ones(size(tick)), '--', 'LineWidth', 1.2);",
            "grid on;",
            "xlabel('Refresh tick');",
            "ylabel('Packets/s');",
            "title('Packet Rate vs Baseline');",
            "legend('Packet rate', 'Baseline median', 'Location', 'best');",
        ]
    )

    path.write_text("\n".join(lines), encoding="utf-8")
    return path
