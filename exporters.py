from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from models import RefreshSnapshot


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def export_refresh_history_csv(history: list[RefreshSnapshot], output_dir: str = ".") -> Path:
    path = Path(output_dir) / f"refresh_history_{_timestamp()}.csv"
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
                ]
            )
    return path


def export_refresh_history_matlab_m(history: list[RefreshSnapshot], output_dir: str = ".") -> Path:
    path = Path(output_dir) / f"refresh_history_{_timestamp()}.m"
    lines = [
        "% Auto-generated refresh history for MATLAB",
        "% Columns: tick, elapsed_seconds, total_packets, new_packets, success_probability, binary_entropy_bits, shannon_entropy_bits",
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
            f"{row.shannon_entropy_bits:.12f};"
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
        ]
    )

    path.write_text("\n".join(lines), encoding="utf-8")
    return path
