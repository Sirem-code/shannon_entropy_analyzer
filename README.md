# Shannon Entropy Analyzer

A modern, terminal-based user interface (TUI) for real-time network traffic analysis, using Shannon Entropy to detect anomalies, network shifts, and potential malicious activity.

## Overview
The Shannon Entropy Analyzer monitors your network interfaces using `scapy` and calculates the Shannon Entropy of the protocol mix in real-time. By observing the diversity of packets, it can intelligently identify when your network state shifts from its normal baseline.

## Key Features
- **Live Packet Sniffing**: Real-time traffic capture with customizable BPF filters (e.g., `tcp`, `port 443`).
- **Dynamic Shift Detection**: Automatically calculates rolling baselines and detects statistically significant deviations in packet rates and entropy.
- **Advanced Heuristic Alerts**:
  - **DoS/Flood Attack**: Detects massive spikes in packet rates combined with critically low entropy.
  - **Port Scan/Reconnaissance**: Identifies high packet rates combined with high or spiking entropy (diversity of ports/protocols).
  - **Data Exfiltration/Tunneling**: Catches sudden extreme spikes in entropy that often indicate encrypted or highly randomized traffic leaving the network.
  - **Entropy Volatility (Jitter)**: Warns when network traffic diversity is highly unstable.
  - **Sustained State Warnings**: Alerts if the network remains in a flooded or unnatural state for extended periods.
  - **New Species Alert**: Notifies you when a completely new protocol appears that wasn't in the baseline.
- **Configurable Alert Rules**: Tweak the sensitivity of all detection algorithms on the fly via the built-in UI.
- **Exporting**: Save your refresh history and metrics to CSV or MATLAB `.m` formats for post-incident analysis.

## Installation
Ensure you have Python 3.10+ installed.

1. Install the required dependencies:
```bash
pip install scapy textual
```
*(Note: On Windows, Scapy requires Npcap to be installed to capture packets).*

## Usage
Run the application directly:
```bash
python app.py
```

### Controls
- **Start Listening**: Begins capturing packets on the selected interface.
- **Toggle Mode**: Switch between Interval Mode (fixed time windows) or Packet Mode (fixed packet count windows).
- **Settings & Rules**: Navigate to the "Alert Rules" tab to configure detection thresholds.

## Credits
- **Developer**: Sirem
- **GitHub**: [Sirem-code](https://github.com/Sirem-code)
