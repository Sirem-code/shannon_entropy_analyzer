# Shannon Entropy Analyzer

A modern, terminal-based user interface (TUI) for real-time network traffic analysis, using Shannon Entropy to detect anomalies, network shifts, and potential malicious activity.

## Overview
The Shannon Entropy Analyzer monitors your network interfaces using `scapy` and calculates the Shannon Entropy of the protocol mix in real-time. By observing the diversity of packets, it can intelligently identify when your network state shifts from its normal baseline.

## Screenshot

![image_alt](https://github.com/Sirem-code/shannon_entropy_analyzer/blob/2ef0f32fc9dcd9dc5d06a1268cb8595abafed50d/Screenshot%202026-04-29%20101045.png)

## Key Features
- **Live Packet Sniffing**: Real-time traffic capture with customizable BPF filters (e.g., `tcp`, `port 443`).
- **Dynamic Shift Detection**: Automatically calculates rolling baselines and detects statistically significant deviations in packet rates and entropy.
- **Security Intelligence (DPI)**: 
  - **Signature Matching**: Scans payloads for shellcode and NOP sleds.
  - **Behavioral Scanning**: Detects port scanning and SYN flooding by tracking IP-level state.
  - **Protocol Anomaly**: Identifies ICMP tunneling and other oversized protocol payloads.
- **Advanced Heuristic Alerts**:
  - **DoS/Flood Attack**: Detects massive spikes in packet rates combined with critically low entropy.
  - **Port Scan/Reconnaissance**: Identifies high packet rates combined with high or spiking entropy.
  - **Data Exfiltration**: Catches sudden extreme spikes in entropy indicating encrypted or random traffic.
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

3. (Optional) Run the application with a specific interface:
```bash
python app.py --interface "Wi-Fi"
```

## Running Tests
The project includes a comprehensive unit test suite to ensure mathematical accuracy and security detection reliability.

To run all tests:
```bash
python -m unittest discover tests
```

To run a specific test module (e.g., Analysis):
```bash
python -m unittest tests/test_analysis.py
```

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

## License
See the [LISENCE](https://github.com/Sirem-code/shannon_entropy_analyzer/blob/main/LICENSE) file for license rights and limitations (GNU).
