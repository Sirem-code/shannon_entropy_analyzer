# Shannon Entropy TUI

A simple Textual-based terminal UI app that:
- Listens to real network traffic from the current device interface.
- Computes Shannon entropy from captured packet-symbol observations.
- Builds a Bernoulli process chart from the same captured stream.
- Plots binary entropy per refresh tick in a dedicated Trends tab.
- Keeps full per-refresh history for retrospective review.
- Supports live start/stop capture with periodic report refresh.
- Includes an About tab explaining the model and usage.

## Tabs

- **Analyzer**: live H(X), capture session summary, and symbol probability report.
- **Trends**: Shannon H(X) timeline (dynamic axis), binary entropy chart, refresh history table, and Bernoulli chart.
- **Packet Analysis**: protocol class breakdown, packet-rate context, and protocol-mixing indicators.
- **Investigate**: automatic shift alerts, alert timeline, trigger reasons, and before/after baseline comparison.
- **About**: concise explanation and reference link.

## What to enter

- **Refresh duration (seconds)**: how often on-screen analysis is refreshed while listening.
  - Example: `10`
- **Interface (optional)**: leave blank to use the default active interface.

## Run

```powershell
python -m pip install -r requirements.txt
python app.py
```

## Important for packet capture

- Packet sniffing may require elevated privileges.
- On Windows, install Npcap if capture is unavailable.
- If no packets are captured, increase the listening duration or generate traffic during capture.

## Live controls

- Click **Start Listening** to begin packet capture immediately.
- The analysis refreshes every configured duration while capture is active.
- Click **Stop** to end capture and keep the final report on screen.

## Export

- In the **Trends** tab, use **Export CSV** to save refresh history as a CSV file.
- Use **Export MATLAB** to save a MATLAB-compatible `.m` file with the same history matrix.
- Export actions create/use an `exports` folder in the project directory and show the saved file path in the Trends panel.
- Use **Clear Charts** to reset trend plots/history and start charting from the current moment.
- Exports now include shift detection fields (shift score, alert level, alert reasons, and baseline comparison values).

## Notes

- Shannon entropy is computed as:

$$
H(X) = -\sum_i p(x_i)\log_2 p(x_i)
$$

- The Bernoulli chart displays:
  - A binary projection of captured symbols using the most frequent observed symbol as success (1), and all others as failure (0)
  - Running success rate $\hat p_n$
  - An ASCII plot of running success rate over trials
