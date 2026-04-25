# Shannon Entropy TUI

A simple Textual-based terminal UI app that:
- Listens to real network traffic from the current device interface.
- Computes Shannon entropy from captured packet-symbol observations.
- Builds a Bernoulli process chart from the same captured stream.

## What to enter

- **Listening duration (seconds)**: how long the sniffer runs.
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

## Notes

- Shannon entropy is computed as:

$$
H(X) = -\sum_i p(x_i)\log_2 p(x_i)
$$

- The Bernoulli chart displays:
  - A binary projection of captured symbols using the most frequent observed symbol as success (1), and all others as failure (0)
  - Running success rate $\hat p_n$
  - An ASCII plot of running success rate over trials
