# Shannon Entropy TUI

A simple Textual-based terminal UI app that:
- Computes Shannon entropy from network observation symbols.
- Builds a Bernoulli process chart from binary events.

## What to enter

- **Network symbols**: packet or state labels separated by commas or spaces.
  - Example: `SYN ACK ACK FIN SYN`
- **Bernoulli sequence**: binary observations (`0` or `1`) separated by commas or spaces.
  - Example: `1 1 0 1 0 0 1`

## Run

```powershell
python -m pip install -r requirements.txt
python app.py
```

## Notes

- Shannon entropy is computed as:

$$
H(X) = -\sum_i p(x_i)\log_2 p(x_i)
$$

- The Bernoulli chart displays:
  - The raw binary sequence
  - Running success rate $\hat p_n$
  - An ASCII plot of running success rate over trials
