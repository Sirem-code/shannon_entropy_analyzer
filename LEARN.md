### How the idea was conceived

A common link was found between information theory and thermodynamics, specifically, the way entropy which is a measure of uncertainty or randomness can be applied to find disturbances in the context of a network. Therefore, these disturbances can be classified as events or threats with the use of thresholds. However, the need for baselines became prevalent, which lead to the consideration of establishing baselines in the context of networks. Using simple statistical methods, baselines for entropy and packet rates can be established by taking into account the type of network and its characteristics (e.g protocol, traffic type, etc.). The characteristics of a network can be used to determine the normal levels of entropy and packet rates.

### Entropy and binary entropy

These are two measures of the uncertainty of a system. Entropy is a measure of the uncertainty of the distribution of symbols in a system, while binary entropy is a measure of the uncertainty of the distribution of bits in a system. 

### Entropy details

Entropy can be derived from the shannon entropy formula:

```
H(X) = - Σ p(x)log(p(x))
```

where X is a random variable, p(x) is the probability of x, and Σ is the sum over all possible values of x. 

In this context, it means that high entropy will mean that a plethora of different protocols are being used in the network, while low entropy will mean that a few protocols are being used in the network. This concept can be further broken down into:

High entropy = network is being used for its intended purpose (high diversity of protocols and services).
Low entropy = network is being used for unintended purposes (e.g. exfiltration, scanning, etc.)

### Binary entropy details

Binary entropy is a measure of the uncertainty of the distribution of bits in a system. It is calculated as:

```
H(X) = - Σ p(x)log(p(x))
```

where X is a random variable, p(x) is the probability of x, and Σ is the sum over all possible values of x.

The success rate represents how the proportion of the most frequent protocol (or dominant) changes over time as more network packets are analyzed. It uses the Bernoulli Model (basically a fancy way to represent a coinflip) which has 2 possible outcomes:

- Success: Packet belongs to the dominant protocol
- Failure: Packet does not belong to the dominant protocol

### The success rate chart

Tracks the cumulative percentage of "successes" over time.

- High/Rising line: Indicates the dominant protocol is making up a larger and larger share of the traffic. Therefore, the network is becoming less diverse and predictable (Shannon entropy goes down).

- Low/Falling line: Indicates other, less common protocols are taking up a larger share of traffic. The network is becoming more diverse (Shannon entropy goes up).

This is a means of analyzing the network's behavior over time and can be used to detect anomalies or suspicious activity. Visually, a sharp increase in the success rate and subsequent decrease in entropy could indicate a scanning activity. On the antipode, a sharp increase in entropy and subsequent decrease in the success rate could indicate a new type of traffic entering the network. There is however, a handy warnings system to help determine if the changes are anomalies or not.

### Dominant Share Delta

This is a security metric that tracks how much the dominant protocol's share has changed over time. A large positive delta could mean that the network is becoming less diverse and predictable (e.g. during a scanning activity), while a large negative delta could mean that the network is becoming more diverse and unpredictable (e.g. during a new type of traffic entering the network).

### Notes on Terms & Functions

**Core Terms:**
- **Entropy**: Measures network diversity. 
  - *High*: Diverse traffic (normal network use).
  - *Low*: Homogenous traffic (possible scanning or exfiltration).
- **Success Rate**: The proportion of traffic made up by the most frequent (dominant) protocol.
  - *High/Rising*: Network becoming less diverse (entropy down).
  - *Low/Falling*: Network becoming more diverse (entropy up).
- **Dominant Share Delta**: How much the dominant protocol's share is changing.
  - *Positive Delta*: Traffic concentrating on one protocol.
  - *Negative Delta*: Traffic spreading across multiple protocols.
- **Baseline**: The calculated "normal" state of the network.

**Threat Indicators (Heuristics):**
- **DoS/Flood Attack**: Massive Packet Rate + Critically Low Entropy.
- **Port Scan/Recon**: High Packet Rate + Spiking Entropy.
- **Data Exfiltration**: Extreme Spikes in Entropy (indicating encrypted/randomized data).
- **New Species Alert**: Appearance of a protocol not present in the baseline.

**UI Functions & Controls:**
- **Start Listening**: Begin capturing packets on the selected interface.
- **Toggle Mode**: Switch between *Interval Mode* (fixed time windows) and *Packet Mode* (fixed packet count windows).
- **Settings & Rules**: Adjust sensitivity thresholds dynamically in the "Alert Rules" tab.
- **Exporting**: Save current metrics to `.csv` or MATLAB `.m` formats for post-incident analysis.

Lastly, this "disturbance in the network" concept led to the Darth Vader app icon. 