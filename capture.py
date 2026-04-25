from __future__ import annotations
"""
# Packet Capture: Network Interface and Protocol Classification

This module is the **network interface layer** of the Shannon Entropy Analyzer.
It wraps the [Scapy](https://scapy.net/) packet manipulation library to perform
live packet sniffing and converts raw network frames into discrete categorical
**symbols** that the analysis engine can process.

## Why Do We Need This?

Shannon Entropy operates on *symbols*, that is, discrete categories like "TCP", "UDP",
or "DNS/UDP". But the network doesn't send us neat labels; it sends raw binary
frames full of headers and payloads. This module bridges that gap by:

1. **Detecting** which network interface to listen on
2. **Capturing** raw packets asynchronously in a background thread
3. **Classifying** each packet into a human-readable protocol symbol

## How Packet Classification Works

When a packet arrives, `packet_to_symbol()` examines its layers from the
outside in, following the OSI/TCP-IP model:

```
┌──────────────────────────────────┐
│ Layer 2: Is it ARP?              │ → "ARP"
├──────────────────────────────────┤
│ Layer 3: Is it IPv4?             │
│   ├── Layer 4: TCP?              │
│   │   ├── Port 443? → "TLS/TCP" │
│   │   ├── Port 80?  → "HTTP/TCP"│
│   │   └── Other     → "TCP"     │
│   ├── Layer 4: UDP?              │
│   │   ├── Port 53?  → "DNS/UDP" │
│   │   ├── Port 67/68? → "DHCP/UDP"│
│   │   └── Other     → "UDP"     │
│   ├── ICMP?          → "ICMP"   │
│   └── Other          → "IP-OTHER"│
├──────────────────────────────────┤
│ Layer 3: Is it IPv6?             │ → "IPv6"
├──────────────────────────────────┤
│ Anything else                    │ → "OTHER"
└──────────────────────────────────┘
```

## Important Notes for Students

- **Scapy** is imported dynamically (`importlib`) so the app can still load
  even if Scapy is not installed. It will simply show an error when you try
  to start a capture.
- **BPF filters** (Berkeley Packet Filter) can be applied at capture time
  to focus on specific traffic (e.g., `"tcp port 443"` for HTTPS only).
  These are passed directly to the underlying pcap library.
- **Npcap** (Windows) or **libpcap** (Linux/macOS) must be installed for
  packet capture to work. Without it, Scapy cannot access the raw network
  interface.
- **Admin/root privileges** are required because raw packet capture
  bypasses the normal socket API.
"""

import importlib
from typing import Any

try:
    scapy_all = importlib.import_module("scapy.all")
except Exception:  # pragma: no cover
    scapy_all = None

ARP = getattr(scapy_all, "ARP", None)
ICMP = getattr(scapy_all, "ICMP", None)
IP = getattr(scapy_all, "IP", None)
IPv6 = getattr(scapy_all, "IPv6", None)
TCP = getattr(scapy_all, "TCP", None)
UDP = getattr(scapy_all, "UDP", None)
conf = getattr(scapy_all, "conf", None)
AsyncSniffer = getattr(scapy_all, "AsyncSniffer", None)


def detect_default_interface() -> str:
    """
    Detects the default active network interface using Scapy's configuration.
    
    Returns:
        The name of the default interface as a string, or 'unknown' if Scapy is unavailable.
    """
    if conf is None:
        return "unknown"
    return str(conf.iface)


def packet_to_symbol(packet: Any) -> str:
    """
    Classifies a raw Scapy packet into a discrete categorical symbol.
    Examines the packet layers (ARP, IP, TCP, UDP, ICMP, IPv6) and ports
    to assign a human-readable protocol string.
    
    Args:
        packet: A raw Scapy packet object.
        
    Returns:
        A string representing the packet's protocol category (e.g., 'HTTP/TCP').
    """
    if ARP is not None and packet.haslayer(ARP):
        return "ARP"

    if IP is not None and packet.haslayer(IP):
        if TCP is not None and packet.haslayer(TCP):
            tcp = packet[TCP]
            ports = {int(tcp.sport), int(tcp.dport)}
            if 443 in ports:
                return "TLS/TCP"
            if 80 in ports:
                return "HTTP/TCP"
            return "TCP"
        if UDP is not None and packet.haslayer(UDP):
            udp = packet[UDP]
            ports = {int(udp.sport), int(udp.dport)}
            if 53 in ports:
                return "DNS/UDP"
            if 67 in ports or 68 in ports:
                return "DHCP/UDP"
            return "UDP"
        if ICMP is not None and packet.haslayer(ICMP):
            return "ICMP"
        return "IP-OTHER"

    if IPv6 is not None and packet.haslayer(IPv6):
        return "IPv6"

    return "OTHER"
