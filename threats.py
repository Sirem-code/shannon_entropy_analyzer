from __future__ import annotations
"""
# Threat Detection Engine: Behavioral and Signature Intelligence

This module is the **security layer** of the Shannon Entropy Analyzer.
While `shift_detection.py` identifies statistical anomalies (the "unknown unknowns"),
this module identifies specific, known malicious patterns (the "known unknowns").

## Detection Strategies

1. **Signature Matching**: Scanning packet payloads for known exploit strings
   (e.g., NOP sleds, shell commands, or common malware signatures).
2. **Behavioral Analysis**: Tracking state across multiple packets to identify
   attacks like Port Scanning or SYN Flooding.
3. **Protocol Enforcement**: Identifying when a protocol is behaving in a way
   that violates its intended use (e.g., abnormally large ICMP payloads).

## Why Both Entropy and Threat Detection?

Entropy tells you *that* something is weird (e.g., "The network suddenly became
very random"). Threat detection tells you *what* is weird (e.g., "Someone is
running a port scan from 192.168.1.5"). Together, they provide a complete
picture of network health and security.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set, Optional
import time

@dataclass(frozen=True)
class ThreatAlert:
    """
    Represents a specific detected threat.
    """
    timestamp: float
    source_ip: str
    threat_type: str  # e.g., "PORT_SCAN", "SHELL_CODE"
    severity: str     # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    description: str
    packet_index: Optional[int] = None

class ThreatScanner:
    """
    Main engine for coordinating various threat detection rules.
    """
    def __init__(self) -> None:
        # Behavioral state tracking
        self.ip_port_history: Dict[str, Set[int]] = {}  # source_ip -> set(dest_ports)
        self.syn_count: Dict[str, int] = {}             # source_ip -> count of SYN packets
        self.last_cleanup = time.time()
        
        # Alerts history
        self.alerts: List[ThreatAlert] = []
        
        # Signatures (simplified for demonstration)
        self.signatures = {
            "SHELL_CODE": re.compile(rb"(/bin/sh|cmd\.exe|powershell)", re.IGNORECASE),
            "NOP_SLED": re.compile(rb"\x90\x90\x90\x90\x90\x90\x90\x90"),
        }

    def scan_packet(self, packet: Any, packet_index: int) -> List[ThreatAlert]:
        """
        Runs all active detection rules against a single packet.
        
        Args:
            packet: A raw Scapy packet.
            packet_index: The sequence number of the packet in the current session.
            
        Returns:
            A list of any ThreatAlerts triggered by this packet.
        """
        new_alerts: List[ThreatAlert] = []
        
        # 1. Extract basic metadata
        src_ip = "unknown"
        from capture import IP, TCP, UDP, ICMP, Raw
        
        if IP is not None and packet.haslayer(IP):
            src_ip = packet[IP].src
            
            # --- Rule A: Port Scan Detection (Behavioral) ---
            if TCP is not None and packet.haslayer(TCP):
                dst_port = int(packet[TCP].dport)
                self._track_port(src_ip, dst_port, new_alerts)
                
                # --- Rule B: SYN Flood (Behavioral) ---
                if packet[TCP].flags == "S": # SYN only
                    self.syn_count[src_ip] = self.syn_count.get(src_ip, 0) + 1
                    if self.syn_count[src_ip] > 100: # Threshold
                        new_alerts.append(ThreatAlert(
                            timestamp=time.time(),
                            source_ip=src_ip,
                            threat_type="SYN_FLOOD",
                            severity="HIGH",
                            description=f"Potential SYN Flood detected from {src_ip} (>100 SYNs).",
                            packet_index=packet_index
                        ))

            # --- Rule C: Signature Matching (Payload) ---
            if Raw is not None and packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                for name, pattern in self.signatures.items():
                    if pattern.search(payload):
                        new_alerts.append(ThreatAlert(
                            timestamp=time.time(),
                            source_ip=src_ip,
                            threat_type=name,
                            severity="CRITICAL",
                            description=f"Malicious signature '{name}' found in payload.",
                            packet_index=packet_index
                        ))

            # --- Rule D: ICMP Tunneling (Protocol Anomaly) ---
            if ICMP is not None and packet.haslayer(ICMP):
                if len(packet) > 1000: # Abnormally large ICMP
                    new_alerts.append(ThreatAlert(
                        timestamp=time.time(),
                        source_ip=src_ip,
                        threat_type="ICMP_TUNNEL",
                        severity="MEDIUM",
                        description=f"Oversized ICMP packet ({len(packet)} bytes) - possible tunneling.",
                        packet_index=packet_index
                    ))

        # Periodic cleanup of behavioral state to prevent memory leaks
        if time.time() - self.last_cleanup > 60:
            self._cleanup()
            
        if new_alerts:
            self.alerts.extend(new_alerts)
            
        return new_alerts

    def _track_port(self, ip: str, port: int, alerts: List[ThreatAlert]) -> None:
        """Helper to track unique ports per IP for scan detection."""
        if ip not in self.ip_port_history:
            self.ip_port_history[ip] = set()
        
        self.ip_port_history[ip].add(port)
        
        # If an IP hits more than 15 unique ports, flag as a scan
        if len(self.ip_port_history[ip]) > 15:
            # Check if we already alerted for this IP recently to avoid spam
            if not any(a.source_ip == ip and a.threat_type == "PORT_SCAN" for a in self.alerts[-10:]):
                alerts.append(ThreatAlert(
                    timestamp=time.time(),
                    source_ip=ip,
                    threat_type="PORT_SCAN",
                    severity="MEDIUM",
                    description=f"Host {ip} scanned {len(self.ip_port_history[ip])} unique ports.",
                ))

    def _cleanup(self) -> None:
        """Resets behavioral tracking state."""
        self.ip_port_history.clear()
        self.syn_count.clear()
        self.last_cleanup = time.time()

def format_threat_summary(alerts: List[ThreatAlert]) -> str:
    """Formats the threat alert list for the UI."""
    if not alerts:
        return "No threats detected. System secure."
        
    lines = [
        "Recent Threat Alerts",
        "--------------------",
        "Time     | Severity | Type         | Description"
    ]
    
    # Show last 10 alerts
    for alert in reversed(alerts[-10:]):
        t_str = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
        lines.append(f"{t_str:<8} | {alert.severity:<8} | {alert.threat_type:<12} | {alert.description}")
        
    return "\n".join(lines)
