from __future__ import annotations

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
    if conf is None:
        return "unknown"
    return str(conf.iface)


def packet_to_symbol(packet: Any) -> str:
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
