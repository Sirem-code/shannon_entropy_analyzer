import unittest
from unittest.mock import MagicMock
from threats import ThreatScanner

class TestThreats(unittest.TestCase):
    def setUp(self):
        self.scanner = ThreatScanner()

    def test_signature_matching_shellcode(self):
        # Mock a packet with /bin/sh in payload
        packet = MagicMock()
        raw_layer = MagicMock()
        raw_layer.load = b"GET /?q=$(/bin/sh) HTTP/1.1"
        packet.haslayer.side_effect = lambda layer: layer.__name__ in ["IP", "Raw"]
        packet.getlayer.side_effect = lambda layer: raw_layer if layer.__name__ == "Raw" else MagicMock()
        
        # Manually trigger the scan logic part that handles Raw
        from capture import Raw, IP
        # Note: In our implementation, scanner uses haslayer(Raw)
        # and bytes(packet[Raw].load)
        packet.__getitem__.side_effect = lambda layer: raw_layer if layer == Raw else MagicMock()
        
        alerts = self.scanner.scan_packet(packet, 1)
        self.assertTrue(any(a.threat_type == "SHELL_CODE" for a in alerts))

    def test_behavioral_port_scan(self):
        # Scan 20 unique ports from same IP
        from capture import IP, TCP
        ip = "1.2.3.4"
        for p in range(20):
            packet = MagicMock()
            packet.haslayer.side_effect = lambda l: l in [IP, TCP]
            packet[IP].src = ip
            packet[TCP].dport = p
            alerts = self.scanner.scan_packet(packet, p)
            
        self.assertTrue(any(a.threat_type == "PORT_SCAN" for a in self.scanner.alerts))

if __name__ == "__main__":
    unittest.main()
