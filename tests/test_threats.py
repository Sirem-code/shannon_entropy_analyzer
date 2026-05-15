import unittest
from unittest.mock import MagicMock
from src.threats import ThreatScanner

class TestThreats(unittest.TestCase):
    def setUp(self):
        self.scanner = ThreatScanner()
        import src.capture
        if src.capture.Raw is None:
            src.capture.Raw = MagicMock(__name__='Raw')
            src.capture.IP = MagicMock(__name__='IP')
            src.capture.TCP = MagicMock(__name__='TCP')
            src.capture.UDP = MagicMock(__name__='UDP')
            src.capture.ICMP = MagicMock(__name__='ICMP')

    def test_signature_matching_shellcode(self):
        # Mock a packet with /bin/sh in payload
        packet = MagicMock()
        raw_layer = MagicMock()
        raw_layer.load = b"GET /?q=$(/bin/sh) HTTP/1.1"
        packet.haslayer.side_effect = lambda layer: layer.__name__ in ["IP", "Raw"]
        packet.getlayer.side_effect = lambda layer: raw_layer if layer.__name__ == "Raw" else MagicMock()
        
        # Manually trigger the scan logic part that handles Raw
        from src.capture import Raw, IP
        # Note: In our implementation, scanner uses haslayer(Raw)
        # and bytes(packet[Raw].load)
        packet.__getitem__.side_effect = lambda layer: raw_layer if getattr(layer, '__name__', '') == 'Raw' else MagicMock()
        
        alerts = self.scanner.scan_packet(packet, 1)
        self.assertTrue(any(a.threat_type == "SHELL_CODE" for a in alerts))

    def test_behavioral_port_scan(self):
        # Scan 20 unique ports from same IP
        from src.capture import IP, TCP
        ip = "1.2.3.4"
        for p in range(20):
            packet = MagicMock()
            packet.haslayer.side_effect = lambda l: getattr(l, '__name__', '') in ["IP", "TCP"]
            ip_mock = MagicMock()
            ip_mock.src = ip
            tcp_mock = MagicMock()
            tcp_mock.dport = p
            packet.__getitem__.side_effect = lambda l: ip_mock if getattr(l, '__name__', '') == "IP" else (tcp_mock if getattr(l, '__name__', '') == "TCP" else MagicMock())
            alerts = self.scanner.scan_packet(packet, p)
            
        self.assertTrue(any(a.threat_type == "PORT_SCAN" for a in self.scanner.alerts))

if __name__ == "__main__":
    unittest.main()
