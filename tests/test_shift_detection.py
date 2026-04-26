import unittest
from models import RefreshSnapshot
from shift_detection import detect_shift

class TestShiftDetection(unittest.TestCase):
    def test_no_shift_on_stable_baseline(self):
        # Create a stable baseline of 15 ticks
        history = []
        for i in range(15):
            history.append(RefreshSnapshot(
                tick=i, elapsed_seconds=i*10, total_packets=i*100, new_packets=100,
                dominant_symbol="TCP", success_probability=0.8, binary_entropy_bits=0.72,
                shannon_entropy_bits=1.5, packet_rate=10.0, baseline_shannon_bits=1.5,
                baseline_packet_rate=10.0, dominant_share_delta=0.0, shift_score=0.0,
                alert_level="NONE", alert_reasons=[]
            ))
            
        # Check current tick with same values
        assessment = detect_shift(history, 1.5, 10.0, 0.8)
        self.assertEqual(assessment.level, "NONE")
        self.assertEqual(assessment.score, 0.0)

    def test_critical_flood_heuristic(self):
        history = []
        for i in range(15):
            history.append(RefreshSnapshot(
                tick=i, elapsed_seconds=i*10, total_packets=i*100, new_packets=100,
                dominant_symbol="TCP", success_probability=0.5, binary_entropy_bits=1.0,
                shannon_entropy_bits=3.0, packet_rate=10.0, baseline_shannon_bits=3.0,
                baseline_packet_rate=10.0, dominant_share_delta=0.0, shift_score=0.0,
                alert_level="NONE", alert_reasons=[]
            ))
            
        # High packet rate (50.0 vs 10.0) + Low entropy (0.5 vs 3.0)
        assessment = detect_shift(history, 0.5, 50.0, 0.9)
        self.assertEqual(assessment.level, "CRITICAL")
        self.assertTrue(any("DoS/Flood" in r for r in assessment.reasons))

if __name__ == "__main__":
    unittest.main()
