import unittest
from analysis import compute_shannon_entropy, to_bernoulli_from_symbol_stream

class TestAnalysis(unittest.TestCase):
    def test_shannon_entropy_balanced(self):
        # Two symbols, equal probability -> 1.0 bit
        symbols = ["A", "B"] * 50
        result = compute_shannon_entropy(symbols)
        self.assertAlmostEqual(result.entropy_bits, 1.0)
        self.assertEqual(result.symbol_count, 2)
        self.assertEqual(result.sample_count, 100)

    def test_shannon_entropy_monoculture(self):
        # One symbol -> 0.0 bits
        symbols = ["A"] * 100
        result = compute_shannon_entropy(symbols)
        self.assertAlmostEqual(result.entropy_bits, 0.0)

    def test_shannon_entropy_empty(self):
        # Empty list -> 0.0 bits (safely handled)
        result = compute_shannon_entropy([])
        self.assertEqual(result.entropy_bits, 0.0)

    def test_bernoulli_conversion(self):
        symbols = ["TCP", "UDP", "TCP", "TCP"]
        # Projection for "TCP"
        sequence = to_bernoulli_from_symbol_stream(symbols, "TCP")
        self.assertEqual(sequence, [1, 0, 1, 1])

if __name__ == "__main__":
    unittest.main()
