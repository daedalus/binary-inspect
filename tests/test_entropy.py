"""Tests for EntropyAnalyzer."""

from binary_inspect.core.entropy import EntropyAnalyzer


class TestEntropyAnalyzer:
    """Test cases for EntropyAnalyzer."""

    def test_shannon_entropy_zero(self):
        """Test entropy of uniform data is low."""
        data = b"\x00" * 1000
        analyzer = EntropyAnalyzer()
        entropy = analyzer.shannon_entropy(data)
        assert entropy == 0.0

    def test_shannon_entropy_max(self):
        """Test entropy of random data is high."""
        import os

        data = os.urandom(1000)
        analyzer = EntropyAnalyzer()
        entropy = analyzer.shannon_entropy(data)
        assert entropy > 7.0

    def test_shannon_entropy_text(self):
        """Test entropy of text is medium-low."""
        data = b"AAAA" * 250  # Very repetitive
        analyzer = EntropyAnalyzer()
        entropy = analyzer.shannon_entropy(data)
        assert 0.0 <= entropy < 3.0

    def test_shannon_entropy_empty(self):
        """Test entropy of empty data."""
        data = b""
        analyzer = EntropyAnalyzer()
        entropy = analyzer.shannon_entropy(data)
        assert entropy == 0.0

    def test_byte_histogram(self):
        """Test byte frequency histogram."""
        data = b"aaabbc"
        analyzer = EntropyAnalyzer()
        hist = analyzer.byte_histogram(data)
        assert hist[ord("a")] == 3
        assert hist[ord("b")] == 2
        assert hist[ord("c")] == 1

    def test_find_high_entropy_regions(self):
        """Test finding high entropy regions."""
        import os

        # Create data with low and high entropy sections - use larger chunks
        # to ensure individual chunks reach high entropy threshold
        data = b"\x00" * 1024 + os.urandom(1024) + b"\x00" * 1024

        analyzer = EntropyAnalyzer(high_entropy_threshold=7.0)
        regions = analyzer.find_high_entropy_regions(
            data, chunk_size=256, min_length=256
        )

        # Should find at least one high entropy region
        assert len(regions) >= 1

    def test_find_high_entropy_regions_none(self):
        """Test no high entropy in uniform data."""
        data = b"\x00" * 1000
        analyzer = EntropyAnalyzer()
        regions = analyzer.find_high_entropy_regions(data)
        assert len(regions) == 0

    def test_calculate_chunk_entropies(self):
        """Test calculating chunk entropies."""
        data = b"a" * 256 + b"b" * 256
        analyzer = EntropyAnalyzer()
        entropies = analyzer.calculate_chunk_entropies(data, chunk_size=256)
        assert len(entropies) == 2
        # First two chunks should have zero entropy
        assert entropies[0][1] == 0.0
        assert entropies[1][1] == 0.0

    def test_entropy_graph(self):
        """Test generating ASCII entropy graph."""
        data = b"a" * 100 + b"\x00" * 100
        analyzer = EntropyAnalyzer()
        graph = analyzer.entropy_graph(data, chunk_size=100, width=40)
        assert "a" in graph or "0" in graph  # Should contain offset or entropy
