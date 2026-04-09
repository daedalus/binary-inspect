"""Entropy analysis for detecting packed/encrypted sections."""

import math
from dataclasses import dataclass


@dataclass
class EntropyRegion:
    """Region with entropy data."""

    start: int
    end: int
    entropy: float
    is_high_entropy: bool


class EntropyAnalyzer:
    """Calculate Shannon entropy and detect high-entropy regions."""

    def __init__(self, high_entropy_threshold: float = 7.0):
        """Initialize analyzer.

        Args:
            high_entropy_threshold: Entropy level above which data is considered high-entropy
        """
        self.high_entropy_threshold = high_entropy_threshold

    def shannon_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy (0-8 bits).

        Args:
            data: Binary data to analyze

        Returns:
            Entropy in bits (0 = no entropy, 8 = max entropy)
        """
        if not data:
            return 0.0

        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        # Calculate entropy
        entropy = 0.0
        length = len(data)
        for count in freq:
            if count == 0:
                continue
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def byte_histogram(self, data: bytes) -> dict[int, int]:
        """Calculate byte frequency histogram.

        Args:
            data: Binary data to analyze

        Returns:
            Dict mapping byte value to frequency
        """
        hist: dict[int, int] = {}
        for byte in data:
            hist[byte] = hist.get(byte, 0) + 1
        return hist

    def find_high_entropy_regions(
        self,
        data: bytes,
        chunk_size: int = 256,
        min_length: int = 16,
    ) -> list[EntropyRegion]:
        """Find regions of high entropy (packed/encrypted).

        Args:
            data: Binary data to analyze
            chunk_size: Size of chunks to analyze
            min_length: Minimum region length

        Returns:
            List of high-entropy regions
        """
        regions = []
        i = 0

        while i < len(data):
            chunk = data[i : i + chunk_size]
            if not chunk:
                break

            entropy = self.shannon_entropy(chunk)

            if entropy >= self.high_entropy_threshold:
                # Start of high-entropy region
                start = i
                # Extend region
                while i < len(data):
                    chunk = data[i : i + chunk_size]
                    if not chunk:
                        break
                    if self.shannon_entropy(chunk) >= self.high_entropy_threshold:
                        i += chunk_size
                    else:
                        break
                end = min(i, len(data))
                if end - start >= min_length:
                    regions.append(
                        EntropyRegion(
                            start=start,
                            end=end,
                            entropy=entropy,
                            is_high_entropy=True,
                        )
                    )
            else:
                i += chunk_size

        return regions

    def calculate_chunk_entropies(
        self,
        data: bytes,
        chunk_size: int = 256,
    ) -> list[tuple[int, float]]:
        """Calculate entropy for each chunk.

        Args:
            data: Binary data to analyze
            chunk_size: Size of chunks

        Returns:
            List of (offset, entropy) tuples
        """
        result = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i : i + chunk_size]
            if chunk:
                entropy = self.shannon_entropy(chunk)
                result.append((i, entropy))
        return result

    def entropy_graph(
        self,
        data: bytes,
        chunk_size: int = 256,
        width: int = 80,
    ) -> str:
        """Generate ASCII entropy graph.

        Args:
            data: Binary data to analyze
            chunk_size: Size of chunks
            width: Width of graph in characters

        Returns:
            ASCII graph string
        """
        entropies = self.calculate_chunk_entropies(data, chunk_size)
        if not entropies:
            return ""

        # Scale to width
        max_entropy = 8.0
        result = []
        for offset, entropy in entropies:
            bar_len = int((entropy / max_entropy) * width)
            bar = "#" * bar_len + "-" * (width - bar_len)
            result.append(f"{offset:08X} [{entropy:5.2f}] {bar}")

        return "\n".join(result)
