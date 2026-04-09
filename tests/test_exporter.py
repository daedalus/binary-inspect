"""Tests for Exporter and BinarySearch."""

from binary_inspect.core.exporter import BinarySearch, Exporter
from binary_inspect.core.models import ParsedField


class TestExporter:
    """Test cases for Exporter."""

    def test_to_json(self):
        """Test exporting to JSON."""
        fields = [
            ParsedField(
                name="magic", offset=0, size=4, type_name="u32", value=0x12345678
            ),
        ]
        exporter = Exporter()
        json_str = exporter.to_json(fields)
        assert '"magic"' in json_str
        assert '"0x12345678"' in json_str or "305419896" in json_str

    def test_to_csv(self):
        """Test exporting to CSV."""
        fields = [
            ParsedField(
                name="magic", offset=0, size=4, type_name="u32", value=0x12345678
            ),
        ]
        exporter = Exporter()
        csv_str = exporter.to_csv(fields)
        assert "Name" in csv_str
        assert "magic" in csv_str

    def test_to_yaml(self):
        """Test exporting to YAML."""
        fields = [
            ParsedField(
                name="magic", offset=0, size=4, type_name="u32", value=0x12345678
            ),
        ]
        exporter = Exporter()
        yaml_str = exporter.to_yaml(fields)
        assert "magic" in yaml_str


class TestBinarySearch:
    """Test cases for BinarySearch."""

    def test_find_strings(self):
        """Test finding ASCII strings."""
        data = b"Hello\x00World\x00Test"
        searcher = BinarySearch(data)
        results = searcher.find_strings(min_length=3)
        assert len(results) >= 2

    def test_find_strings_min_length(self):
        """Test minimum string length filter."""
        data = b"ab\x00cd\x00"
        searcher = BinarySearch(data)
        results = searcher.find_strings(min_length=3)
        assert len(results) == 0

    def test_find_bytes(self):
        """Test finding byte pattern."""
        data = b"\x00\x01\x02\x03\x00\x01\x02\x03"
        searcher = BinarySearch(data)
        results = searcher.find_bytes(b"\x01\x02")
        assert len(results) == 2

    def test_find_hex_pattern(self):
        """Test finding hex pattern."""
        data = b"\xde\xad\xbe\xef\xde\xad\xbe\xef"
        searcher = BinarySearch(data)
        results = searcher.find_hex_pattern("DE AD")
        assert len(results) == 2

    def test_find_integers(self):
        """Test finding integer values."""
        import struct

        # Create data with u32 value 0x12345678 in little-endian
        data = struct.pack("<I", 0x12345678) * 2
        searcher = BinarySearch(data)
        results = searcher.find_integers(0x12345678, endian="little")
        assert len(results["u32"]) == 2
