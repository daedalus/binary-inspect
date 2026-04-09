"""Tests for DataInspector."""

from binary_inspect.core.data_inspector import DataInspector


class TestDataInspector:
    """Test cases for DataInspector."""

    def test_inspect_u8(self):
        """Test inspecting unsigned 8-bit."""
        data = b"\x42"
        inspector = DataInspector()
        results = inspector.inspect(data, 0)
        u8_results = [r for r in results if r["name"] == "U8"]
        assert len(u8_results) > 0
        assert u8_results[0]["value"] == "66"

    def test_inspect_u16_le(self):
        """Test inspecting unsigned 16-bit little-endian."""
        data = b"\x34\x12"
        inspector = DataInspector(endian="little")
        results = inspector.inspect(data, 0)
        u16_results = [r for r in results if r["name"] == "U16"]
        assert len(u16_results) > 0
        assert u16_results[0]["value"] == "4660"

    def test_inspect_u32_le(self):
        """Test inspecting unsigned 32-bit little-endian."""
        data = b"\x78\x56\x34\x12"
        inspector = DataInspector(endian="little")
        results = inspector.inspect(data, 0)
        u32_results = [r for r in results if r["name"] == "U32"]
        assert len(u32_results) > 0
        assert u32_results[0]["value"] == "305419896"

    def test_inspect_ascii_string(self):
        """Test inspecting ASCII string."""
        data = b"Hello"
        inspector = DataInspector()
        results = inspector.inspect(data, 0)
        ascii_results = [r for r in results if r["name"] == "ASCII"]
        assert len(ascii_results) > 0

    def test_inspect_hex(self):
        """Test inspecting hex."""
        data = b"\xde\xad\xbe\xef"
        inspector = DataInspector()
        results = inspector.inspect(data, 0)
        hex_results = [r for r in results if r["name"] == "Hex"]
        assert len(hex_results) > 0

    def test_inspect_binary(self):
        """Test inspecting binary."""
        data = b"\x42"
        inspector = DataInspector()
        results = inspector.inspect(data, 0)
        bin_results = [r for r in results if r["name"] == "Binary"]
        assert len(bin_results) > 0

    def test_inspect_float(self):
        """Test inspecting float."""
        import struct

        data = struct.pack("<f", 3.14)
        inspector = DataInspector()
        results = inspector.inspect(data, 0)
        f32_results = [r for r in results if r["name"] == "F32"]
        assert len(f32_results) > 0

    def test_inspect_out_of_bounds(self):
        """Test inspecting beyond data."""
        data = b"\x01"
        inspector = DataInspector()
        results = inspector.inspect(data, 10)
        # Should return empty or minimal results
        assert isinstance(results, list)

    def test_inspect_multiple_interpretations(self):
        """Test that multiple interpretations are returned."""
        data = b"\x48\x65\x6c\x6c\x6f"  # "Hello"
        inspector = DataInspector()
        results = inspector.inspect(data, 0)
        # Should have multiple types (U8, ASCII, Hex, etc.)
        assert len(results) >= 3
