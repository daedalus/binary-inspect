"""Tests for BinaryReader."""

from binary_inspect.core.binary_reader import BinaryReader


class TestBinaryReader:
    """Test cases for BinaryReader."""

    def test_read_u8(self):
        """Test reading unsigned 8-bit integer."""
        data = b"\x42\x00\xff"
        reader = BinaryReader(data)
        assert reader.read_u8() == 0x42
        assert reader.read_u8() == 0x00
        assert reader.read_u8() == 0xFF

    def test_read_u16_le(self):
        """Test reading unsigned 16-bit integer little-endian."""
        data = b"\x34\x12"
        reader = BinaryReader(data, endian="little")
        assert reader.read_u16() == 0x1234

    def test_read_u16_be(self):
        """Test reading unsigned 16-bit integer big-endian."""
        data = b"\x12\x34"
        reader = BinaryReader(data, endian="big")
        assert reader.read_u16() == 0x1234

    def test_read_u32_le(self):
        """Test reading unsigned 32-bit integer little-endian."""
        data = b"\x78\x56\x34\x12"
        reader = BinaryReader(data, endian="little")
        assert reader.read_u32() == 0x12345678

    def test_read_u32_be(self):
        """Test reading unsigned 32-bit integer big-endian."""
        data = b"\x12\x34\x56\x78"
        reader = BinaryReader(data, endian="big")
        assert reader.read_u32() == 0x12345678

    def test_read_s32_negative(self):
        """Test reading signed 32-bit negative integer."""
        data = b"\xff\xff\xff\xff"
        reader = BinaryReader(data, endian="little")
        assert reader.read_s32() == -1

    def test_read_f32(self):
        """Test reading 32-bit float."""
        import struct

        data = struct.pack("<f", 3.14159)
        reader = BinaryReader(data, endian="little")
        val = reader.read_f32()
        assert abs(val - 3.14159) < 0.001

    def test_read_f64(self):
        """Test reading 64-bit float."""
        import struct

        data = struct.pack("<d", 3.14159265359)
        reader = BinaryReader(data, endian="little")
        val = reader.read_f64()
        assert abs(val - 3.14159265359) < 0.00000000001

    def test_read_cstring(self):
        """Test reading null-terminated string."""
        data = b"Hello\x00World"
        reader = BinaryReader(data)
        assert reader.read_cstring() == "Hello"

    def test_read_string_fixed_length(self):
        """Test reading fixed-length string."""
        data = b"Test\x00\x00\x00\x00"
        reader = BinaryReader(data)
        assert reader.read_string(8) == "Test"

    def test_read_at_offset(self):
        """Test reading at specific offset."""
        data = b"\x00\x00\x00\x00\xaa\xbb\xcc\xdd"
        reader = BinaryReader(data)
        assert reader.read_u32(offset=4) == 0xDDCCBBAA

    def test_position_tracking(self):
        """Test position tracking."""
        data = b"\x01\x02\x03\x04"
        reader = BinaryReader(data)
        assert reader.position == 0
        reader.read_u8()
        assert reader.position == 1
        reader.read_u16()
        assert reader.position == 3

    def test_out_of_bounds(self):
        """Test reading beyond data bounds."""
        data = b"\x01\x02"
        reader = BinaryReader(data)
        # Should return 0 for out of bounds
        assert reader.read_u32() == 0

    def test_get_size_of_type(self):
        """Test type size lookup."""
        reader = BinaryReader(b"")
        assert reader.get_size_of_type("u8") == 1
        assert reader.get_size_of_type("u16") == 2
        assert reader.get_size_of_type("u32") == 4
        assert reader.get_size_of_type("u64") == 8
        assert reader.get_size_of_type("f32") == 4
        assert reader.get_size_of_type("f64") == 8
