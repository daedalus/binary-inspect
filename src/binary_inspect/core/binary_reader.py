"""Binary reader with endianness support and type reading."""

import struct
from typing import Any


class BinaryReader:
    """Read binary data with endianness awareness."""

    def __init__(self, data: bytes, endian: str = "little"):
        """Initialize reader with binary data.

        Args:
            data: Binary data to read
            endian: 'little' or 'big' endianness
        """
        self.data = data
        self.endian = ">" if endian == "big" else "<"
        self._pos = 0

    @property
    def size(self) -> int:
        """Return total size of data."""
        return len(self.data)

    @property
    def position(self) -> int:
        """Current position in bytes."""
        return self._pos

    @position.setter
    def position(self, value: int) -> None:
        """Set position."""
        self._pos = max(0, min(value, len(self.data)))

    def read_bytes(self, size: int, offset: int | None = None) -> bytes:
        """Read raw bytes.

        Args:
            size: Number of bytes to read
            offset: Optional offset, otherwise uses current position

        Returns:
            Raw bytes read
        """
        pos = offset if offset is not None else self._pos
        if pos >= len(self.data):
            return b""
        result = self.data[pos : pos + size]
        if offset is None:
            self._pos += len(result)
        return result

    def read_u8(self, offset: int | None = None) -> int:
        """Read unsigned 8-bit integer."""
        data = self.read_bytes(1, offset)
        return struct.unpack("B", data)[0] if data else 0

    def read_s8(self, offset: int | None = None) -> int:
        """Read signed 8-bit integer."""
        data = self.read_bytes(1, offset)
        return struct.unpack("b", data)[0] if data else 0

    def read_u16(self, offset: int | None = None) -> int:
        """Read unsigned 16-bit integer."""
        data = self.read_bytes(2, offset)
        fmt = f"{self.endian}H"
        return struct.unpack(fmt, data)[0] if len(data) == 2 else 0

    def read_s16(self, offset: int | None = None) -> int:
        """Read signed 16-bit integer."""
        data = self.read_bytes(2, offset)
        fmt = f"{self.endian}h"
        return struct.unpack(fmt, data)[0] if len(data) == 2 else 0

    def read_u24(self, offset: int | None = None) -> int:
        """Read unsigned 24-bit integer."""
        data = self.read_bytes(3, offset)
        if len(data) != 3:
            return 0
        if self.endian == ">":
            return (data[0] << 16) | (data[1] << 8) | data[2]
        return data[0] | (data[1] << 8) | (data[2] << 16)

    def read_u32(self, offset: int | None = None) -> int:
        """Read unsigned 32-bit integer."""
        data = self.read_bytes(4, offset)
        fmt = f"{self.endian}I"
        return struct.unpack(fmt, data)[0] if len(data) == 4 else 0

    def read_s32(self, offset: int | None = None) -> int:
        """Read signed 32-bit integer."""
        data = self.read_bytes(4, offset)
        fmt = f"{self.endian}i"
        return struct.unpack(fmt, data)[0] if len(data) == 4 else 0

    def read_u48(self, offset: int | None = None) -> int:
        """Read unsigned 48-bit integer."""
        data = self.read_bytes(6, offset)
        if len(data) != 6:
            return 0
        if self.endian == ">":
            return int.from_bytes(data, "big")
        return int.from_bytes(data, "little")

    def read_u64(self, offset: int | None = None) -> int:
        """Read unsigned 64-bit integer."""
        data = self.read_bytes(8, offset)
        fmt = f"{self.endian}Q"
        return struct.unpack(fmt, data)[0] if len(data) == 8 else 0

    def read_s64(self, offset: int | None = None) -> int:
        """Read signed 64-bit integer."""
        data = self.read_bytes(8, offset)
        fmt = f"{self.endian}q"
        return struct.unpack(fmt, data)[0] if len(data) == 8 else 0

    def read_f32(self, offset: int | None = None) -> float:
        """Read 32-bit float."""
        data = self.read_bytes(4, offset)
        fmt = f"{self.endian}f"
        return struct.unpack(fmt, data)[0] if len(data) == 4 else 0.0

    def read_f64(self, offset: int | None = None) -> float:
        """Read 64-bit float (double)."""
        data = self.read_bytes(8, offset)
        fmt = f"{self.endian}d"
        return struct.unpack(fmt, data)[0] if len(data) == 8 else 0.0

    def read_string(
        self, size: int, offset: int | None = None, encoding: str = "utf-8"
    ) -> str:
        """Read string of fixed length.

        Args:
            size: Number of bytes to read
            offset: Optional offset
            encoding: Character encoding (utf-8, ascii, utf-16)

        Returns:
            Decoded string
        """
        data = self.read_bytes(size, offset)
        if encoding == "utf-16":
            if len(data) >= 2:
                return data.decode("utf-16-le" if self.endian == "<" else "utf-16-be")
        return data.decode(encoding, errors="replace").rstrip("\x00")

    def read_cstring(
        self, offset: int | None = None, max_size: int = 256, encoding: str = "utf-8"
    ) -> str:
        """Read null-terminated string.

        Args:
            offset: Starting offset
            max_size: Maximum bytes to read
            encoding: Character encoding

        Returns:
            String up to null terminator
        """
        pos = offset if offset is not None else self._pos
        end = pos
        while end < min(pos + max_size, len(self.data)) and self.data[end] != 0:
            end += 1
        result = self.data[pos:end].decode(encoding, errors="replace")
        if offset is None:
            self._pos = end + 1
        return result

    def read_type(self, type_name: str, offset: int | None = None) -> Any:
        """Read a value by type name.

        Args:
            type_name: Type (u8, u16, u32, s32, f32, etc.)
            offset: Optional offset

        Returns:
            Parsed value
        """
        type_map = {
            "u8": lambda: self.read_u8(offset),
            "s8": lambda: self.read_s8(offset),
            "u16": lambda: self.read_u16(offset),
            "s16": lambda: self.read_s16(offset),
            "u24": lambda: self.read_u24(offset),
            "u32": lambda: self.read_u32(offset),
            "s32": lambda: self.read_s32(offset),
            "u48": lambda: self.read_u48(offset),
            "u64": lambda: self.read_u64(offset),
            "s64": lambda: self.read_s64(offset),
            "f32": lambda: self.read_f32(offset),
            "f64": lambda: self.read_f64(offset),
        }
        if type_name not in type_map:
            raise ValueError(f"Unknown type: {type_name}")
        return type_map[type_name]()

    def get_size_of_type(self, type_name: str) -> int:
        """Get size in bytes for a type."""
        sizes = {
            "u8": 1,
            "s8": 1,
            "u16": 2,
            "s16": 2,
            "u24": 3,
            "u32": 4,
            "s32": 4,
            "u48": 6,
            "u64": 8,
            "s64": 8,
            "f32": 4,
            "f64": 8,
            "char": 1,
        }
        return sizes.get(type_name, 0)
