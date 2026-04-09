"""Data inspector for real-time value decoding at cursor position."""

import datetime
import struct
import uuid
from typing import Any


class DataInspector:
    """Decode binary data at cursor position with multiple interpretations."""

    def __init__(self, endian: str = "little"):
        """Initialize inspector.

        Args:
            endian: Default endianness (little/big)
        """
        self.endian = "<" if endian == "little" else ">"
        self._inspectors = [
            self._inspect_u8,
            self._inspect_s8,
            self._inspect_u16,
            self._inspect_s16,
            self._inspect_u24,
            self._inspect_u32,
            self._inspect_s32,
            self._inspect_u64,
            self._inspect_s64,
            self._inspect_f32,
            self._inspect_f64,
            self._inspect_ascii,
            self._inspect_utf8,
            self._inspect_utf16,
            self._inspect_unix_time,
            self._inspect_filetime,
            self._inspect_guid,
            self._inspect_hex,
            self._inspect_binary,
        ]

    def inspect(self, data: bytes, offset: int = 0) -> list[dict[str, Any]]:
        """Inspect data at offset and return all interpretations.

        Args:
            data: Binary data
            offset: Offset to inspect

        Returns:
            List of inspection results
        """
        results = []
        for inspector in self._inspectors:
            try:
                result = inspector(data, offset)
                if result:
                    results.append(result)
            except Exception:
                continue
        return results

    def _make_result(
        self, name: str, value: str, type_name: str, size: int, raw: bytes
    ) -> dict:
        """Create inspection result dict."""
        return {
            "name": name,
            "value": value,
            "type": type_name,
            "size": size,
            "raw": raw.hex() if raw else "",
        }

    def _inspect_u8(self, data: bytes, offset: int) -> dict | None:
        if offset >= len(data):
            return None
        val = data[offset]
        return self._make_result("U8", str(val), "unsigned", 1, bytes([val]))

    def _inspect_s8(self, data: bytes, offset: int) -> dict | None:
        if offset >= len(data):
            return None
        val = struct.unpack("b", bytes([data[offset]]))[0]
        return self._make_result("S8", str(val), "signed", 1, bytes([val]))

    def _inspect_u16(self, data: bytes, offset: int) -> dict | None:
        if offset + 2 > len(data):
            return None
        raw = data[offset : offset + 2]
        val = struct.unpack(f"{self.endian}H", raw)[0]
        return self._make_result("U16", str(val), "unsigned", 2, raw)

    def _inspect_s16(self, data: bytes, offset: int) -> dict | None:
        if offset + 2 > len(data):
            return None
        raw = data[offset : offset + 2]
        val = struct.unpack(f"{self.endian}h", raw)[0]
        return self._make_result("S16", str(val), "signed", 2, raw)

    def _inspect_u24(self, data: bytes, offset: int) -> dict | None:
        if offset + 3 > len(data):
            return None
        raw = data[offset : offset + 3]
        if self.endian == "<":
            val = raw[0] | (raw[1] << 8) | (raw[2] << 16)
        else:
            val = (raw[0] << 16) | (raw[1] << 8) | raw[2]
        return self._make_result("U24", str(val), "unsigned", 3, raw)

    def _inspect_u32(self, data: bytes, offset: int) -> dict | None:
        if offset + 4 > len(data):
            return None
        raw = data[offset : offset + 4]
        val = struct.unpack(f"{self.endian}I", raw)[0]
        return self._make_result("U32", str(val), "unsigned", 4, raw)

    def _inspect_s32(self, data: bytes, offset: int) -> dict | None:
        if offset + 4 > len(data):
            return None
        raw = data[offset : offset + 4]
        val = struct.unpack(f"{self.endian}i", raw)[0]
        return self._make_result("S32", str(val), "signed", 4, raw)

    def _inspect_u64(self, data: bytes, offset: int) -> dict | None:
        if offset + 8 > len(data):
            return None
        raw = data[offset : offset + 8]
        val = struct.unpack(f"{self.endian}Q", raw)[0]
        return self._make_result("U64", str(val), "unsigned", 8, raw)

    def _inspect_s64(self, data: bytes, offset: int) -> dict | None:
        if offset + 8 > len(data):
            return None
        raw = data[offset : offset + 8]
        val = struct.unpack(f"{self.endian}q", raw)[0]
        return self._make_result("S64", str(val), "signed", 8, raw)

    def _inspect_f32(self, data: bytes, offset: int) -> dict | None:
        if offset + 4 > len(data):
            return None
        raw = data[offset : offset + 4]
        val = struct.unpack(f"{self.endian}f", raw)[0]
        if val != val:  # NaN check
            return None
        return self._make_result("F32", f"{val:.6f}", "float", 4, raw)

    def _inspect_f64(self, data: bytes, offset: int) -> dict | None:
        if offset + 8 > len(data):
            return None
        raw = data[offset : offset + 8]
        val = struct.unpack(f"{self.endian}d", raw)[0]
        if val != val:
            return None
        return self._make_result("F64", f"{val:.10f}", "float", 8, raw)

    def _inspect_ascii(self, data: bytes, offset: int) -> dict | None:
        if offset >= len(data):
            return None
        # Try to read up to 16 printable ASCII chars
        end = offset
        while end < min(offset + 16, len(data)) and 32 <= data[end] < 127:
            end += 1
        if end == offset:
            return None
        raw = data[offset:end]
        val = raw.decode("ascii", errors="replace")
        return self._make_result("ASCII", repr(val), "string", len(raw), raw)

    def _inspect_utf8(self, data: bytes, offset: int) -> dict | None:
        if offset >= len(data):
            return None
        # Try to decode as UTF-8
        try:
            end = offset
            while end < min(offset + 32, len(data)):
                if data[end] == 0:
                    break
                end += 1
            raw = data[offset:end]
            val = raw.decode("utf-8")
            # Only show if it has some valid content
            if len(val.strip("\x00")) > 0:
                return self._make_result(
                    "UTF-8", repr(val[:16]), "string", len(raw), raw
                )
        except UnicodeDecodeError:
            pass
        return None

    def _inspect_utf16(self, data: bytes, offset: int) -> dict | None:
        if offset + 2 > len(data):
            return None
        try:
            raw = data[offset : offset + 32]
            if self.endian == "<":
                val = raw.decode("utf-16-le")
            else:
                val = raw.decode("utf-16-be")
            val = val.rstrip("\x00")
            if len(val) > 0:
                return self._make_result(
                    "UTF-16", repr(val[:16]), "string", len(raw), raw
                )
        except UnicodeDecodeError:
            pass
        return None

    def _inspect_unix_time(self, data: bytes, offset: int) -> dict | None:
        if offset + 4 > len(data):
            return None
        raw = data[offset : offset + 4]
        val = struct.unpack(f"{self.endian}I", raw)[0]
        try:
            dt = datetime.datetime.fromtimestamp(val, tz=datetime.UTC)
            return self._make_result("Unix Time", str(dt), "timestamp", 4, raw)
        except (ValueError, OSError):
            return None

    def _inspect_filetime(self, data: bytes, offset: int) -> dict | None:
        if offset + 8 > len(data):
            return None
        raw = data[offset : offset + 8]
        val = struct.unpack(f"{self.endian}Q", raw)[0]
        # Windows FILETIME: 100-nanosecond intervals since Jan 1, 1601
        if val == 0:
            return None
        try:
            # Convert to Unix timestamp
            unix_ts = (val - 116444736000000000) / 10000000
            dt = datetime.datetime.fromtimestamp(unix_ts, tz=datetime.UTC)
            return self._make_result("FILETIME", str(dt), "timestamp", 8, raw)
        except (ValueError, OSError):
            return None

    def _inspect_guid(self, data: bytes, offset: int) -> dict | None:
        if offset + 16 > len(data):
            return None
        raw = data[offset : offset + 16]
        try:
            # GUID stored as bytes - try to parse as UUID
            u = uuid.UUID(bytes=raw)
            return self._make_result("GUID", str(u), "uuid", 16, raw)
        except ValueError:
            pass
        return None

    def _inspect_hex(self, data: bytes, offset: int) -> dict | None:
        if offset >= len(data):
            return None
        # Show hex of first 8 bytes
        raw = data[offset : offset + 8]
        if not raw:
            return None
        val = " ".join(f"{b:02X}" for b in raw)
        return self._make_result("Hex", val, "hex", len(raw), raw)

    def _inspect_binary(self, data: bytes, offset: int) -> dict | None:
        if offset >= len(data):
            return None
        val = data[offset]
        bin_str = bin(val)[2:].zfill(8)
        return self._make_result("Binary", bin_str, "binary", 1, bytes([val]))
