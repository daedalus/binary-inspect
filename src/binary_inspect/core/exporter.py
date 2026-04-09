"""Export parsed binary data to various formats."""

import csv
import json
from io import StringIO
from typing import Any

from .models import ParsedField


class Exporter:
    """Export parsed binary data to JSON, CSV, or YAML."""

    def __init__(self):
        """Initialize exporter."""
        pass

    def to_json(self, fields: list[ParsedField], indent: int = 2) -> str:
        """Export to JSON format.

        Args:
            fields: List of parsed fields
            indent: JSON indentation

        Returns:
            JSON string
        """
        data = [field.to_dict() for field in fields]
        return json.dumps(data, indent=indent, default=str)

    def to_csv(self, fields: list[ParsedField]) -> str:
        """Export to CSV format.

        Args:
            fields: List of parsed fields

        Returns:
            CSV string
        """
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["Name", "Offset", "Size", "Type", "Value"])

        for field in fields:
            writer.writerow(
                [
                    field.name,
                    f"0x{field.offset:08X}",
                    field.size,
                    field.type_name,
                    str(field.value)[:100],
                ]
            )
            # Write children
            for child in field.children:
                writer.writerow(
                    [
                        f"  {child.name}",
                        f"0x{child.offset:08X}",
                        child.size,
                        child.type_name,
                        str(child.value)[:100],
                    ]
                )

        return output.getvalue()

    def to_yaml(self, fields: list[ParsedField]) -> str:
        """Export to YAML format.

        Args:
            fields: List of parsed fields

        Returns:
            YAML string
        """
        data = [field.to_dict() for field in fields]
        return self._dict_to_yaml(data, 0)

    def _dict_to_yaml(self, data: Any, indent: int) -> str:
        """Convert dict to YAML string."""
        lines = []
        prefix = "  " * indent

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    lines.append(f"{prefix}-")
                    lines.append(self._dict_to_yaml(item, indent + 1))
                else:
                    lines.append(f"{prefix}- {item}")
        elif isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    lines.append(f"{prefix}{key}:")
                    lines.append(self._dict_to_yaml(value, indent + 1))
                else:
                    lines.append(f"{prefix}{key}: {value}")
        else:
            lines.append(f"{prefix}{data}")

        return "\n".join(lines)

    def save_json(self, fields: list[ParsedField], path: str) -> None:
        """Save to JSON file.

        Args:
            fields: List of parsed fields
            path: Output file path
        """
        with open(path, "w") as f:
            f.write(self.to_json(fields))

    def save_csv(self, fields: list[ParsedField], path: str) -> None:
        """Save to CSV file.

        Args:
            fields: List of parsed fields
            path: Output file path
        """
        with open(path, "w", newline="") as f:
            f.write(self.to_csv(fields))

    def save_yaml(self, fields: list[ParsedField], path: str) -> None:
        """Save to YAML file.

        Args:
            fields: List of parsed fields
            path: Output file path
        """
        with open(path, "w") as f:
            f.write(self.to_yaml(fields))


class BinarySearch:
    """Search for patterns in binary data."""

    def __init__(self, data: bytes):
        """Initialize search.

        Args:
            data: Binary data to search
        """
        self.data = data

    def find_strings(
        self,
        min_length: int = 4,
        encoding: str = "utf-8",
    ) -> list[dict[str, Any]]:
        """Find ASCII/UTF-8 strings.

        Args:
            min_length: Minimum string length
            encoding: String encoding

        Returns:
            List of found strings with offset
        """
        results = []
        current = []
        start_offset = 0

        for i, byte in enumerate(self.data):
            if 32 <= byte < 127:
                if not current:
                    start_offset = i
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    results.append(
                        {
                            "offset": start_offset,
                            "string": "".join(current),
                            "length": len(current),
                            "encoding": "ascii",
                        }
                    )
                current = []

        # Check end
        if len(current) >= min_length:
            results.append(
                {
                    "offset": start_offset,
                    "string": "".join(current),
                    "length": len(current),
                    "encoding": "ascii",
                }
            )

        return results

    def find_bytes(self, pattern: bytes) -> list[int]:
        """Find all occurrences of bytes.

        Args:
            pattern: Pattern to find

        Returns:
            List of offsets
        """
        results = []
        start = 0
        while True:
            pos = self.data.find(pattern, start)
            if pos == -1:
                break
            results.append(pos)
            start = pos + 1
        return results

    def find_hex_pattern(self, hex_str: str) -> list[int]:
        """Find hex pattern.

        Args:
            hex_str: Hex string (e.g., "4D 5A" or "4D5A" or "4d5a")

        Returns:
            List of offsets
        """
        # Normalize hex string
        hex_str = hex_str.replace(" ", "").replace("0x", "")
        pattern = bytes.fromhex(hex_str)
        return self.find_bytes(pattern)

    def find_integers(
        self,
        value: int,
        endian: str = "little",
    ) -> dict[str, list[int]]:
        """Find integer value.

        Args:
            value: Integer to find
            endian: Endianness

        Returns:
            Dict with found sizes and offsets
        """
        import struct

        results = {"u8": [], "u16": [], "u32": [], "u64": []}

        # Search for various sizes - skip u8 if value > 255
        sizes_to_try = []
        if 0 <= value <= 255:
            sizes_to_try.append((1, "B"))
        if 0 <= value <= 0xFFFF:
            sizes_to_try.append((2, f"{'<' if endian == 'little' else '>'}H"))
        if 0 <= value <= 0xFFFFFFFF:
            sizes_to_try.append((4, f"{'<' if endian == 'little' else '>'}I"))
        sizes_to_try.append((8, f"{'<' if endian == 'little' else '>'}Q"))

        for size, fmt in sizes_to_try:
            packed = struct.pack(fmt, value)
            pos = 0
            while True:
                pos = self.data.find(packed, pos)
                if pos == -1:
                    break
                type_name = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}[size]
                results[type_name].append(pos)
                pos += 1

        return results
