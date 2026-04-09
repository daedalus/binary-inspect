"""Core data models for binary inspection."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParsedField:
    """Represents a parsed field from a binary structure."""

    name: str
    offset: int
    size: int
    type_name: str
    value: Any
    children: list["ParsedField"] = field(default_factory=list)
    raw_bytes: bytes = b""

    def to_dict(self) -> dict:
        """Convert to dictionary for export."""
        result = {
            "name": self.name,
            "offset": self.offset,
            "size": self.size,
            "type": self.type_name,
            "value": self._serialize_value(self.value),
        }
        if self.children:
            result["children"] = [c.to_dict() for c in self.children]
        return result

    @staticmethod
    def _serialize_value(val: Any) -> Any:
        """Serialize value to JSON-compatible type."""
        if isinstance(val, bytes):
            return val.hex()
        if isinstance(val, list):
            return [ParsedField._serialize_value(v) for v in val]
        if isinstance(val, ParsedField):
            return val.to_dict()
        return val


@dataclass
class FieldDef:
    """Definition of a field in a pattern."""

    name: str
    field_type: str
    offset_expr: str | None = None
    count: str | None = None
    element_type: dict | None = None
    condition: str | None = None


@dataclass
class Pattern:
    """Binary format pattern definition."""

    name: str
    fields: list[FieldDef]
    magic: bytes | None = None
    description: str = ""
    endian: str = "little"


@dataclass
class MagicMatch:
    """Result of a magic byte detection."""

    format_name: str
    confidence: float
    magic_bytes: bytes
    description: str = ""
