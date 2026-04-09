"""Pattern language parser using Lark."""

from typing import Any

from lark import Lark, Transformer

from .binary_reader import BinaryReader
from .models import ParsedField

PATTERN_GRAMMAR = r"""
?start: statement+

statement: struct_def | placement

struct_def: "struct" NAME "{" field_defs "}" -> struct
          | "struct" "{" field_defs "}" -> anon_struct

field_defs: field_def*

field_def: type_spec NAME ("[" (NUMBER | NAME) "]")? ("@" expr)? ("if" expr)? ";"
         | padding
         | union_def

padding: "padding" NUMBER ";"

union_def: "union" NAME "{" field_defs "}" NAME ";"

type_spec: "u8" | "u16" | "u24" | "u32" | "u48" | "u64" | "u128"
         | "s8" | "s16" | "s32" | "s64"
         | "f32" | "f64"
         | "char" | "bool"
         | NAME

placement: type_spec NAME "@" expr ";"

expr: NAME -> var
    | NUMBER -> number
    | expr "+" expr -> add
    | expr "-" expr -> sub
    | expr "*" expr -> mul
    | "(" expr ")"
    | "EOF" -> eof

%import NAME -> NAME
%import NUMBER -> NUMBER
%import WS -> _

%ignore WS
"""


class PatternTransformer(Transformer):
    """Transform parsed pattern into structured data."""

    def struct(self, items):
        name = items[0]
        fields = items[1:] if len(items) > 1 else []
        return {"type": "struct", "name": name, "fields": fields}

    def anon_struct(self, items):
        fields = items
        return {"type": "struct", "name": None, "fields": fields}

    def field_def(self, items):
        if hasattr(items[0], "data") and items[0].data == "padding":
            return {"type": "padding", "size": items[0].children[0]}
        return {
            "type": "field",
            "name": items[1],
            "field_type": str(items[0]),
            "offset": None,
        }

    def placement(self, items):
        return {
            "type": "placement",
            "field_type": str(items[0]),
            "name": str(items[1]),
            "offset": items[2] if len(items) > 2 else None,
        }

    def padding(self, items):
        return {"type": "padding", "size": int(str(items[0]))}

    def var(self, items):
        return str(items[0])

    def number(self, items):
        val = str(items[0])
        if val.startswith("0x"):
            return int(val, 16)
        return int(val)

    def add(self, items):
        return {"op": "+", "a": items[0], "b": items[1]}

    def sub(self, items):
        return {"op": "-", "a": items[0], "b": items[1]}


class PatternParser:
    """Parse and evaluate pattern language."""

    def __init__(self):
        """Initialize parser with grammar."""
        self._parser = Lark(PATTERN_GRAMMAR, parser="lalr")
        self._structs: dict[str, list[dict[str, str]]] = {}
        self._placements: list[dict[str, str]] = []

    def parse(self, source: str) -> dict:
        """Parse pattern source code.

        Args:
            source: Pattern language source code

        Returns:
            Parsed pattern dict with structs and placements
        """
        tree = self._parser.parse(source)
        transformer = PatternTransformer()
        result = transformer.transform(tree)

        self._structs = {}
        self._placements = []

        for item in result:
            if item.get("type") == "struct":
                name = item.get("name")
                if name:
                    self._structs[name] = item.get("fields", [])
            elif item.get("type") == "placement":
                self._placements.append(item)

        return {"structs": self._structs, "placements": self._placements}

    def evaluate(self, data: bytes, endian: str = "little") -> list[ParsedField]:
        """Evaluate parsed pattern against binary data.

        Args:
            data: Binary data to parse
            endian: Endianness (little/big)

        Returns:
            List of parsed fields
        """
        reader = BinaryReader(data, endian)
        results: list[ParsedField] = []
        ctx: dict[str, int] = {}

        for placement in self._placements:
            field_type = placement.get("field_type", "")
            name = placement.get("name", "")
            offset_expr = placement.get("offset")

            if offset_expr:
                offset = self._eval_expr(offset_expr, ctx, reader)
            else:
                offset = reader.position

            value, size = self._read_value(reader, field_type, offset)

            ctx[name] = value if isinstance(value, int) else offset

            field = ParsedField(
                name=name,
                offset=offset,
                size=size,
                type_name=field_type,
                value=value,
                raw_bytes=reader.data[offset : offset + size]
                if offset < len(data)
                else b"",
            )
            results.append(field)

        return results

    def _eval_expr(self, expr: Any, ctx: dict, reader: BinaryReader) -> int:
        """Evaluate expression to get offset."""
        if isinstance(expr, int):
            return expr
        if isinstance(expr, dict):
            if expr.get("op") == "+":
                a = self._eval_expr(expr.get("a"), ctx, reader)
                b = self._eval_expr(expr.get("b"), ctx, reader)
                return a + b
            elif expr.get("op") == "-":
                a = self._eval_expr(expr.get("a"), ctx, reader)
                b = self._eval_expr(expr.get("b"), ctx, reader)
                return a - b
        if isinstance(expr, str):
            if expr in ctx:
                return ctx[expr]
            if expr == "EOF":
                return reader.size
            # Try to parse as number
            if expr.isdigit():
                return int(expr)
            if expr.startswith("0x"):
                return int(expr, 16)
        return 0

    def _read_value(
        self, reader: BinaryReader, field_type: str, offset: int
    ) -> tuple[Any, int]:
        """Read a value of given type at offset."""
        # Check if it's a known struct
        if field_type in self._structs:
            # Handle struct with children
            children = []
            size = 0
            for field in self._structs[field_type]:
                if field.get("type") == "padding":
                    size += int(field.get("size", 0))
                    continue
                child_type = field.get("field_type", "")
                child_name = field.get("name", "")
                child_val, child_size = self._read_value(
                    reader, child_type, offset + size
                )
                children.append(
                    ParsedField(
                        name=child_name,
                        offset=offset + size,
                        size=child_size,
                        type_name=child_type,
                        value=child_val,
                    )
                )
                size += child_size
            return children, size

        # Primitive type
        size = reader.get_size_of_type(field_type)
        if field_type == "char":
            # Read as string
            value = reader.read_bytes(size, offset)
            return value.decode("utf-8", errors="replace").rstrip("\x00"), size
        elif field_type == "bool":
            return bool(reader.read_u8(offset)), 1

        return reader.read_type(field_type, offset), size


class PatternLoader:
    """Load patterns from JSON .pybip files."""

    @staticmethod
    def load_json(path: str) -> dict:
        """Load pattern from JSON file."""
        import json

        with open(path) as f:
            return json.load(f)

    @staticmethod
    def save_json(pattern: dict, path: str) -> None:
        """Save pattern to JSON file."""
        import json

        with open(path, "w") as f:
            json.dump(pattern, f, indent=2)
