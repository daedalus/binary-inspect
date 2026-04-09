"""Core package for binary inspection."""

from .binary_reader import BinaryReader
from .data_inspector import DataInspector
from .entropy import EntropyAnalyzer, EntropyRegion
from .exporter import BinarySearch, Exporter
from .magic_detector import MagicDetector
from .models import FieldDef, MagicMatch, ParsedField, Pattern
from .pattern_parser import PatternLoader, PatternParser

__all__ = [
    "ParsedField",
    "FieldDef",
    "Pattern",
    "MagicMatch",
    "BinaryReader",
    "MagicDetector",
    "PatternParser",
    "PatternLoader",
    "DataInspector",
    "EntropyAnalyzer",
    "EntropyRegion",
    "Exporter",
    "BinarySearch",
]
