"""Binary Inspector - A Python binary analysis tool for reverse engineering."""

__version__ = "0.1.0"

from .core.binary_reader import BinaryReader
from .core.data_inspector import DataInspector
from .core.entropy import EntropyAnalyzer
from .core.exporter import BinarySearch, Exporter
from .core.magic_detector import MagicDetector
from .core.models import ParsedField, Pattern
from .core.pattern_parser import PatternParser

__all__ = [
    "__version__",
    "BinaryReader",
    "MagicDetector",
    "PatternParser",
    "DataInspector",
    "EntropyAnalyzer",
    "Exporter",
    "BinarySearch",
    "ParsedField",
    "Pattern",
]
