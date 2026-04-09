# Binary Inspect

A Python binary analysis tool for reverse engineering - detect formats, parse structures, inspect values.

[![PyPI](https://img.shields.io/pypi/v/binary-inspect.svg)](https://pypi.org/project/binary-inspect/)
[![Python](https://img.shields.io/pypi/pyversions/binary-inspect.svg)](https://pypi.org/project/binary-inspect/)

## Install

```bash
pip install binary-inspect
```

Or from source:

```bash
git clone https://github.com/daedalus/binary-inspect.git
cd binary-inspect
pip install -e ".[test]"
```

## Usage

```bash
# Analyze a binary file (auto-detect format, inspect data, calculate entropy)
binary-inspect analyze file.bin

# Detect file format using magic bytes
binary-inspect detect file.bin

# Inspect data at specific offset
binary-inspect inspect file.bin 0x100

# Calculate entropy
binary-inspect entropy file.bin

# Find strings
binary-inspect strings file.bin

# Search for hex pattern
binary-inspect search file.bin -p "4D 5A"

# Display hex dump
binary-inspect hexview file.bin

# Parse with pattern
binary-inspect parse file.bin --pattern my_format.pybip --format json -o output.json
```

## Features

- **Magic Detection**: Identify file format via header signatures (PE, ELF, PNG, ZIP, etc.)
- **Data Inspector**: Decode integers, floats, strings, GUIDs, timestamps at cursor
- **Pattern Language**: Define custom binary structures with DSL
- **Entropy Analysis**: Detect packed/encrypted sections
- **Search**: Find strings, integers, hex patterns
- **Export**: JSON, CSV, YAML output

## API

```python
from binary_inspect import (
    MagicDetector,
    DataInspector,
    EntropyAnalyzer,
    BinaryReader,
)

# Detect format
detector = MagicDetector()
match = detector.detect_one(data)
print(f"Format: {match.format_name}")

# Inspect at offset
inspector = DataInspector()
results = inspector.inspect(data, 0x100)
for r in results:
    print(f"{r['type']}: {r['value']}")

# Calculate entropy
analyzer = EntropyAnalyzer()
entropy = analyzer.shannon_entropy(data)
print(f"Entropy: {entropy:.2f}")
```

## Development

```bash
# Install dev dependencies
pip install -e ".[test]"

# Run tests
pytest

# Format
ruff format src/ tests/

# Lint
ruff check src/ tests/
```

## License

MIT