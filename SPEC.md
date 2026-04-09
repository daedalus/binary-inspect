# Binary Inspector - Specification

## Project Overview

- **Project Name:** Binary Inspector
- **Type:** Python CLI/GUI Tool for Binary Analysis
- **Core Functionality:** Analyze unknown binary files to automatically detect format, extract fields, display structured values with tree view and hex navigation
- **Target Users:** Security researchers, malware analysts, CTF players, software archaeologists, developers working with proprietary file formats

---

## Feature Specification

### 1. Magic Bytes Detection

- Detect file format via header signatures (magic bytes)
- Support for common formats: PE, ELF, Mach-O, ZIP, PNG, JPEG, PDF, GIF, TAR, ISO, ROM
- User-defined custom magic signatures
- Display confidence score for matches

### 2. Auto-field Detection

- Analyze binary patterns to guess field sizes (u8, u16, u32, u64)
- Detect endianness (little-endian vs big-endian)
- Identify common patterns: null-terminated strings, padding, arrays
- Suggest field boundaries based on repetition

### 3. Data Inspector

- Decode integers (signed/unsigned, 8/16/32/64 bit)
- Decode floats (float32, float64)
- Decode strings (ASCII, UTF-8, UTF-16, null-terminated)
- Decode GUIDs/UUIDs
- Decode timestamps (Unix, Windows FILETIME, ISO 8601)
- Display multiple interpretations simultaneously

### 4. Pattern Language (DSL)

Define custom binary structures:

```
struct Header {
    u32 magic;
    u32 version;
    u32 entryCount;
    Entry entries[entryCount] @ 0x10;
};

struct Entry {
    u32 offset;
    u32 size;
    char name[32];
};

Header header @ 0x0;
```

Supported constructs:
- Primitives: u8, u16, u24, u32, u48, u64, u128, s8, s16, s32, s64, f32, f64
- Arrays: type name[count] or type name[variable_count]
- Strings: char name[length] or char name[EOF]
- Structs/ Unions
- Bitfields: field : bits
- Pointers: type name @ offset_expr
- Enums
- Padding/alignment

### 5. Tree View

- Hierarchical display of parsed fields
- Columns: Name, Offset, Size, Type, Value
- Expand/collapse nested structures
- Click to navigate to byte offset
- Filter by name, value, or offset range

### 6. Hex Editor View

- Raw byte view (address, hex, ASCII)
- Highlight parsed regions with colors
- Synchronized cursor with tree view
- Navigate to offset from tree selection

### 7. Format Library

- Built-in patterns for common formats (PE, ELF, PNG, ZIP, etc.)
- User-defined pattern storage
- Pattern import/export (.pybip files)
- Pattern marketplace/community patterns

### 8. Export

- JSON output with full structure
- CSV export for spreadsheet analysis
- YAML output for interoperability
- C/C++ header generation from patterns

### 9. Search

- Find strings (with encoding selection)
- Find integers (exact value or range)
- Find hex patterns (with wildcards)
- Find pattern matches in data

### 10. Entropy Analysis

- Byte frequency histogram
- Shannon entropy graph
- Highlight high-entropy (packed/encrypted) regions
- Overlay entropy on hex view

### 11. Visualizers (Nice-to-have)

- Image preview (PNG, JPEG, BMP, GIF)
- Audio playback (WAV, MP3 raw)
- 3D data visualization for point clouds

### 12. Binary Diff (Nice-to-have)

- Side-by-side comparison
- Byte-level and structure-level diff
- Highlight added/removed/modified regions

### 13. Scripting (Nice-to-have)

- Python scripting for automation
- Load custom parsers at runtime
- Batch processing support

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Binary Inspector                         │
├─────────────────────────────────────────────────────────────┤
│  CLI Interface / GUI (Rich/Tkinter)                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ Magic       │  │ Pattern     │  │ Data Inspector      │ │
│  │ Detection   │  │ Matcher     │  │ (Real-time decode)  │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              Pattern Language Engine                  │  │
│  │   - Lexer/Parser (Lark)                               │  │
│  │   - Evaluator                                        │  │
│  │   - Type system                                      │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ Tree View   │  │ Hex Editor  │  │ Export (JSON/CSV)   │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              Format Library (Built-in + User)        │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Core Components

1. **BinaryReader** - Read bytes with endianness awareness
2. **MagicDetector** - Signature matching for format detection
3. **PatternParser** - Parse DSL using Lark grammar
4. **PatternEvaluator** - Execute patterns against binary
5. **DataInspector** - Multi-format value decoding
6. **EntropyAnalyzer** - Byte distribution analysis
7. **Exporter** - JSON/CSV/YAML output generation
8. **CLI/GUI** - User interface layer

---

## Data Structures

### ParsedField

```python
@dataclass
class ParsedField:
    name: str
    offset: int
    size: int
    type_name: str
    value: Any
    children: List['ParsedField']
    raw_bytes: bytes
```

### Pattern

```python
@dataclass
class Pattern:
    name: str
    fields: List[FieldDef]
    magic: Optional[bytes]
    description: str
```

### FieldDef

```python
@dataclass
class FieldDef:
    name: str
    field_type: Union[PrimitiveType, StructType, ArrayType, UnionType, BitfieldType]
    offset_expr: Optional[str]
    condition: Optional[str]
```

---

## Supported Types

| Type | Size | Description |
|------|------|-------------|
| u8 | 1 | unsigned 8-bit integer |
| u16 | 2 | unsigned 16-bit integer |
| u24 | 3 | unsigned 24-bit integer |
| u32 | 4 | unsigned 32-bit integer |
| u48 | 6 | unsigned 48-bit integer |
| u64 | 8 | unsigned 64-bit integer |
| u128 | 16 | unsigned 128-bit integer |
| s8 | 1 | signed 8-bit integer |
| s16 | 2 | signed 16-bit integer |
| s32 | 4 | signed 32-bit integer |
| s64 | 8 | signed 64-bit integer |
| f32 | 4 | 32-bit float |
| f64 | 8 | 64-bit float (double) |
| char | 1 | character |

---

## CLI Usage

```bash
# Analyze a binary file
binary-inspector analyze file.bin

# Auto-detect format
binary-inspector detect file.bin

# Apply a pattern
binary-inspector parse file.bin --pattern my_format.pybip

# Export to JSON
binary-inspector export file.bin --format json --output result.json

# Search for strings
binary-inspector search file.bin --strings

# Calculate entropy
binary-inspector entropy file.bin

# Interactive mode
binary-inspector interactive file.bin
```

---

## Pattern File Format (.pybip)

JSON-based pattern definition:

```json
{
  "name": "MyFormat",
  "magic": "4D594F00",
  "description": "My custom binary format",
  "endian": "little",
  "fields": [
    {
      "name": "magic",
      "type": "u32",
      "offset": "0x00",
      "value": "0x004F594D"
    },
    {
      "name": "version",
      "type": "u16",
      "offset": "0x04"
    },
    {
      "name": "entryCount",
      "type": "u32",
      "offset": "0x06"
    },
    {
      "name": "entries",
      "type": "array",
      "count": "entryCount",
      "elementType": {
        "type": "struct",
        "fields": [
          {"name": "offset", "type": "u32"},
          {"name": "size", "type": "u32"},
          {"name": "name", "type": "char[32]"}
        ]
      },
      "offset": "0x10"
    }
  ]
}
```

---

## Acceptance Criteria

1. **Magic Detection**: Tool correctly identifies PE, ELF, PNG, ZIP files from magic bytes
2. **Pattern Parsing**: DSL parses valid patterns without errors
3. **Tree View**: Displays parsed structure with name, offset, size, type, value
4. **Data Inspector**: Shows all integer/float/string interpretations at cursor
5. **Export**: Produces valid JSON/CSV with full structure
6. **Search**: Finds strings and patterns in binary
7. **Entropy**: Shows byte distribution with highlighted regions
8. **Pattern Library**: Loads built-in patterns for common formats

---

## Dependencies

- Python 3.10+
- struct (stdlib)
- dataclasses (stdlib)
- lark - Pattern language parsing
- rich - CLI formatting
- click - CLI framework

---

## Future Enhancements

- GUI with tkinter or PyQt
- Disassembly view (integrate capstone)
- Firmware analysis (support for embedded filesystems)
- Plugin system for extensibility