"""Magic byte detection for file format identification."""

from .models import MagicMatch

MAGIC_SIGNATURES = {
    "PE": {
        "magic": b"MZ",
        "description": "Windows Portable Executable",
        "confidence": 1.0,
    },
    "ELF": {
        "magic": b"\x7fELF",
        "description": "Linux Executable",
        "confidence": 1.0,
    },
    "PNG": {
        "magic": b"\x89PNG\r\n\x1a\n",
        "description": "PNG Image",
        "confidence": 1.0,
    },
    "JPEG": {
        "magic": b"\xff\xd8\xff",
        "description": "JPEG Image",
        "confidence": 0.8,
    },
    "GIF87a": {
        "magic": b"GIF87a",
        "description": "GIF Image (87a)",
        "confidence": 1.0,
    },
    "GIF89a": {
        "magic": b"GIF89a",
        "description": "GIF Image (89a)",
        "confidence": 1.0,
    },
    "PDF": {
        "magic": b"%PDF",
        "description": "PDF Document",
        "confidence": 1.0,
    },
    "ZIP": {
        "magic": b"PK\x03\x04",
        "description": "ZIP Archive",
        "confidence": 1.0,
    },
    "GZIP": {
        "magic": b"\x1f\x8b",
        "description": "GZIP Archive",
        "confidence": 1.0,
    },
    "TAR": {
        # POSIX ustar format
        "magic": b"ustar",
        "description": "TAR Archive",
        "confidence": 0.9,
    },
    "ISO": {
        "magic": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "description": "ISO 9660 Disk Image",
        "confidence": 0.3,
    },
    "BMP": {
        "magic": b"BM",
        "description": "BMP Image",
        "confidence": 1.0,
    },
    "ICO": {
        "magic": b"\x00\x00\x01\x00",
        "description": "Windows Icon",
        "confidence": 1.0,
    },
    "TIF": {
        # TIFF little-endian
        "magic": b"II\x2a\x00",
        "description": "TIFF Image (LE)",
        "confidence": 1.0,
    },
    "TIF_BE": {
        # TIFF big-endian
        "magic": b"MM\x00\x2a",
        "description": "TIFF Image (BE)",
        "confidence": 1.0,
    },
    "WAV": {
        "magic": b"RIFF",
        "description": "WAV Audio",
        "confidence": 0.9,
    },
    "FLAC": {
        "magic": b"fLaC",
        "description": "FLAC Audio",
        "confidence": 1.0,
    },
    "MP3": {
        # MP3 frame sync
        "magic": b"\xff\xfb",
        "description": "MP3 Audio",
        "confidence": 0.7,
    },
    "SQLite": {
        "magic": b"SQLite format 3\x00",
        "description": "SQLite Database",
        "confidence": 1.0,
    },
    "MachO": {
        "magic": b"\xfe\xed\xfa\xce",
        "description": "Mach-O 32-bit (LE)",
        "confidence": 1.0,
    },
    "MachO64": {
        "magic": b"\xfe\xed\xfa\xcf",
        "description": "Mach-O 64-bit (LE)",
        "confidence": 1.0,
    },
    "MachO_FAT": {
        "magic": b"\xca\xfe\xba\xbe",
        "description": "Mach-O Universal Binary",
        "confidence": 1.0,
    },
    "DEX": {
        "magic": "dex\n",
        "description": "Android DEX",
        "confidence": 1.0,
    },
    "APK": {
        "magic": b"PK\x03\x04",
        "description": "Android APK",
        "confidence": 0.8,
    },
    "CRC32": {
        # Various compression formats
        "magic": b"\x1f\x8b",
        "description": "GZIP Compression",
        "confidence": 1.0,
    },
    "LZ4": {
        "magic": b"\x04\x22\x4d\x18",
        "description": "LZ4 Compression",
        "confidence": 1.0,
    },
    "XZ": {
        "magic": b"\xfd7zXZ\x00",
        "description": "XZ Compression",
        "confidence": 1.0,
    },
    "zstd": {
        "magic": b"\x28\xb5\x2f\xfd",
        "description": "Zstandard Compression",
        "confidence": 1.0,
    },
    "WebP": {
        "magic": b"RIFF\x00\x00WEBP",
        "description": "WebP Image",
        "confidence": 1.0,
    },
    "AVIF": {
        "magic": b"\x00\x00\x00\x20\x66\x74\x79\x70\x61\x76\x69\x66",
        "description": "AVIF Image",
        "confidence": 1.0,
    },
    "RTF": {
        "magic": b"{\\rtf",
        "description": "Rich Text Format",
        "confidence": 1.0,
    },
    "OLE": {
        "magic": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        "description": "OLE Compound Document",
        "confidence": 1.0,
    },
}


class MagicDetector:
    """Detect file format using magic bytes."""

    def __init__(self, signatures: dict | None = None):
        """Initialize detector.

        Args:
            signatures: Optional custom signatures dict
        """
        self.signatures = signatures or MAGIC_SIGNATURES

    def detect(self, data: bytes, max_matches: int = 5) -> list[MagicMatch]:
        """Detect file format from binary data.

        Args:
            data: Binary data to analyze
            max_matches: Maximum number of matches to return

        Returns:
            List of MagicMatch objects sorted by confidence
        """
        matches = []

        for format_name, sig in self.signatures.items():
            magic = sig["magic"]
            if isinstance(magic, str):
                magic = magic.encode()

            if data.startswith(magic):
                matches.append(
                    MagicMatch(
                        format_name=format_name,
                        confidence=sig["confidence"],
                        magic_bytes=magic,
                        description=sig["description"],
                    )
                )

        # Sort by confidence descending
        matches.sort(key=lambda m: m.confidence, reverse=True)
        return matches[:max_matches]

    def detect_one(self, data: bytes) -> MagicMatch | None:
        """Detect the most likely format.

        Args:
            data: Binary data to analyze

        Returns:
            Best MagicMatch or None
        """
        matches = self.detect(data)
        return matches[0] if matches else None

    def add_signature(
        self, name: str, magic: bytes | str, description: str, confidence: float = 1.0
    ) -> None:
        """Add a custom signature.

        Args:
            name: Format name
            magic: Magic bytes
            description: Description
            confidence: Confidence score 0-1
        """
        if isinstance(magic, str):
            magic = magic.encode()
        self.signatures[name] = {
            "magic": magic,
            "description": description,
            "confidence": confidence,
        }

    def get_supported_formats(self) -> list[str]:
        """Get list of supported format names."""
        return list(self.signatures.keys())
