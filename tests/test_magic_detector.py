"""Tests for MagicDetector."""

from binary_inspect.core.magic_detector import MagicDetector


class TestMagicDetector:
    """Test cases for MagicDetector."""

    def test_detect_pe(self):
        """Test detecting PE format."""
        data = b"MZ" + b"\x00" * 100
        detector = MagicDetector()
        matches = detector.detect(data)
        assert len(matches) > 0
        assert matches[0].format_name == "PE"

    def test_detect_elf(self):
        """Test detecting ELF format."""
        data = b"\x7fELF" + b"\x00" * 100
        detector = MagicDetector()
        matches = detector.detect(data)
        assert len(matches) > 0
        assert matches[0].format_name == "ELF"

    def test_detect_png(self):
        """Test detecting PNG format."""
        data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        detector = MagicDetector()
        matches = detector.detect(data)
        assert len(matches) > 0
        assert matches[0].format_name == "PNG"

    def test_detect_pdf(self):
        """Test detecting PDF format."""
        data = b"%PDF-1.4" + b"\x00" * 100
        detector = MagicDetector()
        matches = detector.detect(data)
        assert len(matches) > 0
        assert matches[0].format_name == "PDF"

    def test_detect_zip(self):
        """Test detecting ZIP format."""
        data = b"PK\x03\x04" + b"\x00" * 100
        detector = MagicDetector()
        matches = detector.detect(data)
        assert len(matches) > 0
        assert matches[0].format_name == "ZIP"

    def test_detect_jpeg(self):
        """Test detecting JPEG format."""
        data = b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 100
        detector = MagicDetector()
        matches = detector.detect(data)
        assert len(matches) > 0
        assert matches[0].format_name == "JPEG"

    def test_detect_unknown(self):
        """Test unknown format returns empty."""
        data = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        detector = MagicDetector()
        matches = detector.detect(data)
        assert len(matches) == 0

    def test_detect_one(self):
        """Test detect_one returns best match."""
        data = b"MZ" + b"\x00" * 100
        detector = MagicDetector()
        match = detector.detect_one(data)
        assert match is not None
        assert match.format_name == "PE"

    def test_detect_none(self):
        """Test detect_one returns None for unknown."""
        data = b"\x00\x00\x00\x00"
        detector = MagicDetector()
        match = detector.detect_one(data)
        assert match is None

    def test_add_custom_signature(self):
        """Test adding custom signature."""
        detector = MagicDetector()
        detector.add_signature("MyFormat", b"MySig", "My custom format", 0.9)

        data = b"MySig" + b"\x00" * 100
        matches = detector.detect(data)
        assert len(matches) > 0
        assert matches[0].format_name == "MyFormat"

    def test_get_supported_formats(self):
        """Test getting list of supported formats."""
        detector = MagicDetector()
        formats = detector.get_supported_formats()
        assert "PE" in formats
        assert "ELF" in formats
        assert "PNG" in formats
