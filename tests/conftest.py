"""Pytest configuration for binary-inspect tests."""

import pytest


@pytest.fixture
def sample_binary_data():
    """Sample binary data for testing."""
    return b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"


@pytest.fixture
def pe_header():
    """Minimal PE header for testing."""
    return b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"


@pytest.fixture
def elf_header():
    """Minimal ELF header for testing."""
    return b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00"


@pytest.fixture
def png_header():
    """PNG header for testing."""
    return b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10"


@pytest.fixture
def pdf_header():
    """PDF header for testing."""
    return b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"


@pytest.fixture
def zip_header():
    """ZIP header for testing."""
    return b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
