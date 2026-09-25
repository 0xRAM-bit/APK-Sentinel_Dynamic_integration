"""Tests for APK upload validation and hashing."""

import hashlib
import io
import os
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.upload import (
    UploadValidationError,
    validate_and_store_apk,
)


def _make_fake_apk(content: bytes = b"") -> bytes:
    """Create a minimal fake APK (ZIP header + content)."""
    # PK ZIP magic bytes
    return b"PK\x03\x04" + content


class FakeUploadFile:
    """Mock UploadFile for testing."""

    def __init__(self, filename: str, content: bytes):
        self.filename = filename
        self._content = content
        self._offset = 0

    async def read(self, size: int = -1) -> bytes:
        if size == -1:
            data = self._content[self._offset:]
            self._offset = len(self._content)
        else:
            data = self._content[self._offset:self._offset + size]
            self._offset += len(data)
        return data


@pytest.mark.asyncio
async def test_valid_apk_upload():
    """Test that a valid APK file is accepted."""
    content = _make_fake_apk(b"test content for valid apk")
    upload = FakeUploadFile("test_app.apk", content)

    with patch("app.services.upload.settings") as mock_settings:
        mock_settings.max_apk_size_bytes = 100 * 1024 * 1024
        mock_settings.analysis_path = Path(tempfile.mkdtemp())

        try:
            analysis_id, sha256, file_size, apk_path = await validate_and_store_apk(upload)

            assert analysis_id  # UUID generated
            assert len(sha256) == 64  # SHA-256 hex
            assert file_size == len(content)
            assert apk_path.exists()

            # Verify SHA-256 correctness
            expected_hash = hashlib.sha256(content).hexdigest()
            assert sha256 == expected_hash
        finally:
            shutil.rmtree(mock_settings.analysis_path, ignore_errors=True)


@pytest.mark.asyncio
async def test_invalid_extension_rejected():
    """Test that non-APK files are rejected."""
    upload = FakeUploadFile("malware.exe", b"PK\x03\x04not an apk")

    with pytest.raises(UploadValidationError, match="Invalid file extension"):
        with patch("app.services.upload.settings") as mock_settings:
            mock_settings.max_apk_size_bytes = 100 * 1024 * 1024
            mock_settings.analysis_path = Path(tempfile.mkdtemp())
            await validate_and_store_apk(upload)


@pytest.mark.asyncio
async def test_empty_file_rejected():
    """Test that empty files are rejected."""
    upload = FakeUploadFile("empty.apk", b"")

    with pytest.raises(UploadValidationError, match="empty"):
        with patch("app.services.upload.settings") as mock_settings:
            mock_settings.max_apk_size_bytes = 100 * 1024 * 1024
            mock_settings.analysis_path = Path(tempfile.mkdtemp())
            await validate_and_store_apk(upload)


@pytest.mark.asyncio
async def test_oversized_file_rejected():
    """Test that files exceeding max size are rejected."""
    content = _make_fake_apk(b"x" * 1000)
    upload = FakeUploadFile("large.apk", content)

    with pytest.raises(UploadValidationError, match="exceeds maximum size"):
        with patch("app.services.upload.settings") as mock_settings:
            mock_settings.max_apk_size_bytes = 100  # 100 bytes limit
            mock_settings.analysis_path = Path(tempfile.mkdtemp())
            await validate_and_store_apk(upload)


@pytest.mark.asyncio
async def test_invalid_magic_bytes_rejected():
    """Test that files without ZIP magic bytes are rejected."""
    upload = FakeUploadFile("not_zip.apk", b"NOT A ZIP FILE CONTENT HERE")

    with pytest.raises(UploadValidationError, match="invalid file signature"):
        with patch("app.services.upload.settings") as mock_settings:
            mock_settings.max_apk_size_bytes = 100 * 1024 * 1024
            mock_settings.analysis_path = Path(tempfile.mkdtemp())
            try:
                await validate_and_store_apk(upload)
            finally:
                shutil.rmtree(mock_settings.analysis_path, ignore_errors=True)


def test_sha256_streaming_correctness():
    """Test that streaming SHA-256 matches full-file hash."""
    content = b"PK\x03\x04" + os.urandom(10000)
    expected = hashlib.sha256(content).hexdigest()

    # Simulate streaming hash
    h = hashlib.sha256()
    offset = 0
    while offset < len(content):
        chunk = content[offset:offset + 8192]
        h.update(chunk)
        offset += len(chunk)

    assert h.hexdigest() == expected
