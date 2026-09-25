"""APK upload validation, quarantine, and hashing service."""

from __future__ import annotations

import hashlib
import shutil
import uuid
from pathlib import Path
from typing import Tuple

from fastapi import UploadFile

from app.config import settings
from app.utils.logging import logger

# Valid APK magic bytes (PK ZIP header)
_ZIP_MAGIC = b"PK\x03\x04"

ALLOWED_EXTENSIONS = {".apk"}


class UploadValidationError(Exception):
    """Raised when an uploaded file fails validation."""
    pass


async def validate_and_store_apk(upload_file: UploadFile) -> Tuple[str, str, int, Path]:
    """Validate an uploaded APK and store it in a quarantine workspace.

    Returns:
        Tuple of (analysis_id, sha256_hex, file_size, apk_path)

    Raises:
        UploadValidationError: If the file fails any validation check.
    """
    # ── Validate filename extension ───────────────────────────────────
    original_filename = upload_file.filename or "unknown.apk"
    ext = Path(original_filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise UploadValidationError(
            f"Invalid file extension '{ext}'. Only .apk files are accepted."
        )

    # ── Generate analysis ID (never trust user filename for paths) ────
    analysis_id = str(uuid.uuid4())

    # ── Create quarantine workspace ───────────────────────────────────
    workspace = settings.analysis_path / analysis_id
    input_dir = workspace / "input"
    output_dir = workspace / "output"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    # The analyzer runs as an unprivileged user inside a separate container.
    # Let that user write analysis artifacts into this dedicated output mount.
    output_dir.chmod(0o777)

    apk_path = input_dir / "application.apk"

    # ── Stream file to disk and compute SHA-256 ───────────────────────
    sha256_hash = hashlib.sha256()
    file_size = 0

    try:
        with open(apk_path, "wb") as f:
            while True:
                chunk = await upload_file.read(8192)
                if not chunk:
                    break
                file_size += len(chunk)

                # Check size limit during streaming
                if file_size > settings.max_apk_size_bytes:
                    # Clean up partial file
                    f.close()
                    shutil.rmtree(workspace, ignore_errors=True)
                    raise UploadValidationError(
                        f"File exceeds maximum size of {settings.MAX_APK_SIZE_MB} MB."
                    )

                sha256_hash.update(chunk)
                f.write(chunk)
    except UploadValidationError:
        raise
    except Exception as e:
        shutil.rmtree(workspace, ignore_errors=True)
        raise UploadValidationError(f"Failed to save uploaded file: {e}")

    sha256_hex = sha256_hash.hexdigest()

    # ── Validate file is not empty ────────────────────────────────────
    if file_size == 0:
        shutil.rmtree(workspace, ignore_errors=True)
        raise UploadValidationError("Uploaded file is empty.")

    # ── Validate ZIP/APK magic bytes ──────────────────────────────────
    try:
        with open(apk_path, "rb") as f:
            magic = f.read(4)
        if magic != _ZIP_MAGIC:
            shutil.rmtree(workspace, ignore_errors=True)
            raise UploadValidationError(
                "File does not appear to be a valid APK (invalid file signature)."
            )
    except UploadValidationError:
        raise
    except Exception:
        shutil.rmtree(workspace, ignore_errors=True)
        raise UploadValidationError("Failed to validate file signature.")

    logger.info(
        "APK quarantined | analysis_id=%s | sha256=%s | size=%d bytes",
        analysis_id,
        sha256_hex,
        file_size,
    )

    return analysis_id, sha256_hex, file_size, apk_path


def cleanup_workspace(analysis_id: str) -> None:
    """Remove an analysis workspace from disk."""
    workspace = settings.analysis_path / analysis_id
    if workspace.exists():
        shutil.rmtree(workspace, ignore_errors=True)
        logger.info("Cleaned up workspace | analysis_id=%s", analysis_id)
