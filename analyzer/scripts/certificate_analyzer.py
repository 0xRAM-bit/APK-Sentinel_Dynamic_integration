"""Certificate and signing analyzer.

Extracts certificate fingerprints (SHA-256, SHA-1) and signature scheme
information from the APK's META-INF directory.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional


def analyze_certificate(output_dir: Path, input_dir: Path) -> Dict[str, Any]:
    """Extract certificate and signing information.

    Attempts to extract certificate details from:
    1. META-INF/*.RSA / *.DSA / *.EC files via keytool
    2. APKTool's original/ directory

    Args:
        output_dir: Analysis output directory.
        input_dir: Analysis input directory (contains the APK).

    Returns:
        Dict with certificate fingerprints and metadata.
    """
    cert_info: Dict[str, Any] = {}

    # Look for certificate files in APKTool output
    meta_inf = output_dir / "apktool" / "original" / "META-INF"
    if not meta_inf.exists():
        meta_inf = output_dir / "apktool" / "META-INF"

    cert_file = _find_cert_file(meta_inf)

    if cert_file:
        cert_info = _extract_cert_info_keytool(cert_file)

    # Try to determine signature scheme from APK structure
    apk_path = input_dir / "application.apk"
    if apk_path.exists():
        scheme = _detect_signature_scheme(output_dir / "apktool")
        if scheme:
            cert_info["signature_scheme"] = scheme

    return cert_info


def _find_cert_file(meta_inf: Path) -> Optional[Path]:
    """Find a certificate file in META-INF directory."""
    if not meta_inf.exists():
        return None

    for ext in ["*.RSA", "*.DSA", "*.EC"]:
        files = list(meta_inf.glob(ext))
        if files:
            return files[0]

    return None


def _extract_cert_info_keytool(cert_file: Path) -> Dict[str, Any]:
    """Extract certificate info using keytool command."""
    info: Dict[str, Any] = {}

    try:
        result = subprocess.run(
            [
                "keytool", "-printcert", "-file", str(cert_file),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            output = result.stdout

            # Extract SHA-256 fingerprint
            sha256_match = re.search(
                r'SHA256:\s*([A-Fa-f0-9:]+)', output
            )
            if sha256_match:
                info["sha256_fingerprint"] = sha256_match.group(1)

            # Extract SHA-1 fingerprint
            sha1_match = re.search(
                r'SHA1:\s*([A-Fa-f0-9:]+)', output
            )
            if sha1_match:
                info["sha1_fingerprint"] = sha1_match.group(1)

            # Extract owner/issuer
            owner_match = re.search(r'Owner:\s*(.+)', output)
            if owner_match:
                info["subject"] = owner_match.group(1).strip()

            issuer_match = re.search(r'Issuer:\s*(.+)', output)
            if issuer_match:
                info["issuer"] = issuer_match.group(1).strip()

            # Extract validity dates
            valid_from_match = re.search(r'Valid from:\s*(.+?)(?:until|$)', output)
            if valid_from_match:
                info["valid_from"] = valid_from_match.group(1).strip()

            valid_to_match = re.search(r'until:\s*(.+)', output)
            if valid_to_match:
                info["valid_to"] = valid_to_match.group(1).strip()

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        # keytool not available or timed out — try manual extraction
        info = _extract_cert_info_manual(cert_file)

    return info


def _extract_cert_info_manual(cert_file: Path) -> Dict[str, Any]:
    """Fallback: compute fingerprints directly from certificate file."""
    info: Dict[str, Any] = {}
    try:
        cert_bytes = cert_file.read_bytes()
        sha256 = hashlib.sha256(cert_bytes).hexdigest().upper()
        sha1 = hashlib.sha1(cert_bytes).hexdigest().upper()

        # Format as colon-separated
        info["sha256_fingerprint"] = ":".join(
            sha256[i:i+2] for i in range(0, len(sha256), 2)
        )
        info["sha1_fingerprint"] = ":".join(
            sha1[i:i+2] for i in range(0, len(sha1), 2)
        )
    except OSError:
        pass

    return info


def _detect_signature_scheme(apktool_dir: Path) -> Optional[str]:
    """Detect APK signature scheme from directory structure."""
    meta_inf = apktool_dir / "original" / "META-INF"
    if not meta_inf.exists():
        meta_inf = apktool_dir / "META-INF"
    if not meta_inf.exists():
        return None

    schemes = []

    # V1 (JAR signing)
    if any(meta_inf.glob("*.SF")):
        schemes.append("v1 (JAR)")

    # V2/V3 indicators (APK Signing Block — harder to detect from APKTool output)
    # V2+ signs the entire APK, detectable by the APK Signing Block in the ZIP
    # APKTool doesn't always preserve this, so we check for common indicators
    if any(meta_inf.glob("*.RSA")) or any(meta_inf.glob("*.DSA")):
        if not schemes:
            schemes.append("v1 (JAR)")

    return " + ".join(schemes) if schemes else "Unknown"
