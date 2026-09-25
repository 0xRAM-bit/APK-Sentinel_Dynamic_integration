"""Potential hardcoded secret detector.

Uses contextual regex patterns AND entropy analysis, not simply generic
long-string matching. Labels results as "Potential Hardcoded Secret" —
never as confirmed credentials. Redacts actual values everywhere.
"""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any, Dict, List

from utils import safe_read_text, walk_source_files

# ── Contextual secret patterns ────────────────────────────────────────
# Each pattern has a context keyword (variable name / key) plus a value capture

SECRET_PATTERNS: List[Dict[str, Any]] = [
    {
        "type": "API_KEY",
        "regex": re.compile(
            r'(?:api[_-]?key|apikey|api_secret)\s*[=:]\s*["\']([A-Za-z0-9_\-/+=]{16,128})["\']',
            re.IGNORECASE,
        ),
        "min_entropy": 3.0,
    },
    {
        "type": "AWS_ACCESS_KEY",
        "regex": re.compile(r'(AKIA[0-9A-Z]{16})'),
        "min_entropy": 0,  # AWS keys have a known prefix
    },
    {
        "type": "AWS_SECRET_KEY",
        "regex": re.compile(
            r'(?:aws[_-]?secret|secret[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9/+=]{30,50})["\']',
            re.IGNORECASE,
        ),
        "min_entropy": 3.5,
    },
    {
        "type": "JWT",
        "regex": re.compile(r'(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})'),
        "min_entropy": 0,  # JWTs have a known structure
    },
    {
        "type": "BEARER_TOKEN",
        "regex": re.compile(
            r'[Bb]earer\s+([A-Za-z0-9_\-/+=.]{20,128})',
        ),
        "min_entropy": 3.0,
    },
    {
        "type": "PASSWORD",
        "regex": re.compile(
            r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,100})["\']',
            re.IGNORECASE,
        ),
        "min_entropy": 2.5,
    },
    {
        "type": "CLIENT_SECRET",
        "regex": re.compile(
            r'(?:client[_-]?secret|app[_-]?secret)\s*[=:]\s*["\']([A-Za-z0-9_\-/+=]{10,128})["\']',
            re.IGNORECASE,
        ),
        "min_entropy": 3.0,
    },
    {
        "type": "PRIVATE_KEY",
        "regex": re.compile(r'(-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----)'),
        "min_entropy": 0,
    },
    {
        "type": "AUTHORIZATION_HEADER",
        "regex": re.compile(
            r'[Aa]uthorization["\']?\s*[=:]\s*["\']([A-Za-z0-9+/=\s]{20,200})["\']',
        ),
        "min_entropy": 3.0,
    },
    {
        "type": "GOOGLE_API_KEY",
        "regex": re.compile(r'(AIza[0-9A-Za-z_-]{35})'),
        "min_entropy": 0,
    },
    {
        "type": "FIREBASE_KEY",
        "regex": re.compile(
            r'(?:firebase|fcm)[_-]?(?:key|token|secret)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,200})["\']',
            re.IGNORECASE,
        ),
        "min_entropy": 3.0,
    },
    {
        "type": "TOKEN",
        "regex": re.compile(
            r'(?:access[_-]?token|auth[_-]?token|secret[_-]?token)\s*[=:]\s*["\']([A-Za-z0-9_\-/+=.]{16,200})["\']',
            re.IGNORECASE,
        ),
        "min_entropy": 3.0,
    },
]


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _redact(value: str) -> str:
    """Redact a secret value, showing only first 4 and last 4 chars."""
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}…{value[-4:]}"


def _assess_confidence(entropy: float, min_entropy: float) -> str:
    """Assess confidence level based on entropy and pattern specificity."""
    if min_entropy == 0:
        return "HIGH"  # Structurally identifiable (AWS, JWT, etc.)
    if entropy > 4.0:
        return "HIGH"
    if entropy > 3.0:
        return "MEDIUM"
    return "LOW"


def detect_secrets(output_dir: Path) -> List[Dict[str, Any]]:
    """Scan decompiled source for potential hardcoded secrets.

    Args:
        output_dir: Analysis output directory.

    Returns:
        List of potential secret findings with redacted evidence.
    """
    findings: List[Dict[str, Any]] = []
    seen: set[str] = set()

    # Scan JADX source
    jadx_sources = output_dir / "jadx" / "sources"
    _scan_for_secrets(jadx_sources, findings, seen, {".java", ".kt"})

    # Scan XML configs and properties
    apktool_dir = output_dir / "apktool"
    _scan_for_secrets(apktool_dir, findings, seen, {".xml", ".json", ".properties"})

    return findings


def _scan_for_secrets(
    root: Path,
    findings: List[Dict[str, Any]],
    seen: set[str],
    extensions: set[str],
) -> None:
    """Scan files for secret patterns."""
    for fpath in walk_source_files(root, extensions):
        content = safe_read_text(fpath)
        if not content:
            continue

        rel_path = str(fpath)

        for line_num, line in enumerate(content.split("\n"), 1):
            for pattern in SECRET_PATTERNS:
                for match in pattern["regex"].finditer(line):
                    value = match.group(1) if match.lastindex else match.group()

                    # Entropy check
                    entropy = _shannon_entropy(value)
                    if pattern["min_entropy"] > 0 and entropy < pattern["min_entropy"]:
                        continue

                    # Dedup
                    dedup_key = f"{pattern['type']}:{_redact(value)}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    confidence = _assess_confidence(entropy, pattern["min_entropy"])

                    findings.append({
                        "type": pattern["type"],
                        "pattern_matched": pattern["type"],
                        "source_file": rel_path,
                        "line": line_num,
                        "redacted_evidence": _redact(value),
                        "confidence": confidence,
                        "entropy": round(entropy, 2),
                    })
