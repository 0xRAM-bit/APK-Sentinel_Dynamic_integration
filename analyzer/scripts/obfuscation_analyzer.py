"""Obfuscation analyzer.

Detects indicators of code obfuscation by analyzing class/method naming
patterns. Explicitly notes that legitimate Android applications commonly
use R8/ProGuard and that obfuscation is NOT itself evidence of malware.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List

from utils import safe_read_text, walk_source_files


def analyze_obfuscation(output_dir: Path) -> Dict[str, Any]:
    """Analyze decompiled code for obfuscation indicators.

    Args:
        output_dir: Analysis output directory.

    Returns:
        Dict with obfuscation score (0-100), indicators list, and explanation.
    """
    indicators: List[str] = []
    stats = {
        "total_classes": 0,
        "short_name_classes": 0,
        "total_methods": 0,
        "short_name_methods": 0,
        "base64_strings": 0,
        "dynamic_loading": 0,
        "encoded_strings": 0,
    }

    # Analyze JADX output (Java-like source)
    jadx_sources = output_dir / "jadx" / "sources"
    if jadx_sources.exists():
        _analyze_java_source(jadx_sources, stats)

    # Calculate score
    score = _compute_score(stats, indicators)

    explanation = (
        "Obfuscation analysis examines naming patterns and code characteristics. "
        "Note: legitimate Android applications commonly use R8/ProGuard for code "
        "shrinking and obfuscation. A high obfuscation score is an indicator, "
        "not evidence of malicious intent."
    )

    return {
        "score": score,
        "indicators": indicators,
        "explanation": explanation,
        "stats": stats,
    }


def _analyze_java_source(root: Path, stats: Dict[str, int]) -> None:
    """Analyze Java source files for obfuscation indicators."""
    # Class name regex (single-letter or very short names)
    class_pattern = re.compile(r'(?:public|private|protected)?\s*class\s+(\w+)')
    method_pattern = re.compile(r'(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?\w+\s+(\w+)\s*\(')
    base64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    dynamic_load_pattern = re.compile(r'DexClassLoader|InMemoryDexClassLoader|Class\.forName')

    for fpath in walk_source_files(root, {".java", ".kt"}):
        content = safe_read_text(fpath)
        if not content:
            continue

        # Count class names
        for match in class_pattern.finditer(content):
            name = match.group(1)
            stats["total_classes"] += 1
            if len(name) <= 2 and name.isalpha():
                stats["short_name_classes"] += 1

        # Count method names
        for match in method_pattern.finditer(content):
            name = match.group(1)
            stats["total_methods"] += 1
            if len(name) <= 2 and name.isalpha():
                stats["short_name_methods"] += 1

        # Count Base64-like strings
        stats["base64_strings"] += len(base64_pattern.findall(content))

        # Count dynamic loading
        stats["dynamic_loading"] += len(dynamic_load_pattern.findall(content))


def _compute_score(stats: Dict[str, int], indicators: List[str]) -> int:
    """Compute an obfuscation score from 0-100."""
    score = 0

    # Short class names ratio
    if stats["total_classes"] > 5:
        ratio = stats["short_name_classes"] / stats["total_classes"]
        if ratio > 0.5:
            score += 30
            indicators.append(f"{ratio:.0%} of classes have very short names (≤2 chars)")
        elif ratio > 0.2:
            score += 15
            indicators.append(f"{ratio:.0%} of classes have short names")

    # Short method names ratio
    if stats["total_methods"] > 10:
        ratio = stats["short_name_methods"] / stats["total_methods"]
        if ratio > 0.5:
            score += 25
            indicators.append(f"{ratio:.0%} of methods have very short names (≤2 chars)")
        elif ratio > 0.2:
            score += 12
            indicators.append(f"{ratio:.0%} of methods have short names")

    # Base64 strings
    if stats["base64_strings"] > 20:
        score += 15
        indicators.append(f"{stats['base64_strings']} potential Base64-encoded strings found")
    elif stats["base64_strings"] > 5:
        score += 8
        indicators.append(f"{stats['base64_strings']} Base64-encoded strings found")

    # Dynamic loading
    if stats["dynamic_loading"] > 0:
        score += min(stats["dynamic_loading"] * 5, 20)
        indicators.append(f"{stats['dynamic_loading']} dynamic class loading references")

    # Encoded strings (high proportion of non-readable strings)
    if stats["encoded_strings"] > 10:
        score += 10
        indicators.append("High number of encoded/non-readable strings")

    return min(score, 100)
