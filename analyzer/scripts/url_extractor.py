"""URL, domain, and IP address extractor.

Extracts network indicators from decompiled source. Does NOT
automatically classify extracted indicators as malicious.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

from utils import safe_read_text, walk_source_files

# ── Regex patterns ────────────────────────────────────────────────────

URL_REGEX = re.compile(
    r'https?://[^\s\'"<>\)\]\}]{5,200}',
    re.IGNORECASE,
)

# IPv4 address (not in a version-string context)
IPV4_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
)

# Simple domain extraction (after removing URLs)
DOMAIN_REGEX = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
    r'{1,3}(?:com|org|net|io|dev|co|info|biz|app|xyz|me|us|uk|de|fr|ru|cn|top)\b',
    re.IGNORECASE,
)

# Exclude common non-indicator patterns
EXCLUDE_PATTERNS = {
    "schemas.android.com",
    "www.w3.org",
    "ns.adobe.com",
    "xmlpull.org",
    "xml.org",
    "apache.org",
    "google.com/android",
    "developer.android.com",
    "schemas.microsoft.com",
    "purl.org",
    "127.0.0.1",
    "0.0.0.0",
    "255.255.255.255",
    "localhost",
}


def extract_network_indicators(output_dir: Path) -> List[Dict[str, Any]]:
    """Extract URLs, domains, and IP addresses from decompiled source.

    Args:
        output_dir: Analysis output directory.

    Returns:
        List of network indicators with type, source, and context.
    """
    indicators: List[Dict[str, Any]] = []
    seen: set[str] = set()

    # Scan JADX source
    jadx_sources = output_dir / "jadx" / "sources"
    _scan_for_indicators(jadx_sources, indicators, seen, {".java", ".kt"})

    # Scan smali and other files
    apktool_dir = output_dir / "apktool"
    _scan_for_indicators(apktool_dir, indicators, seen, {".smali", ".xml", ".json", ".properties"})

    return indicators


def _is_excluded(value: str) -> bool:
    """Check if a value matches an exclusion pattern."""
    lower = value.lower()
    return any(excl in lower for excl in EXCLUDE_PATTERNS)


def _scan_for_indicators(
    root: Path,
    indicators: List[Dict[str, Any]],
    seen: set[str],
    extensions: set[str],
) -> None:
    """Scan files for network indicators."""
    for fpath in walk_source_files(root, extensions):
        content = safe_read_text(fpath)
        if not content:
            continue

        rel_path = str(fpath)

        for line_num, line in enumerate(content.split("\n"), 1):
            # URLs
            for match in URL_REGEX.finditer(line):
                url = match.group().rstrip(".,;:\"')")
                if url not in seen and not _is_excluded(url):
                    seen.add(url)
                    indicators.append({
                        "indicator": url,
                        "type": "URL",
                        "source_file": rel_path,
                        "line": line_num,
                        "context": line.strip()[:200],
                    })

            # IPv4
            for match in IPV4_REGEX.finditer(line):
                ip = match.group()
                if ip not in seen and not _is_excluded(ip):
                    seen.add(ip)
                    indicators.append({
                        "indicator": ip,
                        "type": "IPv4",
                        "source_file": rel_path,
                        "line": line_num,
                        "context": line.strip()[:200],
                    })

            # Domains (scan after URL extraction to avoid double counting)
            for match in DOMAIN_REGEX.finditer(line):
                domain = match.group()
                if domain not in seen and not _is_excluded(domain):
                    seen.add(domain)
                    indicators.append({
                        "indicator": domain,
                        "type": "DOMAIN",
                        "source_file": rel_path,
                        "line": line_num,
                        "context": line.strip()[:200],
                    })
