"""Suspicious API analyzer.

Scans JADX-decompiled source and/or APKTool smali output for
security-sensitive APIs. Treats API presence as an indicator,
NOT proof of malicious behavior.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

from utils import safe_read_text, walk_source_files

# ── API patterns grouped by category ─────────────────────────────────

API_PATTERNS: List[Dict[str, Any]] = [
    # Process execution
    {"pattern": r"Runtime\.exec\s*\(", "category": "PROCESS_EXECUTION", "api": "Runtime.exec", "severity": "HIGH",
     "explanation": "Executes system commands — could be used for privilege escalation or system manipulation"},
    {"pattern": r"ProcessBuilder", "category": "PROCESS_EXECUTION", "api": "ProcessBuilder", "severity": "HIGH",
     "explanation": "Creates system processes — could execute arbitrary commands"},

    # Dynamic code loading
    {"pattern": r"DexClassLoader", "category": "DYNAMIC_CODE_LOADING", "api": "DexClassLoader", "severity": "HIGH",
     "explanation": "Loads code from DEX files at runtime — could load malicious code dynamically"},
    {"pattern": r"PathClassLoader", "category": "DYNAMIC_CODE_LOADING", "api": "PathClassLoader", "severity": "MEDIUM",
     "explanation": "Loads classes from a specified path — standard but can be used for code injection"},
    {"pattern": r"System\.loadLibrary\s*\(", "category": "DYNAMIC_CODE_LOADING", "api": "System.loadLibrary", "severity": "MEDIUM",
     "explanation": "Loads native libraries — may contain native code not visible to static analysis"},
    {"pattern": r"InMemoryDexClassLoader", "category": "DYNAMIC_CODE_LOADING", "api": "InMemoryDexClassLoader", "severity": "HIGH",
     "explanation": "Loads DEX code from memory — advanced technique sometimes used to evade analysis"},

    # SMS
    {"pattern": r"SmsManager", "category": "SMS", "api": "SmsManager", "severity": "HIGH",
     "explanation": "SMS management API — could send, read, or intercept SMS messages"},

    # Telephony
    {"pattern": r"TelephonyManager", "category": "TELEPHONY", "api": "TelephonyManager", "severity": "MEDIUM",
     "explanation": "Access to telephony information — could read device identifiers, SIM info, or call state"},

    # Location
    {"pattern": r"LocationManager", "category": "LOCATION", "api": "LocationManager", "severity": "MEDIUM",
     "explanation": "Location tracking API — could monitor device position"},
    {"pattern": r"FusedLocationProviderClient", "category": "LOCATION", "api": "FusedLocationProviderClient", "severity": "MEDIUM",
     "explanation": "Google Play location API — could track device position"},

    # Audio
    {"pattern": r"MediaRecorder", "category": "AUDIO", "api": "MediaRecorder", "severity": "MEDIUM",
     "explanation": "Media recording API — could record audio or video"},
    {"pattern": r"AudioRecord", "category": "AUDIO", "api": "AudioRecord", "severity": "HIGH",
     "explanation": "Low-level audio recording — could record from microphone"},

    # Camera
    {"pattern": r"android\.hardware\.camera2", "category": "CAMERA", "api": "Camera2 API", "severity": "MEDIUM",
     "explanation": "Camera2 API — could capture images or video"},
    {"pattern": r"android\.hardware\.Camera", "category": "CAMERA", "api": "Camera API", "severity": "MEDIUM",
     "explanation": "Legacy Camera API — could capture images or video"},

    # Networking
    {"pattern": r"HttpURLConnection", "category": "NETWORKING", "api": "HttpURLConnection", "severity": "LOW",
     "explanation": "HTTP connection — standard networking API"},
    {"pattern": r"OkHttpClient", "category": "NETWORKING", "api": "OkHttpClient", "severity": "LOW",
     "explanation": "OkHttp networking library — standard HTTP client"},
    {"pattern": r"new\s+Socket\s*\(", "category": "NETWORKING", "api": "Socket", "severity": "MEDIUM",
     "explanation": "Raw socket connection — could communicate with arbitrary servers"},
    {"pattern": r"DatagramSocket", "category": "NETWORKING", "api": "DatagramSocket", "severity": "MEDIUM",
     "explanation": "UDP socket — could communicate with arbitrary servers"},
    {"pattern": r"SSLSocket", "category": "NETWORKING", "api": "SSLSocket", "severity": "LOW",
     "explanation": "SSL/TLS socket — encrypted network communication"},

    # WebView
    {"pattern": r"WebView", "category": "WEBVIEW", "api": "WebView", "severity": "MEDIUM",
     "explanation": "Embedded browser — could load arbitrary web content or execute JavaScript"},
    {"pattern": r"setJavaScriptEnabled\s*\(\s*true\s*\)", "category": "WEBVIEW", "api": "WebView.setJavaScriptEnabled", "severity": "MEDIUM",
     "explanation": "JavaScript enabled in WebView — increases attack surface for XSS"},
    {"pattern": r"addJavascriptInterface", "category": "WEBVIEW", "api": "WebView.addJavascriptInterface", "severity": "HIGH",
     "explanation": "JavaScript bridge to native code — could be exploited if WebView loads untrusted content"},

    # Cryptography
    {"pattern": r"Cipher\.getInstance", "category": "CRYPTOGRAPHY", "api": "Cipher", "severity": "LOW",
     "explanation": "Encryption/decryption — check for weak algorithms"},
    {"pattern": r"MessageDigest\.getInstance", "category": "CRYPTOGRAPHY", "api": "MessageDigest", "severity": "LOW",
     "explanation": "Hash computation — check for weak algorithms (MD5, SHA-1)"},
    {"pattern": r"SecretKeySpec", "category": "CRYPTOGRAPHY", "api": "SecretKeySpec", "severity": "MEDIUM",
     "explanation": "Symmetric key specification — may indicate hardcoded keys"},
    {"pattern": r"Base64\.(encode|decode)", "category": "CRYPTOGRAPHY", "api": "Base64", "severity": "LOW",
     "explanation": "Base64 encoding/decoding — may be used to obfuscate data"},

    # Reflection
    {"pattern": r"Class\.forName\s*\(", "category": "REFLECTION", "api": "Class.forName", "severity": "MEDIUM",
     "explanation": "Reflection API — could dynamically load and invoke arbitrary classes"},
    {"pattern": r"Method\.invoke\s*\(", "category": "REFLECTION", "api": "Method.invoke", "severity": "MEDIUM",
     "explanation": "Reflective method invocation — could call methods dynamically to evade analysis"},
    {"pattern": r"getDeclaredMethod", "category": "REFLECTION", "api": "getDeclaredMethod", "severity": "MEDIUM",
     "explanation": "Reflection to access methods — could access private/hidden APIs"},
]


def analyze_apis(output_dir: Path) -> List[Dict[str, Any]]:
    """Scan decompiled source for security-sensitive API usage.

    Args:
        output_dir: Analysis output directory containing jadx/ and apktool/ subdirs.

    Returns:
        List of API findings with category, file, line, severity, etc.
    """
    findings: List[Dict[str, Any]] = []
    seen: set[str] = set()  # Deduplicate: (api, file, line)

    # Scan JADX source (Java-like)
    jadx_sources = output_dir / "jadx" / "sources"
    _scan_directory(jadx_sources, findings, seen, {".java", ".kt"})

    # Scan smali code
    apktool_dir = output_dir / "apktool"
    for smali_dir in apktool_dir.glob("smali*"):
        _scan_directory(smali_dir, findings, seen, {".smali"})

    return findings


def _scan_directory(
    root: Path,
    findings: List[Dict[str, Any]],
    seen: set[str],
    extensions: set[str],
) -> None:
    """Scan all source files in a directory for API patterns."""
    for fpath in walk_source_files(root, extensions):
        content = safe_read_text(fpath)
        if not content:
            continue

        rel_path = str(fpath)
        lines = content.split("\n")

        for pattern_info in API_PATTERNS:
            regex = re.compile(pattern_info["pattern"])
            for line_num, line in enumerate(lines, 1):
                if regex.search(line):
                    dedup_key = f"{pattern_info['api']}:{rel_path}:{line_num}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    findings.append({
                        "category": pattern_info["category"],
                        "matched_api": pattern_info["api"],
                        "file": rel_path,
                        "line": line_num,
                        "severity": pattern_info["severity"],
                        "explanation": pattern_info["explanation"],
                        "evidence": line.strip()[:200],
                    })
