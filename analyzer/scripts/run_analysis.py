#!/usr/bin/env python3
"""APK Sentinel Analysis Orchestrator.

Main entry point for the analyzer container. Calls each analyzer module
in sequence and produces the canonical analysis_results.json.

This script produces RAW OBSERVABLE FINDINGS only. It does NOT calculate
the final risk score — that is owned by the backend's deterministic
scoring engine.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent))

from manifest_analyzer import analyze_manifest
from permission_analyzer import analyze_permissions
from component_analyzer import analyze_components
from api_analyzer import analyze_apis
from url_extractor import extract_network_indicators
from secret_detector import detect_secrets
from obfuscation_analyzer import analyze_obfuscation
from certificate_analyzer import analyze_certificate


def main():
    parser = argparse.ArgumentParser(description="APK Sentinel Static Analyzer")
    parser.add_argument("--input", required=True, help="Input directory containing APK")
    parser.add_argument("--output", required=True, help="Output directory for results")
    args = parser.parse_args()

    input_dir = Path(args.input)
    output_dir = Path(args.output)
    apk_path = input_dir / "application.apk"

    if not apk_path.exists():
        print(f"[ERROR] APK not found at {apk_path}", file=sys.stderr)
        sys.exit(1)

    print("[Analysis] Starting static analysis pipeline…")

    # ── APK file metadata ─────────────────────────────────────────────
    print("[Analysis] Computing APK metadata…")
    file_size = apk_path.stat().st_size
    sha256 = _compute_sha256(apk_path)

    # ── Manifest Analysis ─────────────────────────────────────────────
    print("[Analysis] Parsing AndroidManifest.xml…")
    manifest_data = analyze_manifest(output_dir)
    if manifest_data.get("error"):
        raise RuntimeError(
            f"Could not read AndroidManifest.xml: {manifest_data['error']}"
        )
    apk_metadata = manifest_data.get("apk", {})
    apk_metadata["sha256"] = sha256
    apk_metadata["file_size"] = file_size

    # ── Permission Analysis ───────────────────────────────────────────
    print("[Analysis] Analyzing permissions…")
    raw_permissions = manifest_data.get("raw_permissions", [])
    permissions, correlations = analyze_permissions(raw_permissions)

    # ── Component Analysis ────────────────────────────────────────────
    print("[Analysis] Analyzing components…")
    raw_components = manifest_data.get("raw_components", [])
    components, component_summary = analyze_components(raw_components)

    # ── Suspicious API Analysis ───────────────────────────────────────
    print("[Analysis] Scanning for suspicious APIs…")
    suspicious_apis = analyze_apis(output_dir)

    # ── Network Indicator Extraction ──────────────────────────────────
    print("[Analysis] Extracting network indicators…")
    network_indicators = extract_network_indicators(output_dir)

    # ── Secret Detection ──────────────────────────────────────────────
    print("[Analysis] Detecting potential secrets…")
    potential_secrets = detect_secrets(output_dir)

    # ── Obfuscation Analysis ──────────────────────────────────────────
    print("[Analysis] Analyzing obfuscation…")
    obfuscation = analyze_obfuscation(output_dir)

    # ── Certificate Analysis ──────────────────────────────────────────
    print("[Analysis] Analyzing certificate…")
    certificate = analyze_certificate(output_dir, input_dir)

    # ── Build canonical results JSON ──────────────────────────────────
    results = {
        "analysis_id": os.environ.get("ANALYSIS_ID", "unknown"),
        "apk": apk_metadata,
        "permissions": permissions,
        "permission_correlations": correlations,
        "components": components,
        "component_summary": component_summary,
        "suspicious_apis": suspicious_apis,
        "network_indicators": network_indicators,
        "potential_secrets": potential_secrets,
        "obfuscation": obfuscation,
        "certificate": certificate,
        # NOTE: 'score' is NOT calculated here.
        # The backend's deterministic scoring engine owns score calculation.
    }

    # ── Write results ─────────────────────────────────────────────────
    findings_dir = output_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    results_file = findings_dir / "analysis_results.json"

    with open(results_file, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"[Analysis] Results written to {results_file}")
    print(f"[Analysis] Found: {len(permissions)} permissions, "
          f"{len(correlations)} correlations, "
          f"{len(components)} components, "
          f"{len(suspicious_apis)} suspicious APIs, "
          f"{len(network_indicators)} network indicators, "
          f"{len(potential_secrets)} potential secrets")
    print("[Analysis] Pipeline complete.")


def _compute_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


if __name__ == "__main__":
    main()
