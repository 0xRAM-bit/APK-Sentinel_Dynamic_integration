"""Component analyzer with attack surface summary.

Analyzes exported components and their protection status.
Does NOT automatically classify exported components as malicious.
"""

from __future__ import annotations

from typing import Any, Dict, List


def analyze_components(
    raw_components: List[Dict[str, Any]],
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Analyze components for export status and protection.

    Args:
        raw_components: Component list from manifest analyzer.

    Returns:
        Tuple of (analyzed_components, component_summary).
    """
    analyzed: List[Dict[str, Any]] = []

    counts = {
        "total_activities": 0,
        "total_services": 0,
        "total_receivers": 0,
        "total_providers": 0,
        "exported_activities": 0,
        "exported_services": 0,
        "exported_receivers": 0,
        "exported_providers": 0,
        "unprotected_exported": 0,
    }

    type_key_map = {
        "activity": ("total_activities", "exported_activities"),
        "service": ("total_services", "exported_services"),
        "receiver": ("total_receivers", "exported_receivers"),
        "provider": ("total_providers", "exported_providers"),
    }

    for comp in raw_components:
        comp_type = comp.get("type", "unknown")
        exported = comp.get("exported", False)
        protected = comp.get("permission_protected", False)

        # Update counts
        total_key, exported_key = type_key_map.get(comp_type, (None, None))
        if total_key:
            counts[total_key] += 1
        if exported and exported_key:
            counts[exported_key] += 1
        if exported and not protected:
            counts["unprotected_exported"] += 1

        # Build analyzed component entry
        entry = {
            "name": comp.get("name", "unknown"),
            "type": comp_type,
            "exported": exported,
            "permission_protected": protected,
            "permission": comp.get("permission"),
            "has_intent_filter": comp.get("has_intent_filter", False),
            "intent_filters": comp.get("intent_filters", []),
        }

        # Determine severity/notes for exported components
        if exported and not protected:
            entry["severity"] = "HIGH"
            entry["note"] = (
                f"Exported {comp_type} without permission protection. "
                "This component is accessible to any app on the device."
            )
        elif exported and protected:
            entry["severity"] = "MEDIUM"
            entry["note"] = (
                f"Exported {comp_type} with permission protection "
                f"({comp.get('permission', 'unknown')}). "
                "Access is restricted to apps holding the required permission."
            )
        else:
            entry["severity"] = "INFO"
            entry["note"] = f"Internal {comp_type} — not exported."

        analyzed.append(entry)

    return analyzed, counts
