"""AndroidManifest.xml analyzer.

Parses the decoded AndroidManifest.xml from APKTool output to extract
APK metadata, permissions, components, and intent filters.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional


ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _attr(element: ET.Element, name: str) -> Optional[str]:
    """Get an android-namespaced attribute value."""
    return element.get(f"{{{ANDROID_NS}}}{name}")


def analyze_manifest(output_dir: Path) -> Dict[str, Any]:
    """Parse AndroidManifest.xml and extract metadata and components.

    Args:
        output_dir: The analysis output directory containing apktool/ subdirectory.

    Returns:
        Dict with 'apk' metadata, 'permissions', and raw 'components' list.
    """
    manifest_path = output_dir / "apktool" / "AndroidManifest.xml"

    if not manifest_path.exists():
        return {
            "apk": {},
            "raw_permissions": [],
            "raw_components": [],
            "error": "AndroidManifest.xml not found",
        }

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError as e:
        return {
            "apk": {},
            "raw_permissions": [],
            "raw_components": [],
            "error": f"Failed to parse AndroidManifest.xml: {e}",
        }

    # ── APK Metadata ──────────────────────────────────────────────────
    package = root.get("package", "unknown")
    version_name = _attr(root, "versionName") or ""
    version_code = _attr(root, "versionCode") or ""

    # SDK versions from <uses-sdk>
    uses_sdk = root.find("uses-sdk")
    min_sdk = None
    target_sdk = None
    if uses_sdk is not None:
        min_sdk_str = _attr(uses_sdk, "minSdkVersion")
        target_sdk_str = _attr(uses_sdk, "targetSdkVersion")
        min_sdk = int(min_sdk_str) if min_sdk_str and min_sdk_str.isdigit() else None
        target_sdk = int(target_sdk_str) if target_sdk_str and target_sdk_str.isdigit() else None

    # Application label
    app_elem = root.find("application")
    app_label = _attr(app_elem, "label") if app_elem is not None else None

    apk_metadata = {
        "package": package,
        "application_label": app_label,
        "version_name": version_name,
        "version_code": version_code,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
    }

    # ── Permissions ───────────────────────────────────────────────────
    raw_permissions: List[str] = []
    for perm_elem in root.findall("uses-permission"):
        perm_name = _attr(perm_elem, "name")
        if perm_name:
            raw_permissions.append(perm_name)

    # ── Components ────────────────────────────────────────────────────
    component_types = {
        "activity": "activity",
        "service": "service",
        "receiver": "receiver",
        "provider": "provider",
    }

    raw_components: List[Dict[str, Any]] = []

    if app_elem is not None:
        for tag, comp_type in component_types.items():
            for comp_elem in app_elem.findall(tag):
                name = _attr(comp_elem, "name") or "unknown"
                exported_attr = _attr(comp_elem, "exported")
                permission = _attr(comp_elem, "permission")

                # Determine exported status
                intent_filters = _parse_intent_filters(comp_elem)
                has_intent_filter = len(intent_filters) > 0

                if exported_attr is not None:
                    exported = exported_attr.lower() == "true"
                else:
                    # Before target SDK 31, components with intent-filters
                    # were implicitly exported
                    exported = has_intent_filter and (
                        target_sdk is None or target_sdk < 31
                    )

                raw_components.append({
                    "name": name,
                    "type": comp_type,
                    "exported": exported,
                    "permission": permission,
                    "permission_protected": permission is not None and permission != "",
                    "intent_filters": intent_filters,
                    "has_intent_filter": has_intent_filter,
                })

    return {
        "apk": apk_metadata,
        "raw_permissions": raw_permissions,
        "raw_components": raw_components,
    }


def _parse_intent_filters(component: ET.Element) -> List[Dict[str, Any]]:
    """Parse intent-filter elements from a component."""
    filters = []
    for if_elem in component.findall("intent-filter"):
        actions = []
        categories = []
        data_schemes = []

        for action in if_elem.findall("action"):
            action_name = _attr(action, "name")
            if action_name:
                actions.append(action_name)

        for category in if_elem.findall("category"):
            cat_name = _attr(category, "name")
            if cat_name:
                categories.append(cat_name)

        for data in if_elem.findall("data"):
            scheme = _attr(data, "scheme")
            if scheme:
                data_schemes.append(scheme)

        filters.append({
            "actions": actions,
            "categories": categories,
            "data_schemes": data_schemes,
        })

    return filters
