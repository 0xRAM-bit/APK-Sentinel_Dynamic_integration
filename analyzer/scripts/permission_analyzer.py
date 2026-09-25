"""Permission analyzer with classification and correlation engine.

Classifies Android permissions into risk levels and detects suspicious
permission combinations. Does NOT treat any single permission as proof
of malware.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

# ── Permission classification database ────────────────────────────────

PERMISSION_DB: Dict[str, Dict[str, str]] = {
    # NORMAL
    "android.permission.INTERNET": {
        "classification": "NORMAL",
        "description": "Allows the app to access the internet",
    },
    "android.permission.ACCESS_NETWORK_STATE": {
        "classification": "NORMAL",
        "description": "Allows the app to check network connectivity",
    },
    "android.permission.ACCESS_WIFI_STATE": {
        "classification": "NORMAL",
        "description": "Allows the app to check Wi-Fi state",
    },
    "android.permission.VIBRATE": {
        "classification": "NORMAL",
        "description": "Allows the app to use the vibration motor",
    },
    "android.permission.WAKE_LOCK": {
        "classification": "NORMAL",
        "description": "Allows the app to prevent the device from sleeping",
    },
    "android.permission.FOREGROUND_SERVICE": {
        "classification": "NORMAL",
        "description": "Allows the app to run foreground services",
    },

    # DANGEROUS
    "android.permission.READ_SMS": {
        "classification": "DANGEROUS",
        "description": "Allows the app to read SMS messages",
    },
    "android.permission.RECEIVE_SMS": {
        "classification": "DANGEROUS",
        "description": "Allows the app to receive SMS messages",
    },
    "android.permission.SEND_SMS": {
        "classification": "DANGEROUS",
        "description": "Allows the app to send SMS messages",
    },
    "android.permission.READ_CONTACTS": {
        "classification": "DANGEROUS",
        "description": "Allows the app to read contacts",
    },
    "android.permission.WRITE_CONTACTS": {
        "classification": "DANGEROUS",
        "description": "Allows the app to write contacts",
    },
    "android.permission.READ_CALL_LOG": {
        "classification": "DANGEROUS",
        "description": "Allows the app to read call log",
    },
    "android.permission.WRITE_CALL_LOG": {
        "classification": "DANGEROUS",
        "description": "Allows the app to write call log",
    },
    "android.permission.RECORD_AUDIO": {
        "classification": "DANGEROUS",
        "description": "Allows the app to record audio via microphone",
    },
    "android.permission.CAMERA": {
        "classification": "DANGEROUS",
        "description": "Allows the app to access the camera",
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "classification": "DANGEROUS",
        "description": "Allows the app to access precise GPS location",
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "classification": "DANGEROUS",
        "description": "Allows the app to access approximate location",
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "classification": "DANGEROUS",
        "description": "Allows the app to access location in the background",
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "classification": "DANGEROUS",
        "description": "Allows the app to read external storage",
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "classification": "DANGEROUS",
        "description": "Allows the app to write to external storage",
    },
    "android.permission.READ_PHONE_STATE": {
        "classification": "DANGEROUS",
        "description": "Allows the app to read phone state and identity",
    },
    "android.permission.CALL_PHONE": {
        "classification": "DANGEROUS",
        "description": "Allows the app to make phone calls",
    },

    # SPECIAL
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "classification": "SPECIAL",
        "description": "Allows the app to draw overlays on top of other apps",
    },
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "classification": "SPECIAL",
        "description": "Allows the app to start at boot",
    },
    "android.permission.PACKAGE_USAGE_STATS": {
        "classification": "SPECIAL",
        "description": "Allows the app to collect usage statistics of other apps",
    },

    # HIGH_RISK
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "classification": "HIGH_RISK",
        "description": "Allows the app to request installation of other packages",
    },
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "classification": "HIGH_RISK",
        "description": "Allows the app to bind to accessibility services (broad device control)",
    },
    "android.permission.BIND_DEVICE_ADMIN": {
        "classification": "HIGH_RISK",
        "description": "Allows the app to act as a device administrator",
    },
    "android.permission.READ_LOGS": {
        "classification": "HIGH_RISK",
        "description": "Allows the app to read system logs",
    },
}

# ── Correlation rules ─────────────────────────────────────────────────

CORRELATION_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "CORR_SMS_INTERNET",
        "permissions": ["android.permission.READ_SMS", "android.permission.INTERNET"],
        "severity": "HIGH",
        "points": 8,
        "description": "SMS read access combined with internet access — could exfiltrate SMS data",
    },
    {
        "rule_id": "CORR_RECEIVE_SMS_INTERNET",
        "permissions": ["android.permission.RECEIVE_SMS", "android.permission.INTERNET"],
        "severity": "HIGH",
        "points": 8,
        "description": "SMS interception combined with internet access — could intercept and forward SMS (e.g., 2FA codes)",
    },
    {
        "rule_id": "CORR_CONTACTS_INTERNET",
        "permissions": ["android.permission.READ_CONTACTS", "android.permission.INTERNET"],
        "severity": "MEDIUM",
        "points": 6,
        "description": "Contacts read access combined with internet — could exfiltrate contact data",
    },
    {
        "rule_id": "CORR_AUDIO_INTERNET",
        "permissions": ["android.permission.RECORD_AUDIO", "android.permission.INTERNET"],
        "severity": "HIGH",
        "points": 8,
        "description": "Microphone recording combined with internet access — could stream audio",
    },
    {
        "rule_id": "CORR_LOCATION_INTERNET",
        "permissions": ["android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"],
        "severity": "MEDIUM",
        "points": 6,
        "description": "Precise location combined with internet access — could track device location",
    },
    {
        "rule_id": "CORR_CAMERA_INTERNET",
        "permissions": ["android.permission.CAMERA", "android.permission.INTERNET"],
        "severity": "MEDIUM",
        "points": 6,
        "description": "Camera access combined with internet — could capture and upload images",
    },
    {
        "rule_id": "CORR_BOOT_INTERNET",
        "permissions": ["android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.INTERNET"],
        "severity": "MEDIUM",
        "points": 5,
        "description": "Boot start combined with internet — persistent background activity possible",
    },
    {
        "rule_id": "CORR_INSTALL_INTERNET",
        "permissions": ["android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INTERNET"],
        "severity": "HIGH",
        "points": 10,
        "description": "Package installation combined with internet — could download and install additional apps",
    },
    {
        "rule_id": "CORR_SEND_SMS_INTERNET",
        "permissions": ["android.permission.SEND_SMS", "android.permission.INTERNET"],
        "severity": "HIGH",
        "points": 8,
        "description": "SMS sending combined with internet — could send premium SMS or spam",
    },
]


def analyze_permissions(
    raw_permissions: List[str],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Classify permissions and detect suspicious combinations.

    Args:
        raw_permissions: List of permission strings from manifest.

    Returns:
        Tuple of (classified_permissions, triggered_correlations).
    """
    # ── Classify each permission ──────────────────────────────────────
    classified: List[Dict[str, Any]] = []
    perm_set = set(raw_permissions)

    for perm in raw_permissions:
        short_name = perm.split(".")[-1] if "." in perm else perm

        if perm in PERMISSION_DB:
            info = PERMISSION_DB[perm]
            classified.append({
                "name": short_name,
                "full_name": perm,
                "classification": info["classification"],
                "description": info["description"],
            })
        else:
            # Unknown/custom permission
            classified.append({
                "name": short_name,
                "full_name": perm,
                "classification": "NORMAL",
                "description": f"Custom or unrecognized permission: {perm}",
            })

    # ── Check correlation rules ───────────────────────────────────────
    correlations: List[Dict[str, Any]] = []
    for rule in CORRELATION_RULES:
        required = set(rule["permissions"])
        if required.issubset(perm_set):
            matched_short = [p.split(".")[-1] for p in rule["permissions"]]
            correlations.append({
                "rule_id": rule["rule_id"],
                "severity": rule["severity"],
                "points": rule["points"],
                "description": rule["description"],
                "evidence": " + ".join(matched_short),
                "matched_permissions": list(rule["permissions"]),
            })

    return classified, correlations
