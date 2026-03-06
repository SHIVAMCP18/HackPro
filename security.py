"""
security.py — File security checks before processing

1. Malicious script/content detection
2. File hash generation
3. SIEM-compatible audit log export
"""

import re
import hashlib
import json
from datetime import datetime


# ── MALICIOUS CONTENT PATTERNS ───────────────────────────────────

MALICIOUS_PATTERNS = {
    "sql_injection": [
        r"(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE)",
        r"(DELETE\s+FROM\s+\w+\s+WHERE\s+1\s*=\s*1)",
        r"(INSERT\s+INTO.*SELECT\s+\*)",
        r"(UNION\s+SELECT.*FROM)",
        r"(xp_cmdshell|exec\s*\(|execute\s*\()",
        r"(;\s*DROP|;\s*DELETE|;\s*TRUNCATE|;\s*ALTER)",
    ],

    "xss": [
        r"<script[^>]*>.*?</script>",
        r"javascript\s*:",
        r"on(load|click|mouseover|error|focus)\s*=",
        r"<iframe[^>]*>",
        r"document\.cookie",
        r"window\.location",
    ],

    "shell_commands": [
        r"(rm\s+-rf|rmdir\s+/s)",
        r"(wget|curl)\s+https?://",
        r"(bash|sh|cmd|powershell)\s+-c",
        r"(__import__\s*\(\s*['\"]os['\"]|subprocess\.call|os\.system)",
        r"(eval\s*\(|exec\s*\()",
        r"/etc/passwd|/etc/shadow",
    ],

    "path_traversal": [
        r"\.\./\.\./",
        r"%2e%2e%2f",
        r"\.\.\\",
    ],
}


# ── FILE HASH GENERATION ─────────────────────────────────────────

def calculate_hashes(file_bytes: bytes) -> dict:
    """
    Calculate MD5, SHA1, SHA256 hashes of file.
    Useful for integrity and logging.
    """

    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
    }


# ── MALICIOUS CONTENT SCAN ───────────────────────────────────────

def scan_for_malicious_content(file_bytes: bytes, filename: str) -> dict:
    """
    Scan file content for malicious patterns.

    Returns:
    {
        safe: bool,
        threats: list,
        details: dict
    }
    """

    threats = []
    details = {}

    ext = filename.rsplit(".", 1)[-1].lower()

    # Skip binary images
    if ext in ("png", "jpg", "jpeg"):
        return {"safe": True, "threats": [], "details": {}}

    try:
        text = file_bytes.decode("utf-8", errors="replace")
    except Exception:
        return {"safe": True, "threats": [], "details": {}}

    for threat_type, patterns in MALICIOUS_PATTERNS.items():

        matches = []

        for pattern in patterns:

            found = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)

            if found:
                matches.extend(found[:3])

        if matches:
            threats.append(threat_type)
            details[threat_type] = matches

    return {
        "safe": len(threats) == 0,
        "threats": threats,
        "details": details,
    }


# ── FULL SECURITY SCAN ───────────────────────────────────────────

def full_security_scan(file_bytes: bytes, filename: str) -> dict:
    """
    Run complete security scan on file.

    Steps:
    1. Generate hashes
    2. Scan for malicious patterns
    """

    hashes = calculate_hashes(file_bytes)

    malicious_scan = scan_for_malicious_content(file_bytes, filename)

    safe = malicious_scan["safe"]

    return {
        "safe": safe,
        "filename": filename,
        "file_size": len(file_bytes),
        "hashes": hashes,
        "malicious_content": malicious_scan,
        "scanned_at": datetime.utcnow().isoformat() + "Z",
    }


# ── SIEM-COMPATIBLE AUDIT LOG EXPORT ─────────────────────────────

def format_siem_log(log_entry: dict) -> dict:
    """
    Format logs in SIEM-compatible structure.
    Works with Splunk, ELK, QRadar.
    """

    return {
        "@timestamp": str(log_entry.get("timestamp", datetime.utcnow().isoformat())),
        "event": {
            "kind": "event",
            "category": "file" if log_entry.get("file_id") else "authentication",
            "action": log_entry.get("action", "unknown"),
            "outcome": "success",
        },
        "user": {
            "name": log_entry.get("username", "unknown"),
        },
        "file": {
            "name": log_entry.get("original_filename", ""),
        },
        "source": {
            "ip": log_entry.get("ip_address", ""),
        },
        "metadata": log_entry.get("details", {}),
        "host": {
            "name": "pii-sanitizer",
        },
        "tags": ["pii-sanitizer", "hackamined-2025"],
    }


def export_siem_logs(logs: list) -> str:
    """
    Export logs as NDJSON (one JSON per line).
    """

    lines = []

    for log in logs:

        siem_log = format_siem_log(log)

        lines.append(json.dumps(siem_log))

    return "\n".join(lines)