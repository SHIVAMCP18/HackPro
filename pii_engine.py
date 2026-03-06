"""
pii_engine.py — PII Detection using Regex only (no external API)
"""
import re

REGEX_PATTERNS = {
    "aadhaar": (
        r"\b\d{4}\s\d{4}\s\d{4}\b",
        lambda m: m[:4] + " XXXX XXXX"
    ),
    "pan": (
        r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        lambda m: m[:2] + "XXX" + m[5:]
    ),
    "phone": (
        r"(?<!\d)(\+91[\s\-]?)?[6-9]\d{9}(?!\d)",
        lambda m: (
            m[:4] + "X" * (len(m) - 6) + m[-2:]
            if m.startswith("+91") else
            m[0] + "X" * (len(m) - 3) + m[-2:]
        )
    ),
    "us_phone": (
        r"\b(\+1[\s\-]?)?\(?\d{3}\)?[\s\-]\d{3}[\s\-]\d{4}\b",
        lambda m: "***-***-" + m.replace(" ", "").replace("-", "").replace("(","").replace(")","")[-4:]
    ),
    "email": (
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        lambda m: (
            (lambda local, domain:
                ".".join(
                    p[0] + "*" * (len(p) - 1) if len(p) > 1 else p
                    for p in local.split(".")
                ) + "@" + domain
            )(m.split("@")[0], m.split("@")[1])
        ) if "@" in m else "[EMAIL]"
    ),
    "ip_address": (
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        lambda m: m.split(".")[0] + "." + ".".join("X" * len(p) for p in m.split(".")[1:])
    ),
    "passport": (
        r"\b[A-Z][0-9]{7}\b",
        lambda m: m[0] + "XXXXXXX"
    ),
    "ifsc": (
        r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        lambda m: m[:4] + "0XXXXXX"
    ),
    "account_number": (
        r"\b(?!(?:[6-9]\d{9})\b)\d{9,18}\b",
        lambda m: "X" * (len(m) - 4) + m[-4:]
    ),
    "upi": (
        r"\b[a-zA-Z0-9.\-_]{2,256}@(?:upi|oksbi|okaxis|okicici|okhdfcbank|paytm|ybl|ibl|axl|waicici|wahdfcbank)\b",
        lambda m: m[0] + "***@" + m.split("@")[1] if "@" in m else "[UPI]"
    ),
    "credit_card": (
        r"\b(?:\d{4}[\s\-]){3}\d{4}\b",
        lambda m: m.replace(" ", "").replace("-", "")[:4] + " **** **** " + m.replace(" ", "").replace("-", "")[-4:]
    ),
    "cvv": (
        r"\bcvv[\s:]*\d{3,4}\b|\bCVV[\s:]*\d{3,4}\b",
        lambda m: re.sub(r"\d{3,4}", "***", m)
    ),
    "expiry_date": (
        r"\b(0[1-9]|1[0-2])\/([0-9]{2,4})\b",
        lambda m: "**/" + m.split("/")[1]
    ),

    "device_id": (
        r"\b(?:android|ios)-[a-f0-9]{8,}\b",
        lambda m: m.split("-")[0] + "-XXXXXXXX"
    ),
    "fingerprint": (
        r"\bfp_hash_[a-f0-9]+\b",
        lambda m: "fp_hash_XXXXXXXX"
    ),
    "face_template": (
        r"\bface_tmp_[a-f0-9]+\b",
        lambda m: "face_tmp_XXXXXXXX"
    ),
    "dob": (
        r"\b(0?[1-9]|[12]\d|3[01])[\/\-](0?[1-9]|1[0-2])[\/\-](19|20)\d{2}\b",
        lambda m: "[DOB REDACTED]"
    ),
    "pincode": (
        r"(?i)(?:pin|pincode|zip)[\s:]*[1-9][0-9]{5}\b",
        lambda m: re.sub(r"[1-9][0-9]{5}", "XXXXXX", m)
    ),
    "vehicle_number": (
        r"\b[A-Z]{2}[\s\-]?\d{2}[\s\-]?[A-Z]{1,2}[\s\-]?\d{4}\b",
        lambda m: "[VEHICLE REDACTED]"
    ),
    "voter_id": (
        r"\b[A-Z]{3}[0-9]{7}\b",
        lambda m: "[VOTER ID REDACTED]"
    ),
    "gstin": (
        r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b",
        lambda m: "[GSTIN REDACTED]"
    ),
    "swift_code": (
        r"(?i)(?:swift|bic)[\s:]+([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)",
        lambda m: re.sub(r"[A-Z]{6}[A-Z0-9]{2,5}", "[SWIFT REDACTED]", m, flags=re.IGNORECASE)
    ),
}

# ── NAME & ADDRESS PATTERNS ───────────────────────────────────────

NAME_PATTERN = re.compile(
    r"\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?|Shri|Smt\.?|Sri)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b"
)

ADDRESS_PATTERN = re.compile(
    r"\b\d+[,\s]+[A-Za-z0-9\s,\-\.]+(?:Road|Street|Nagar|Colony|Sector|Phase|Block|Avenue|Lane|Marg|Chowk|Layout|Extension|Society|Residency|Apartments?|Towers?|Floor|Flat|Plot)[^.\n]{0,60}",
    re.IGNORECASE
)

def _mask_address(address: str) -> str:
    """Show house number only, hide everything else."""
    parts = [p.strip() for p in address.split(",")]
    # Extract just the leading number
    import re as _re
    num_match = _re.match(r"(\d+[A-Za-z]?)", parts[0].strip())
    if num_match:
        visible = num_match.group(1)
        return f"{visible}, ***, ***, ***"
    # No number found — hide everything
    return "***, ***, ***"


def regex_scan(text: str) -> tuple:
    detections = []
    masked = text

    for pii_type, (pattern, masker) in REGEX_PATTERNS.items():
        for match in re.finditer(pattern, masked, re.IGNORECASE):
            original = match.group()
            try:
                masked_val = masker(original)
            except Exception:
                masked_val = "[REDACTED]"
            detections.append({
                "pii_type":         pii_type,
                "original_value":   original,
                "masked_value":     masked_val,
                "detection_method": "regex",
                "confidence":       1.0,
            })

    for d in detections:
        masked = masked.replace(d["original_value"], d["masked_value"], 1)

    return masked, detections


def name_address_scan(text: str) -> tuple:
    detections = []
    masked = text

    for match in NAME_PATTERN.finditer(masked):
        original = match.group()
        detections.append({
            "pii_type":         "name",
            "original_value":   original,
            "masked_value":     "[NAME REDACTED]",
            "detection_method": "pattern",
            "confidence":       0.9,
        })

    for match in ADDRESS_PATTERN.finditer(masked):
        original = match.group().strip()
        if len(original) > 10:
            detections.append({
                "pii_type":         "address",
                "original_value":   original,
                "masked_value":     _mask_address(original),
                "detection_method": "pattern",
                "confidence":       0.85,
            })

    for d in detections:
        masked = masked.replace(d["original_value"], d["masked_value"], 1)

    return masked, detections


def full_scan(text: str) -> tuple:
    after_regex, regex_detections = regex_scan(text)
    after_names, name_detections = name_address_scan(after_regex)
    return after_names, regex_detections + name_detections


def gemini_scan(text: str, already_masked_types: list = None) -> tuple:
    """Replaced by local pattern scan — no external API."""
    return name_address_scan(text)


def build_pii_summary(detections: list) -> dict:
    summary = {}
    for d in detections:
        t = d["pii_type"]
        summary[t] = summary.get(t, 0) + 1
    return summary