"""
pii_engine.py — Fast PII detection using single-pass regex
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
        lambda m: "***-***-" + re.sub(r'\D','',m)[-4:]
    ),
    "email": (
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        lambda m: (
            m.split("@")[0][0] + "*" * (len(m.split("@")[0])-1)
            + "@" + "*" * len(m.split("@")[1].rsplit(".",1)[0])
            + "." + m.split("@")[1].rsplit(".",1)[1]
        ) if "@" in m else "[EMAIL]"
    ),
    "ip_address": (
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        lambda m: m.split(".")[0] + "." + ".".join("X"*len(p) for p in m.split(".")[1:])
    ),
    "passport": (
        r"\b[A-Z][0-9]{7}\b",
        lambda m: m[0] + "XXXXXXX"
    ),
    "ifsc": (
        r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        lambda m: m[:5] + "XXXXXX"
    ),
    "account_number": (
        r"\b\d{9,18}\b",
        lambda m: "X" * (len(m) - 4) + m[-4:]
    ),
    "credit_card": (
        r"\b(?:\d{4}[\s\-]){3}\d{4}\b",
        lambda m: "XXXX-XXXX-XXXX-" + re.sub(r'\D','',m)[-4:]
    ),
    "cvv": (
        r"\bcvv[\s:]*\d{3,4}\b",
        lambda m: re.sub(r'\d', 'X', m)
    ),
    "upi": (
        r"\b[a-zA-Z0-9.\-_]+@(?:upi|ybl|oksbi|okaxis|okhdfcbank|paytm|apl|ibl)\b",
        lambda m: m[0] + "*" * (m.index("@") - 1) + m[m.index("@"):]
    ),
    "dob": (
        r"\b(?:0[1-9]|[12]\d|3[01])[\/\-](?:0[1-9]|1[0-2])[\/\-](?:19|20)\d{2}\b",
        lambda m: re.sub(r'\d{2}(?=[\/\-])', '**', m, count=2)
    ),
    "expiry_date": (
        r"\b(?:0[1-9]|1[0-2])\/(?:\d{2}|\d{4})\b",
        lambda m: "**/" + m.split("/")[1]
    ),
    "pincode": (
        r"\b[1-9][0-9]{5}\b",
        lambda m: m[:2] + "XXXX"
    ),
    "vehicle_number": (
        r"\b[A-Z]{2}\d{2}[A-Z]{1,2}\d{4}\b",
        lambda m: m[:4] + "XX" + m[-4:]
    ),
    "voter_id": (
        r"\b[A-Z]{3}[0-9]{7}\b",
        lambda m: m[:3] + "XXXXXXX"
    ),
    "gstin": (
        r"\b\d{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b",
        lambda m: m[:2] + "XXXXXXXXXXX" + m[-2:]
    ),
    "swift_code": (
        r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
        lambda m: m[:4] + "XXXXXXXX"
    ),
}

# ── Build combined single-pass regex ─────────────────────────────
def _clean(p):
    return re.sub(r'\(\?[a-zA-Z]+\)', '', p)

_ITEMS = list(REGEX_PATTERNS.items())
_GROUP_MAP = {}
_parts = []
for _i, (_pt, (_pat, _mk)) in enumerate(_ITEMS):
    _gn = f"g{_i}"
    _parts.append(f"(?P<{_gn}>{_clean(_pat)})")
    _GROUP_MAP[_gn] = (_pt, _mk)

_COMBINED = re.compile("|".join(_parts), re.IGNORECASE)

# ── Hint checks: skip patterns whose key chars aren't in the text ─
_HINTS = {
    "aadhaar":       lambda t: bool(re.search(r'\d{4} \d{4}', t[:1000])),
    "us_phone":      lambda t: "(" in t or "+1" in t,
    "email":         lambda t: "@" in t,
    "ip_address":    lambda t: t.count(".") > 5,
    "credit_card":   lambda t: bool(re.search(r'\d{4}[ \-]\d{4}', t[:1000])),
    "cvv":           lambda t: "cvv" in t.lower(),
    "upi":           lambda t: "@" in t,
    "dob":           lambda t: bool(re.search(r'\d{2}[/\-]\d{2}[/\-]\d{4}', t[:1000])),
    "expiry_date":   lambda t: "/" in t,
    "pincode":       lambda t: bool(re.search(r'\b[1-9]\d{5}\b', t[:1000])),
    "vehicle_number":lambda t: bool(re.search(r'\b[A-Z]{2}\d{2}', t[:1000])),
    "voter_id":      lambda t: bool(re.search(r'\b[A-Z]{3}\d{7}', t[:1000])),
    "gstin":         lambda t: bool(re.search(r'\b\d{2}[A-Z]{5}', t[:1000])),
    "swift_code":    lambda t: "swift" in t.lower() or bool(re.search(r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}', t[:500])),
    "passport":      lambda t: bool(re.search(r'\b[A-Z]\d{7}', t[:1000])),
    "ifsc":          lambda t: bool(re.search(r'\b[A-Z]{4}0', t[:1000])),
}

_COMPILED_EACH = {
    pt: re.compile(_clean(pat), re.IGNORECASE)
    for pt, (pat, _) in REGEX_PATTERNS.items()
}

NAME_PATTERN    = re.compile(r'\b(?:name|customer|patient|user)\s*[:\-]\s*([A-Z][a-z]+(?:\s[A-Z][a-z]+){1,3})', re.IGNORECASE)
ADDRESS_PATTERN = re.compile(r'\b\d+[A-Za-z]?\s*,\s*[A-Za-z\s]+(?:Road|Street|Nagar|Colony|Sector|Phase|Block|Lane|Marg|Chowk|Bazar|Plot|Flat)[A-Za-z0-9\s,\-\.]*', re.IGNORECASE)


def _mask_address(addr):
    parts = [p.strip() for p in addr.split(",")]
    num = re.match(r'(\d+[A-Za-z]?)', parts[0].strip())
    return (f"{num.group(1)}, ***, ***, ***" if num else "***, ***, ***")


def regex_scan(text: str) -> tuple:
    """
    Fast single-pass scan using hint-gated per-pattern substitution.
    Avoids the O(detections x file_size) str.replace loop entirely.
    """
    detections = []
    masked = text

    for pt, (pat, masker) in REGEX_PATTERNS.items():
        hint = _HINTS.get(pt)
        if hint and not hint(masked):
            continue
        cpat = _COMPILED_EACH[pt]
        found = []
        def _rep(m, _pt=pt, _mk=masker, _f=found):
            v = m.group()
            try:    mv = _mk(v)
            except: mv = "[REDACTED]"
            _f.append({"pii_type": _pt, "original_value": v, "masked_value": mv,
                       "detection_method": "regex", "confidence": 1.0})
            return mv
        masked = cpat.sub(_rep, masked)
        detections.extend(found)

    return masked, detections


def name_address_scan(text: str) -> tuple:
    detections = []
    masked = text

    if any(k in masked for k in ("Name:", "name:", "customer", "Customer", "patient", "Mr.", "Dr.")):
        for match in NAME_PATTERN.finditer(masked):
            v = match.group(1).strip()
            if len(v) > 2:
                detections.append({"pii_type": "name", "original_value": v,
                                   "masked_value": "[NAME REDACTED]",
                                   "detection_method": "pattern", "confidence": 0.9})
                masked = masked.replace(v, "[NAME REDACTED]", 1)

    if any(k in masked for k in ("Road", "Street", "Nagar", "Colony", "Sector", "Phase", "Block")):
        for match in ADDRESS_PATTERN.finditer(masked):
            v = match.group().strip()
            if len(v) > 10:
                mv = _mask_address(v)
                detections.append({"pii_type": "address", "original_value": v,
                                   "masked_value": mv,
                                   "detection_method": "pattern", "confidence": 0.85})
                masked = masked.replace(v, mv, 1)

    return masked, detections


def full_scan(text: str) -> tuple:
    after_regex, regex_dets = regex_scan(text)
    after_names, name_dets  = name_address_scan(after_regex)
    return after_names, regex_dets + name_dets


def build_pii_summary(detections: list) -> dict:
    summary = {}
    for d in detections:
        summary[d["pii_type"]] = summary.get(d["pii_type"], 0) + 1
    return summary
