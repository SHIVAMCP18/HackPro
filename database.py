"""
database.py — Supabase client-based DB layer (no raw Postgres connection needed)
Only requires SUPABASE_URL and SUPABASE_KEY from .env
"""
import os
import bcrypt
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

def get_client() -> Client:
    return create_client(SUPABASE_URL, SUPABASE_KEY)


# ── AUTH ─────────────────────────────────────────────────────────

def get_user_by_username(username: str):
    sb = get_client()
    res = sb.table("users").select("*").eq("username", username).eq("is_active", True).execute()
    return res.data[0] if res.data else None


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_user(username: str, email: str, password: str, role: str = "standard"):
    sb = get_client()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    res = sb.table("users").insert({
        "username": username,
        "email": email,
        "password_hash": hashed,
        "role": role
    }).execute()
    return res.data[0]["id"] if res.data else None


def get_all_users():
    sb = get_client()
    res = sb.table("users").select("id, username, email, role, created_at, is_active").order("created_at", desc=True).execute()
    return res.data or []


# ── FILES ────────────────────────────────────────────────────────

def create_file_record(original_filename, file_type, uploaded_by, original_r2_key):
    sb = get_client()
    res = sb.table("files").insert({
        "original_filename": original_filename,
        "file_type": file_type,
        "uploaded_by": uploaded_by,
        "original_r2_key": original_r2_key,
        "status": "processing"
    }).execute()
    return res.data[0]["id"] if res.data else None


def update_file_record(file_id, sanitized_r2_key, pii_count, pii_summary, status="done"):
    sb = get_client()
    sb.table("files").update({
        "sanitized_r2_key": sanitized_r2_key,
        "pii_count": pii_count,
        "pii_summary": pii_summary,
        "status": status
    }).eq("id", file_id).execute()


def get_all_files():
    sb = get_client()
    res = sb.table("files").select("*, users(username)").order("upload_time", desc=True).execute()
    files = []
    for f in (res.data or []):
        f["uploader"] = f.get("users", {}).get("username") if f.get("users") else None
        files.append(f)
    return files


def get_files_by_user(user_id: str) -> list:
    """Get only files uploaded by a specific user."""
    sb = get_client()
    res = sb.table("files").select("*, users!files_uploaded_by_fkey(username)").eq("uploaded_by", user_id).order("upload_time", desc=True).execute()
    rows = res.data or []
    for r in rows:
        r["uploader"] = (r.get("users") or {}).get("username", "unknown")
        r.pop("users", None)
    return rows


def get_file_by_id(file_id):
    sb = get_client()
    res = sb.table("files").select("*").eq("id", file_id).execute()
    return res.data[0] if res.data else None


# ── PII DETECTIONS ───────────────────────────────────────────────

def save_pii_detections(file_id, detections: list):
    if not detections:
        return
    sb = get_client()
    rows = [{
        "file_id": file_id,
        "pii_type": d["pii_type"],
        "original_value": d["original_value"],
        "masked_value": d["masked_value"],
        "detection_method": d.get("detection_method", "regex"),
        "confidence": d.get("confidence", 1.0)
    } for d in detections]
    sb.table("pii_detections").insert(rows).execute()


def get_pii_detections(file_id):
    sb = get_client()
    res = sb.table("pii_detections").select("*").eq("file_id", file_id).order("pii_type").execute()
    return res.data or []


# ── AUDIT LOGS ───────────────────────────────────────────────────

def log_action(user_id, action, file_id=None, details=None, ip_address=None):
    sb = get_client()
    sb.table("audit_logs").insert({
        "user_id": user_id,
        "action": action,
        "file_id": file_id,
        "details": details or {},
        "ip_address": ip_address
    }).execute()


def get_user_activity(user_id: str, limit: int = 200) -> list:
    """Get all audit logs for a specific user including login/logout times."""
    sb = get_client()
    res = sb.table("audit_logs").select(
        "*, files(original_filename)"
    ).eq("user_id", user_id).order("timestamp", desc=True).limit(limit).execute()

    logs = []
    for log in (res.data or []):
        log["original_filename"] = (log.get("files") or {}).get("original_filename", "")
        log.pop("files", None)
        logs.append(log)
    return logs


def record_failed_login(username: str):
    """Log a failed login attempt to audit_logs."""
    sb = get_client()
    sb.table("audit_logs").insert({
        "user_id": None,
        "action": "failed_login",
        "file_id": None,
        "details": {"username": username},
        "ip_address": None
    }).execute()


def get_failed_logins():
    """Get failed login counts grouped by username for admin view."""
    sb = get_client()
    res = sb.table("audit_logs").select("details, timestamp").eq("action", "failed_login").order("timestamp", desc=True).execute()
    counts = {}
    recent = {}
    for row in (res.data or []):
        uname = (row.get("details") or {}).get("username", "unknown")
        counts[uname] = counts.get(uname, 0) + 1
        if uname not in recent:
            recent[uname] = str(row.get("timestamp", ""))[:19].replace("T", " ")
    return [{"username": u, "attempts": c, "last_attempt": recent[u]} for u, c in sorted(counts.items(), key=lambda x: x[1], reverse=True)]


def change_password(user_id: str, new_password: str):
    sb = get_client()
    hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    sb.table("users").update({"password_hash": hashed}).eq("id", user_id).execute()


def delete_file_record(file_id: str):
    """Delete file and related records from DB (admin only)."""
    sb = get_client()
    sb.table("pii_detections").delete().eq("file_id", file_id).execute()
    sb.table("audit_logs").delete().eq("file_id", file_id).execute()
    sb.table("files").delete().eq("id", file_id).execute()


def get_pii_summary_all():
    """Aggregate PII type counts across all files from pii_summary JSONB."""
    sb = get_client()
    res = sb.table("files").select("pii_summary").eq("status", "done").execute()
    totals = {}
    for row in (res.data or []):
        summary = row.get("pii_summary") or {}
        for pii_type, count in summary.items():
            totals[pii_type] = totals.get(pii_type, 0) + (count or 0)
    return totals


def get_audit_logs(limit=100):
    sb = get_client()
    res = sb.table("audit_logs").select(
        "*, users(username), files(original_filename)"
    ).order("timestamp", desc=True).limit(limit).execute()

    logs = []
    for log in (res.data or []):
        log["username"] = log.get("users", {}).get("username") if log.get("users") else None
        log["original_filename"] = log.get("files", {}).get("original_filename") if log.get("files") else None
        logs.append(log)
    return logs
