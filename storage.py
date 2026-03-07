"""
storage.py — Supabase Storage (cloud file storage)
Files are stored in Supabase Storage buckets:
  - pii-originals  → original uploaded files
  - pii-sanitized  → redacted/sanitized files
"""
import os
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

# Bridge Streamlit Cloud secrets → environment variables
try:
    import streamlit as st
    if hasattr(st, "secrets"):
        for _k, _v in st.secrets.items():
            os.environ.setdefault(_k, str(_v))
except Exception:
    pass

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

BUCKET_ORIGINALS  = "pii-originals"
BUCKET_SANITIZED  = "pii-sanitized"


def get_client():
    return create_client(SUPABASE_URL, SUPABASE_KEY)


def _get_bucket(r2_key: str) -> tuple:
    """Determine bucket and path from key prefix."""
    if r2_key.startswith("originals/"):
        return BUCKET_ORIGINALS, r2_key[len("originals/"):]
    elif r2_key.startswith("sanitized/"):
        return BUCKET_SANITIZED, r2_key[len("sanitized/"):]
    return BUCKET_ORIGINALS, r2_key


def _sanitize_path(path: str) -> str:
    """Remove spaces and special chars from storage path."""
    import re
    # Replace spaces and invalid chars with underscore
    filename = path.split("/")[-1]
    folder = "/".join(path.split("/")[:-1])
    clean_filename = re.sub(r"[^\w.\-]", "_", filename)
    return f"{folder}/{clean_filename}" if folder else clean_filename


def upload_file(file_bytes: bytes, r2_key: str, content_type: str = "application/octet-stream") -> str:
    """Upload file to Supabase Storage."""
    sb = get_client()
    clean_key = _sanitize_path(r2_key)
    bucket, path = _get_bucket(clean_key)
    sb.storage.from_(bucket).upload(
        path=path,
        file=file_bytes,
        file_options={"content-type": content_type, "upsert": "true"}
    )
    return clean_key


def download_file(r2_key: str) -> bytes:
    """Download file from Supabase Storage."""
    sb = get_client()
    clean_key = _sanitize_path(r2_key)
    bucket, path = _get_bucket(clean_key)
    return sb.storage.from_(bucket).download(path)





def delete_file(r2_key: str):
    """Delete file from Supabase Storage."""
    try:
        sb = get_client()
        bucket, path = _get_bucket(r2_key)
        sb.storage.from_(bucket).remove([path])
    except Exception as e:
        print(f"[Storage delete error] {e}")


def get_presigned_url(r2_key: str, expires_in: int = 3600) -> str:
    """Get a signed URL for temporary access."""
    try:
        sb = get_client()
        bucket, path = _get_bucket(r2_key)
        res = sb.storage.from_(bucket).create_signed_url(path, expires_in)
        return res.get("signedURL", "")
    except Exception as e:
        print(f"[Storage URL error] {e}")
        return ""


def get_content_type(filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower()
    mapping = {
        "pdf":  "application/pdf",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "sql":  "text/plain",
        "csv":  "text/csv",
        "txt":  "text/plain",
        "json": "application/json",
        "png":  "image/png",
        "jpg":  "image/jpeg",
        "jpeg": "image/jpeg",
    }
    return mapping.get(ext, "application/octet-stream")
