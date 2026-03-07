"""
app.py — Main Streamlit application
ShieldGate | Nirma HACKATHON 2026
"""
import uuid
import streamlit as st
import pandas as pd
from datetime import datetime

from auth import require_login, require_admin, is_admin, current_user, logout, show_login_page
from security import full_security_scan, export_siem_logs
from database import (
    get_all_files,
    get_files_by_user,
    get_user_activity, get_file_by_id, create_file_record, update_file_record,
    save_pii_detections, get_pii_detections, get_audit_logs, log_action,
    get_all_users, create_user, get_pii_summary_all, delete_file_record, change_password, get_failed_logins
)
from storage import upload_file, download_file, get_presigned_url, get_content_type
from file_processor import process_file, extract_preview_text
from pii_engine import build_pii_summary

# ── PAGE CONFIG ──────────────────────────────────────────────────

st.set_page_config(
    page_title="ShieldGate",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── GLOBAL CSS ───────────────────────────────────────────────────

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:ital,wght@0,300;0,400;0,500;0,600;1,400&display=swap');

/* Base */
html, body, [class*="css"] {
    font-family: 'DM Sans', sans-serif;
}
.stApp {
    background: #080b12;
    color: #e2e8f0;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #0d1117 !important;
    border-right: 1px solid #1e2433;
}
section[data-testid="stSidebar"] * {
    color: #cbd5e1 !important;
}

/* Metric cards */
.metric-card {
    background: #0f1623;
    border: 1px solid #1e2d45;
    border-radius: 12px;
    padding: 20px 24px;
    text-align: center;
}
.metric-number {
    font-family: 'Space Mono', monospace;
    font-size: 36px;
    font-weight: 700;
    color: #ff3b64;
    line-height: 1;
}
.metric-label {
    font-size: 12px;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 6px;
}

/* Section headers */
.section-header {
    font-family: 'Space Mono', monospace;
    font-size: 13px;
    color: #ff3b64;
    text-transform: uppercase;
    letter-spacing: 2px;
    margin: 28px 0 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid #1e2433;
}

/* File row */
.file-row {
    background: #0f1623;
    border: 1px solid #1e2433;
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

/* Status badges */
.badge {
    font-size: 11px;
    font-weight: 600;
    padding: 3px 10px;
    border-radius: 20px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.badge-done     { background: #052e1a; color: #34d399; border: 1px solid #065f46; }
.badge-process  { background: #1c1a05; color: #fbbf24; border: 1px solid #92400e; }
.badge-admin    { background: #1a0525; color: #c084fc; border: 1px solid #7e22ce; }
.badge-standard { background: #051a26; color: #38bdf8; border: 1px solid #0369a1; }

/* PII type chip */
.pii-chip {
    display: inline-block;
    background: #1a0f1f;
    color: #f472b6;
    border: 1px solid #831843;
    border-radius: 6px;
    padding: 2px 8px;
    font-size: 11px;
    font-family: 'Space Mono', monospace;
    margin: 2px;
}

/* Diff view */
.diff-original {
    background: #1a0f0f;
    border-left: 3px solid #ef4444;
    padding: 12px 16px;
    border-radius: 0 8px 8px 0;
    font-family: 'Space Mono', monospace;
    font-size: 12px;
    white-space: pre-wrap;
    color: #fca5a5;
    line-height: 1.6;
}
.diff-sanitized {
    background: #0a1f0a;
    border-left: 3px solid #22c55e;
    padding: 12px 16px;
    border-radius: 0 8px 8px 0;
    font-family: 'Space Mono', monospace;
    font-size: 12px;
    white-space: pre-wrap;
    color: #86efac;
    line-height: 1.6;
}

/* Buttons */
.stButton > button {
    background: #ff3b64 !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    font-family: 'DM Sans', sans-serif !important;
    font-weight: 600 !important;
}
.stButton > button:hover {
    background: #e02d55 !important;
}

/* Upload area */
[data-testid="stFileUploader"] {
    border: 2px dashed #1e2d45 !important;
    border-radius: 12px !important;
    background: #0a0f1a !important;
}

/* Tables */
.stDataFrame {
    border-radius: 10px;
    overflow: hidden;
}

/* Page title */
.page-title {
    font-family: 'Space Mono', monospace;
    font-size: 28px;
    font-weight: 700;
    color: #f1f5f9;
    margin-bottom: 4px;
}
.page-subtitle {
    color: #475569;
    font-size: 14px;
    margin-bottom: 32px;
}
</style>
""", unsafe_allow_html=True)


# ── SIDEBAR ──────────────────────────────────────────────────────

def render_sidebar():
    user = current_user()
    with st.sidebar:
        st.markdown("""
        <div style="padding: 20px 0 24px; border-bottom: 1px solid #1e2433; margin-bottom: 20px;">
            <div style="font-family:'Space Mono',monospace; font-size:18px; color:#ff3b64; font-weight:700;">
                🔐 ShieldGate
            </div>
            <div style="font-size:11px; color:#475569; margin-top:4px; letter-spacing:1px; text-transform:uppercase;">
                HACKATHON 2026
            </div>
        </div>
        """, unsafe_allow_html=True)

        if user:
            role_badge = "badge-admin" if user["role"] == "admin" else "badge-standard"
            st.markdown(f"""
            <div style="margin-bottom:20px; padding:12px; background:#0a0f1a; border-radius:8px; border:1px solid #1e2433;">
                <div style="font-size:13px; font-weight:600;">{user['username']}</div>
                <div style="margin-top:4px;">
                    <span class="badge {role_badge}">{user['role']}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Navigation
            pages = ["📊 Dashboard", "📁 Files", "✏️ Text Scan", "⬆️ Upload", "🗂️ My Files", "🔒 Change Password"]
            if is_admin():
                pages += ["🔍 Audit Logs", "👥 Users"]

            page = st.radio("Navigation", pages, label_visibility="collapsed")

            st.markdown("<div style='margin-top:auto; padding-top:40px;'>", unsafe_allow_html=True)
            st.markdown(f'<div style="font-size:11px;color:#475569;margin-bottom:8px;">⏱️ Auto-logout after 30 min inactivity</div>', unsafe_allow_html=True)
            if st.button("Sign Out", use_container_width=True):
                logout()

            return page.split(" ", 1)[1].strip()  # strip emoji

    return None


# ── DASHBOARD ────────────────────────────────────────────────────

def page_dashboard():
    st.markdown('<div class="page-title">Dashboard</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Overview of PII sanitization activity</div>', unsafe_allow_html=True)

    # Admin sees all files, standard user sees only their own
    user = current_user()
    files = get_all_files() if is_admin() else get_files_by_user(user["id"])
    done_files = [f for f in files if f["status"] == "done"]
    total_pii = sum(f["pii_count"] or 0 for f in done_files)

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f'<div class="metric-card"><div class="metric-number">{len(files)}</div><div class="metric-label">Total Files</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="metric-card"><div class="metric-number">{len(done_files)}</div><div class="metric-label">Sanitized</div></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="metric-card"><div class="metric-number">{total_pii}</div><div class="metric-label">PII Items Found</div></div>', unsafe_allow_html=True)
    with c4:
        processing = len([f for f in files if f["status"] == "processing"])
        st.markdown(f'<div class="metric-card"><div class="metric-number">{processing}</div><div class="metric-label">Processing</div></div>', unsafe_allow_html=True)

    # ── PII BREAKDOWN CHART ───────────────────────────────────────
    if done_files:
        st.markdown('<div class="section-header">📊 PII Type Breakdown</div>', unsafe_allow_html=True)

        pii_totals = {}
        for f in done_files:
            summary = f.get("pii_summary") or {}
            for pii_type, count in summary.items():
                if pii_type not in ["sql_injection", "xss", "shell_commands", "path_traversal"]:
                    pii_totals[pii_type] = pii_totals.get(pii_type, 0) + (count or 0)

        if pii_totals:
            chart_df = pd.DataFrame(
                sorted(pii_totals.items(), key=lambda x: x[1], reverse=True),
                columns=["PII Type", "Count"]
            )
            col_chart1, col_chart2 = st.columns([3, 2])
            with col_chart1:
                st.bar_chart(chart_df.set_index("PII Type"), color="#ff3b64", height=280)
            with col_chart2:
                st.dataframe(chart_df, use_container_width=True, hide_index=True, height=280)
        else:
            st.info("No PII breakdown data available yet.")

    # ── ACTIVITY TIMELINE ─────────────────────────────────────────
    if done_files:
        st.markdown('<div class="section-header">📈 Upload Activity (Last 30 Days)</div>', unsafe_allow_html=True)
        from datetime import timezone, timedelta
        now_utc = datetime.now(timezone.utc)
        cutoff = now_utc - timedelta(days=30)

        def _parse_ts(ts):
            try:
                if isinstance(ts, str):
                    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
                return ts
            except Exception:
                return now_utc

        recent = [f for f in files if _parse_ts(f["upload_time"]) >= cutoff]
        if recent:
            dates = [_parse_ts(f["upload_time"]).strftime("%Y-%m-%d") for f in recent]
            date_counts = pd.Series(dates).value_counts().sort_index()
            # Fill missing dates with 0
            all_dates = pd.date_range(cutoff.date(), now_utc.date(), freq="D").strftime("%Y-%m-%d")
            date_counts = date_counts.reindex(all_dates, fill_value=0)
            timeline_df = pd.DataFrame({"Date": date_counts.index, "Uploads": date_counts.values})
            st.line_chart(timeline_df.set_index("Date"), color="#ff3b64", height=200)
        else:
            st.info("No uploads in the last 30 days.")

    # ── PII HEATMAP BY FILE TYPE ──────────────────────────────────
    if done_files:
        st.markdown('<div class="section-header">🗺️ PII Heatmap by File Type</div>', unsafe_allow_html=True)

        HIGH_RISK_TYPES = {"aadhaar", "pan", "passport", "credit_card", "cvv", "account_number"}
        MED_RISK_TYPES  = {"phone", "us_phone", "email", "upi", "dob", "voter_id", "gstin"}

        heatmap_data = {}
        for f in done_files:
            ftype = f.get("file_type", "unknown").upper()
            summary = f.get("pii_summary") or {}
            if ftype not in heatmap_data:
                heatmap_data[ftype] = {}
            for pii_type, count in summary.items():
                if pii_type not in ["sql_injection", "xss", "shell_commands", "path_traversal"]:
                    heatmap_data[ftype][pii_type] = heatmap_data[ftype].get(pii_type, 0) + (count or 0)

        if heatmap_data:
            heatmap_df = pd.DataFrame(heatmap_data).fillna(0).astype(int)
            col_h1, col_h2 = st.columns([3, 2])
            with col_h1:
                st.dataframe(
                    heatmap_df.style.background_gradient(cmap="RdYlGn_r", axis=None),
                    use_container_width=True,
                    height=300
                )
            with col_h2:
                # Top file type by PII
                totals_by_type = {ft: sum(v.values()) for ft, v in heatmap_data.items()}
                top_type = max(totals_by_type, key=totals_by_type.get)
                st.markdown(f"""
                <div class="metric-card" style="margin-bottom:12px;">
                    <div class="metric-number" style="font-size:28px;">{top_type}</div>
                    <div class="metric-label">Most Risky File Type</div>
                </div>
                """, unsafe_allow_html=True)
                for ft, total in sorted(totals_by_type.items(), key=lambda x: x[1], reverse=True):
                    bar_pct = int((total / max(totals_by_type.values())) * 100)
                    st.markdown(f"""
                    <div style="margin-bottom:8px;">
                        <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:3px;">
                            <span style="color:#cbd5e1;">{ft}</span>
                            <span style="color:#ff3b64;font-family:'Space Mono',monospace;">{total}</span>
                        </div>
                        <div style="background:#1e2433;border-radius:4px;height:6px;">
                            <div style="background:#ff3b64;width:{bar_pct}%;height:6px;border-radius:4px;"></div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

    # ── RECENT FILES WITH RISK SCORE ──────────────────────────────
    st.markdown('<div class="section-header">Recent Files</div>', unsafe_allow_html=True)

    if not files:
        st.info("No files uploaded yet. Admins can upload files from the Upload page.")
        return

    HIGH_RISK_TYPES = {"aadhaar", "pan", "passport", "credit_card", "cvv", "account_number"}
    MED_RISK_TYPES  = {"phone", "us_phone", "email", "upi", "dob", "voter_id", "gstin"}

    def get_risk(f):
        summary = f.get("pii_summary") or {}
        types = set(summary.keys()) - {"sql_injection","xss","shell_commands","path_traversal"}
        if types & HIGH_RISK_TYPES:
            return "🔴 HIGH", "#ef4444"
        elif types & MED_RISK_TYPES:
            return "🟡 MEDIUM", "#fbbf24"
        elif types:
            return "🟢 LOW", "#34d399"
        return "⚪ NONE", "#64748b"

    for f in files[:8]:
        pii_count = f["pii_count"] or 0
        status = f["status"]
        summary = f.get("pii_summary") or {}
        uploader_info = f" · by **{f['uploader']}**" if is_admin() and f.get("uploader") else ""

        has_threat = isinstance(summary, dict) and any(
            k in summary for k in ["sql_injection", "xss", "shell_commands", "path_traversal"]
        )
        risk_label, risk_color = get_risk(f)

        col1, col2, col3 = st.columns([4, 1, 1])
        with col1:
            st.markdown(f"**{f['original_filename']}**")
            threat_tags = ""
            if has_threat:
                detected = [k for k in ["sql_injection","xss","shell_commands","path_traversal"] if k in summary]
                threat_tags = " 🚨 `" + ", ".join(detected) + "`"
            st.caption(f"{f['file_type'].upper()} · {str(f['upload_time'])[:16]}{uploader_info}{threat_tags}")
        with col2:
            if has_threat:
                st.markdown("🦠 **THREAT** ⛔ `blocked`")
            else:
                status_icon = "✅" if status == "done" else "⏳"
                st.markdown(f"🔴 **{pii_count} PII** {status_icon} `{status}`")
        with col3:
            if not has_threat:
                st.markdown(f'<span style="color:{risk_color};font-weight:700;font-size:13px;">{risk_label}</span>', unsafe_allow_html=True)
        st.divider()


# ── FILES PAGE ───────────────────────────────────────────────────

def _render_file_preview(file_bytes: bytes, filename: str, file_id: str):
    """Render an inline preview of a sanitized file — like Overleaf."""
    ext = filename.rsplit(".", 1)[-1].lower()

    if ext == "pdf":
        # Show as base64 embedded PDF viewer
        import base64
        b64 = base64.b64encode(file_bytes).decode()
        pdf_html = f'''
        <iframe src="data:application/pdf;base64,{b64}"
            width="100%" height="600px"
            style="border:1px solid #1e2d45; border-radius:8px;">
        </iframe>
        '''
        st.markdown(pdf_html, unsafe_allow_html=True)

    elif ext in ("png", "jpg", "jpeg"):
        st.image(file_bytes, use_container_width=True)

    elif ext == "docx":
        from docx import Document
        import io
        doc = Document(io.BytesIO(file_bytes))
        text = "\n".join(p.text for p in doc.paragraphs if p.text.strip())
        st.markdown(f'<div class="diff-sanitized" style="max-height:500px;overflow-y:auto;">{text}</div>', unsafe_allow_html=True)

    elif ext == "csv":
        import io
        df_prev = pd.read_csv(io.BytesIO(file_bytes))
        st.dataframe(df_prev, use_container_width=True)

    elif ext == "json":
        import json as _json
        try:
            parsed = _json.loads(file_bytes.decode("utf-8", errors="replace"))
            st.json(parsed)
        except Exception:
            st.code(file_bytes.decode("utf-8", errors="replace")[:3000], language="json")

    else:
        # SQL, TXT, etc — show as code
        text = file_bytes.decode("utf-8", errors="replace")
        lang = "sql" if ext == "sql" else "text"
        st.code(text[:3000], language=lang)


def page_files():
    require_login()
    user = current_user()
    st.markdown('<div class="page-title">Files</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Preview and download sanitized files — like Overleaf</div>', unsafe_allow_html=True)

    # Admin sees all, user sees own
    all_files = get_all_files() if is_admin() else get_files_by_user(user["id"])
    done_files = [f for f in all_files if f["status"] == "done"]

    if not done_files:
        st.info("No sanitized files available yet.")
        return

    # ── File list + preview panel (Overleaf style) ────────────────
    # Track which file is being previewed
    if "preview_file_id" not in st.session_state:
        st.session_state["preview_file_id"] = None

    # If previewing a file — show full preview panel
    if st.session_state["preview_file_id"]:
        fid = st.session_state["preview_file_id"]
        f = next((x for x in done_files if str(x["id"]) == fid), None)

        if f is None:
            st.session_state["preview_file_id"] = None
            st.rerun()

        # Back button
        if st.button("← Back to Files"):
            st.session_state["preview_file_id"] = None
            st.rerun()

        st.markdown(f'<div class="page-title">📄 {f["original_filename"]}</div>', unsafe_allow_html=True)

        # Meta row
        col_m1, col_m2, col_m3, col_m4 = st.columns(4)
        with col_m1:
            st.metric("Format", f["file_type"].upper())
        with col_m2:
            st.metric("PII Masked", f["pii_count"] or 0)
        with col_m3:
            st.metric("Status", f["status"].capitalize())
        with col_m4:
            st.metric("Uploaded", str(f["upload_time"])[:10])

        # PII chips
        if f.get("pii_summary"):
            chips = "".join([f'<span class="pii-chip">{k}: {v}</span>' for k, v in f["pii_summary"].items()])
            st.markdown(f'<div style="margin:12px 0;">{chips}</div>', unsafe_allow_html=True)

        # Preview panel
        st.markdown('<div class="section-header">📖 Sanitized File Preview</div>', unsafe_allow_html=True)

        if f.get("sanitized_r2_key"):
            try:
                sanitized_bytes = download_file(f["sanitized_r2_key"])
                _render_file_preview(sanitized_bytes, f["original_filename"], str(f["id"]))

                # Download button below preview
                st.markdown("<br>", unsafe_allow_html=True)
                col_d1, col_d2 = st.columns(2)
                with col_d1:
                    st.download_button(
                        label="⬇️ Download Sanitized File",
                        data=sanitized_bytes,
                        file_name=f"sanitized_{f['original_filename']}",
                        mime=get_content_type(f["original_filename"]),
                        use_container_width=True,
                        key=f"dl_prev_{f['id']}"
                    )
                    log_action(user["id"], "download", str(f["id"]), {"filename": f["original_filename"]})
                with col_d2:
                    if is_admin() and f.get("original_r2_key"):
                        try:
                            original_bytes = download_file(f["original_r2_key"])
                            st.download_button(
                                label="⬇️ Download Original (Admin)",
                                data=original_bytes,
                                file_name=f["original_filename"],
                                mime=get_content_type(f["original_filename"]),
                                use_container_width=True,
                                key=f"dl_orig_prev_{f['id']}"
                            )
                        except Exception:
                            pass

            except Exception as e:
                st.error(f"Preview error: {e}")

        # Admin detections table
        if is_admin():
            detections = get_pii_detections(str(f["id"]))
            if detections:
                st.markdown('<div class="section-header">PII Detections</div>', unsafe_allow_html=True)
                df = pd.DataFrame(detections)[["pii_type", "masked_value", "detection_method"]]
                df.columns = ["Type", "Masked As", "Method"]
                st.dataframe(df, use_container_width=True, hide_index=True)
        return

    # ── File list view ────────────────────────────────────────────
    st.markdown('<div class="section-header">All Sanitized Files</div>', unsafe_allow_html=True)

    # ── SEARCH & FILTER ───────────────────────────────────────────
    with st.expander("🔍 Search & Filter", expanded=True):
        col_f1, col_f2, col_f3, col_f4 = st.columns([3, 2, 2, 2])
        with col_f1:
            search_query = st.text_input("Search filename", placeholder="e.g. report.pdf", label_visibility="collapsed")
        with col_f2:
            file_types = sorted(set(f["file_type"].lower() for f in done_files))
            type_filter = st.selectbox("File type", ["All types"] + file_types, label_visibility="collapsed")
        with col_f3:
            pii_filter = st.selectbox("PII count", ["Any amount", "0 PII", "1-10 PII", "11-50 PII", "50+ PII"], label_visibility="collapsed")
        with col_f4:
            date_filter = st.selectbox("Date", ["All time", "Today", "Last 7 days", "Last 30 days"], label_visibility="collapsed")

    # Apply filters
    from datetime import timezone, timedelta
    now = datetime.now(timezone.utc)

    filtered_files = done_files
    if search_query:
        filtered_files = [f for f in filtered_files if search_query.lower() in f["original_filename"].lower()]
    if type_filter != "All types":
        filtered_files = [f for f in filtered_files if f["file_type"].lower() == type_filter]
    if pii_filter == "0 PII":
        filtered_files = [f for f in filtered_files if (f["pii_count"] or 0) == 0]
    elif pii_filter == "1-10 PII":
        filtered_files = [f for f in filtered_files if 1 <= (f["pii_count"] or 0) <= 10]
    elif pii_filter == "11-50 PII":
        filtered_files = [f for f in filtered_files if 11 <= (f["pii_count"] or 0) <= 50]
    elif pii_filter == "50+ PII":
        filtered_files = [f for f in filtered_files if (f["pii_count"] or 0) > 50]
    if date_filter != "All time":
        cutoff = {
            "Today": now - timedelta(days=1),
            "Last 7 days": now - timedelta(days=7),
            "Last 30 days": now - timedelta(days=30),
        }[date_filter]
        def parse_ts(ts):
            try:
                if isinstance(ts, str):
                    ts = ts.replace("Z", "+00:00")
                    return datetime.fromisoformat(ts)
                return ts
            except Exception:
                return now
        filtered_files = [f for f in filtered_files if parse_ts(f["upload_time"]) >= cutoff]

    st.caption(f"Showing {len(filtered_files)} of {len(done_files)} files")

    # ── BULK DOWNLOAD ─────────────────────────────────────────────
    if filtered_files:
        if st.button("📦 Bulk Download All Filtered Files as ZIP", use_container_width=True):
            import zipfile, io as _io
            zip_buffer = _io.BytesIO()
            with st.spinner(f"Packaging {len(filtered_files)} files..."):
                with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                    for f in filtered_files:
                        if f.get("sanitized_r2_key"):
                            try:
                                file_bytes = download_file(f["sanitized_r2_key"])
                                zf.writestr(f"sanitized_{f['original_filename']}", file_bytes)
                            except Exception:
                                pass
            zip_buffer.seek(0)
            st.download_button(
                label=f"⬇️ Download ZIP ({len(filtered_files)} files)",
                data=zip_buffer.getvalue(),
                file_name=f"sanitized_files_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                mime="application/zip",
                use_container_width=True,
                key="bulk_zip_dl"
            )

    st.markdown("<br>", unsafe_allow_html=True)

    for f in filtered_files:
        pii_count = f["pii_count"] or 0
        col1, col2, col3, col4 = st.columns([4, 1, 1, 1]) if is_admin() else st.columns([4, 1, 1])
        with col1:
            st.markdown(f"**📄 {f['original_filename']}**")
            uploader = f" · by **{f['uploader']}**" if is_admin() and f.get("uploader") else ""
            st.caption(f"{f['file_type'].upper()} · {str(f['upload_time'])[:16]}{uploader} · 🔴 {pii_count} PII masked")
        with col2:
            if st.button("👁️ Preview", key=f"prev_{f['id']}", use_container_width=True):
                st.session_state["preview_file_id"] = str(f["id"])
                log_action(user["id"], "view", str(f["id"]), {"filename": f["original_filename"]})
                st.rerun()
        with col3:
            if f.get("sanitized_r2_key"):
                try:
                    sanitized_bytes = download_file(f["sanitized_r2_key"])
                    st.download_button(
                        label="⬇️ Download",
                        data=sanitized_bytes,
                        file_name=f"sanitized_{f['original_filename']}",
                        mime=get_content_type(f["original_filename"]),
                        use_container_width=True,
                        key=f"dl_{f['id']}"
                    )
                except Exception:
                    st.caption("Unavailable")
        if is_admin():
            with col4:
                if st.button("🗑️", key=f"del_{f['id']}", help="Delete this file (admin only)", use_container_width=True):
                    st.session_state[f"confirm_del_{f['id']}"] = True
                    st.rerun()

            # Confirmation row
            if st.session_state.get(f"confirm_del_{f['id']}"):
                st.warning(f"⚠️ Delete **{f['original_filename']}**? This cannot be undone.")
                c_yes, c_no = st.columns(2)
                with c_yes:
                    if st.button("✅ Yes, Delete", key=f"yes_{f['id']}", use_container_width=True):
                        try:
                            from storage import delete_file as storage_delete
                            if f.get("sanitized_r2_key"):
                                try: storage_delete(f["sanitized_r2_key"])
                                except Exception: pass
                            if f.get("original_r2_key"):
                                try: storage_delete(f["original_r2_key"])
                                except Exception: pass
                            delete_file_record(str(f["id"]))
                            log_action(user["id"], "delete", str(f["id"]), {"filename": f["original_filename"]})
                            st.session_state.pop(f"confirm_del_{f['id']}", None)
                            st.success(f"✅ Deleted **{f['original_filename']}**")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Delete failed: {e}")
                with c_no:
                    if st.button("❌ Cancel", key=f"no_{f['id']}", use_container_width=True):
                        st.session_state.pop(f"confirm_del_{f['id']}", None)
                        st.rerun()
        st.divider()


# ── UPLOAD PAGE (ADMIN ONLY) ─────────────────────────────────────

def page_upload():
    require_login()
    st.markdown('<div class="page-title">Upload File</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Upload a file — PII will be automatically detected and masked</div>', unsafe_allow_html=True)

    uploaded = st.file_uploader(
        "Drag and drop a file",
        type=["pdf", "docx", "sql", "csv", "txt", "json", "png", "jpg", "jpeg"],
        help="Supported: PDF, DOCX, SQL, CSV, TXT, JSON, Images"
    )

    if uploaded:
        file_bytes = uploaded.read()
        ext = uploaded.name.rsplit(".", 1)[-1].lower()

        col1, col2 = st.columns(2)
        with col1:
            st.markdown('<div class="section-header">Original Preview</div>', unsafe_allow_html=True)
            if ext in ("png", "jpg", "jpeg"):
                st.image(file_bytes, caption="Uploaded image", use_column_width=True)
                st.info("Image uploaded. OCR-based PII detection will run on sanitize.")
            else:
                preview = extract_preview_text(file_bytes, uploaded.name, max_chars=1500)
                st.markdown(f'<div class="diff-original">{preview}</div>', unsafe_allow_html=True)

        if st.button("🚀 Run PII Detection & Sanitize", use_container_width=True):
            # ── Step 1: Security Scan ─────────────────────────────
            security_result = full_security_scan(file_bytes, uploaded.name)
            is_malicious_content = not security_result["malicious_content"]["safe"]

            # Always show security report
            st.markdown('<div class="section-header">🔒 Security Scan Results</div>', unsafe_allow_html=True)
            col_s1, col_s2 = st.columns(2)
            with col_s1:
                if security_result["safe"]:
                    st.success("✅ File is Safe")
                else:
                    st.error("🚨 Threats Detected!")
            with col_s2:
                st.info("**SHA256:** `" + security_result['hashes']['sha256'][:24] + "...`")

            # BLOCK if malicious
            if is_malicious_content:
                threats = security_result["malicious_content"]["threats"]
                st.error(f"⛔ **UPLOAD BLOCKED** — Malicious content detected: `{', '.join(threats)}`")
                st.warning("This file contains potentially harmful code and cannot be processed.")
                # Log the blocked attempt
                log_action(current_user()["id"], "blocked_upload", details={
                    "filename": uploaded.name,
                    "threats": threats,
                    "sha256": security_result["hashes"]["sha256"]
                })
                st.stop()

            st.success("✅ Security scan passed — proceeding with PII detection.")

            with st.spinner("Scanning for PII..."):
                try:
                    user = current_user()
                    file_id = str(uuid.uuid4())

                    # Upload original to R2
                    orig_key = f"originals/{file_id}/{uploaded.name}"
                    upload_file(file_bytes, orig_key, get_content_type(uploaded.name))

                    # Create DB record
                    db_file_id = create_file_record(
                        uploaded.name, ext, user["id"], orig_key
                    )

                    # Process file
                    sanitized_bytes, detections, pii_summary = process_file(file_bytes, uploaded.name)

                    # Upload sanitized to R2
                    san_key = f"sanitized/{file_id}/sanitized_{uploaded.name}"
                    upload_file(sanitized_bytes, san_key, get_content_type(uploaded.name))

                    # Update DB
                    update_file_record(db_file_id, san_key, len(detections), pii_summary)
                    save_pii_detections(db_file_id, detections)
                    log_action(user["id"], "upload", db_file_id,
                               {"filename": uploaded.name, "pii_count": len(detections)})

                    st.success(f"✅ Done! Found and masked **{len(detections)} PII items**.")

                    # Show results
                    if ext not in ("png", "jpg", "jpeg"):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown('<div class="section-header">Original</div>', unsafe_allow_html=True)
                            original_preview = extract_preview_text(file_bytes, uploaded.name, 1500)
                            st.markdown(f'<div class="diff-original">{original_preview}</div>', unsafe_allow_html=True)
                        with col2:
                            st.markdown('<div class="section-header">Sanitized</div>', unsafe_allow_html=True)
                            sanitized_preview = extract_preview_text(sanitized_bytes, uploaded.name, 1500)
                            st.markdown(f'<div class="diff-sanitized">{sanitized_preview}</div>', unsafe_allow_html=True)
                    else:
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown('<div class="section-header">Original</div>', unsafe_allow_html=True)
                            st.image(file_bytes, use_container_width=True)
                        with col2:
                            st.markdown('<div class="section-header">Redacted (Black Box)</div>', unsafe_allow_html=True)
                            st.image(sanitized_bytes, use_container_width=True)

                    # PII breakdown
                    st.markdown('<div class="section-header">PII Breakdown</div>', unsafe_allow_html=True)
                    if pii_summary:
                        chips = "".join([f'<span class="pii-chip">{k}: {v}</span>' for k, v in pii_summary.items()])
                        st.markdown(f'<div>{chips}</div>', unsafe_allow_html=True)

                        df = pd.DataFrame(detections)[["pii_type", "original_value", "masked_value", "detection_method"]]
                        df.columns = ["Type", "Original", "Masked As", "Method"]
                        st.dataframe(df, use_container_width=True, hide_index=True)

                    # Download button
                    dl_name = f"sanitized_{uploaded.name}"
                    dl_mime = get_content_type(uploaded.name)

                    st.download_button(
                        "⬇️ Download Sanitized File",
                        data=sanitized_bytes,
                        file_name=dl_name,
                        mime=dl_mime,
                        use_container_width=True
                    )

                except Exception as e:
                    st.error(f"Error during processing: {e}")
                    raise e


# ── AUDIT LOGS PAGE (ADMIN ONLY) ─────────────────────────────────

def page_audit_logs():
    require_admin()
    st.markdown('<div class="page-title">Audit Logs</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Complete activity trail for compliance</div>', unsafe_allow_html=True)

    logs = get_audit_logs(limit=200)
    if not logs:
        st.info("No audit logs yet.")
        return

    df = pd.DataFrame(logs)
    display_cols = ["timestamp", "username", "action", "original_filename"]
    available = [c for c in display_cols if c in df.columns]
    df = df[available].copy()
    df.columns = ["Timestamp", "User", "Action", "File"][:len(available)]
    df["Timestamp"] = pd.to_datetime(df["Timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")

    # Filter
    col1, col2 = st.columns(2)
    with col1:
        action_filter = st.selectbox("Filter by Action", ["All"] + sorted(df["Action"].dropna().unique().tolist()))
    with col2:
        user_filter = st.selectbox("Filter by User", ["All"] + sorted(df["User"].dropna().unique().tolist()))

    filtered = df.copy()
    if action_filter != "All":
        filtered = filtered[filtered["Action"] == action_filter]
    if user_filter != "All":
        filtered = filtered[filtered["User"] == user_filter]

    st.dataframe(filtered, use_container_width=True, hide_index=True)

    # ── SIEM Export ──────────────────────────────────────────────
    st.markdown('<div class="section-header">Export Logs</div>', unsafe_allow_html=True)
    col_e1, col_e2 = st.columns(2)
    with col_e1:
        # SIEM NDJSON export
        siem_data = export_siem_logs([dict(l) for l in logs])
        st.download_button(
            "⬇️ Export SIEM Logs (NDJSON)",
            data=siem_data,
            file_name=f"pii_sanitizer_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ndjson",
            mime="application/x-ndjson",
            use_container_width=True,
            help="Compatible with Splunk, ELK, IBM QRadar"
        )
    with col_e2:
        # Raw JSON export
        import json as _json
        raw_json = _json.dumps([dict(l) for l in logs], default=str, indent=2)
        st.download_button(
            "⬇️ Export Raw JSON",
            data=raw_json,
            file_name=f"pii_sanitizer_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True
        )


# ── USERS PAGE (ADMIN ONLY) ──────────────────────────────────────

def page_users():
    require_admin()
    st.markdown('<div class="page-title">User Management</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Manage accounts and view user activity</div>', unsafe_allow_html=True)

    users = get_all_users()

    # ── Selected user activity view ───────────────────────────────
    if "viewing_user_id" in st.session_state and st.session_state["viewing_user_id"]:
        uid = st.session_state["viewing_user_id"]
        uname = st.session_state.get("viewing_user_name", "User")

        if st.button("← Back to All Users"):
            st.session_state["viewing_user_id"] = None
            st.rerun()

        st.markdown(f'<div class="section-header">Activity for: {uname}</div>', unsafe_allow_html=True)

        activity = get_user_activity(uid)
        user_files = get_files_by_user(uid)

        # Summary stats
        logins   = [a for a in activity if a["action"] == "login"]
        logouts  = [a for a in activity if a["action"] == "logout"]
        uploads  = [a for a in activity if a["action"] == "upload"]
        downloads= [a for a in activity if a["action"] == "download"]
        scans    = [a for a in activity if a["action"] == "text_scan"]

        c1, c2, c3, c4, c5 = st.columns(5)
        with c1:
            st.markdown(f'<div class="metric-card"><div class="metric-number">{len(logins)}</div><div class="metric-label">Logins</div></div>', unsafe_allow_html=True)
        with c2:
            st.markdown(f'<div class="metric-card"><div class="metric-number">{len(uploads)}</div><div class="metric-label">Uploads</div></div>', unsafe_allow_html=True)
        with c3:
            st.markdown(f'<div class="metric-card"><div class="metric-number">{len(downloads)}</div><div class="metric-label">Downloads</div></div>', unsafe_allow_html=True)
        with c4:
            st.markdown(f'<div class="metric-card"><div class="metric-number">{len(scans)}</div><div class="metric-label">Text Scans</div></div>', unsafe_allow_html=True)
        with c5:
            st.markdown(f'<div class="metric-card"><div class="metric-number">{len(user_files)}</div><div class="metric-label">Files</div></div>', unsafe_allow_html=True)

        # Login/Logout timeline
        st.markdown('<div class="section-header">Login / Logout Timeline</div>', unsafe_allow_html=True)
        timeline_events = [a for a in activity if a["action"] in ("login", "logout")]
        if timeline_events:
            for event in timeline_events[:20]:
                icon = "🟢" if event["action"] == "login" else "🔴"
                ts = str(event.get("timestamp", ""))[:19].replace("T", " ")
                ip = event.get("ip_address") or "unknown IP"
                st.markdown(f"{icon} **{event['action'].upper()}** — {ts} &nbsp;·&nbsp; `{ip}`")
        else:
            st.info("No login/logout events recorded yet.")

        # Full activity log
        st.markdown('<div class="section-header">Full Activity Log</div>', unsafe_allow_html=True)
        if activity:
            action_icons = {
                "login": "🟢", "logout": "🔴", "upload": "⬆️",
                "download": "⬇️", "text_scan": "🔍", "view": "👁️",
                "blocked_upload": "⛔",
                "pii_detected": "🔐"
            }
            for a in activity[:50]:
                icon = action_icons.get(a["action"], "•")
                ts = str(a.get("timestamp", ""))[:19].replace("T", " ")
                fname = f" · `{a['original_filename']}`" if a.get("original_filename") else ""
                details = a.get("details") or {}
                extra = ""
                if "pii_count" in details:
                    extra = f" · {details['pii_count']} PII"
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.markdown(f"{icon} **{a['action']}**{fname}{extra}")
                with col2:
                    st.caption(ts)
        else:
            st.info("No activity recorded for this user.")

        # Files uploaded by this user
        if user_files:
            st.markdown('<div class="section-header">Files Uploaded</div>', unsafe_allow_html=True)
            df_files = pd.DataFrame(user_files)[["original_filename", "file_type", "pii_count", "status", "upload_time"]]
            df_files.columns = ["Filename", "Type", "PII Count", "Status", "Uploaded At"]
            df_files["Uploaded At"] = pd.to_datetime(df_files["Uploaded At"]).dt.strftime("%Y-%m-%d %H:%M")
            st.dataframe(df_files, use_container_width=True, hide_index=True)
        return

    # ── User list with click to inspect ──────────────────────────
    st.markdown('<div class="section-header">All Users</div>', unsafe_allow_html=True)

    for u in users:
        col1, col2, col3, col4 = st.columns([2, 2, 1, 1])
        with col1:
            st.markdown(f"**{u['username']}**")
            st.caption(u.get("email", ""))
        with col2:
            role_icon = "👑" if u["role"] == "admin" else "👤"
            joined = str(u.get("created_at", ""))[:10]
            st.markdown(f"{role_icon} `{u['role']}`")
            st.caption(f"Joined {joined}")
        with col3:
            active = u.get("is_active", True)
            st.markdown("🟢 Active" if active else "🔴 Inactive")
        with col4:
            if st.button("View Activity", key=f"view_{u['id']}"):
                st.session_state["viewing_user_id"] = u["id"]
                st.session_state["viewing_user_name"] = u["username"]
                st.rerun()
        st.divider()

    # ── Failed Login Tracker ──────────────────────────────────────
    st.markdown('<div class="section-header">📋 Failed Login Attempts</div>', unsafe_allow_html=True)
    failed = get_failed_logins()
    if failed:
        for row in failed:
            attempts = row["attempts"]
            color = "#ef4444" if attempts >= 5 else "#fbbf24" if attempts >= 2 else "#64748b"
            alert = " 🚨 **Suspicious**" if attempts >= 5 else ""
            col_f1, col_f2, col_f3 = st.columns([2, 1, 2])
            with col_f1:
                st.markdown(f"**{row['username']}**{alert}")
            with col_f2:
                st.markdown(f'<span style="color:{color};font-family:\'Space Mono\',monospace;font-weight:700;">{attempts} attempts</span>', unsafe_allow_html=True)
            with col_f3:
                st.caption(f"Last: {row['last_attempt']}")
        st.divider()
    else:
        st.info("No failed login attempts recorded.")

    # ── Add New User ──────────────────────────────────────────────
    st.markdown('<div class="section-header">Add New User</div>', unsafe_allow_html=True)
    with st.form("add_user"):
        c1, c2 = st.columns(2)
        with c1:
            new_username = st.text_input("Username")
            new_email    = st.text_input("Email")
        with c2:
            new_password = st.text_input("Password", type="password")
            new_role     = st.selectbox("Role", ["standard", "admin"])

        if st.form_submit_button("Create User", use_container_width=True):
            try:
                create_user(new_username, new_email, new_password, new_role)
                st.success(f"User '{new_username}' created successfully!")
                st.rerun()
            except Exception as e:
                st.error(f"Error: {e}")


# ── TEXT SCAN PAGE ───────────────────────────────────────────────

def page_text_scan():
    require_login()
    st.markdown('<div class="page-title">Text Scanner</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Paste any text to instantly detect and mask PII</div>', unsafe_allow_html=True)

    # Sample texts for quick testing
    st.markdown('<div class="section-header">Quick Load Sample</div>', unsafe_allow_html=True)
    col1, col2, col3 = st.columns(3)
    
    sample_indian = """My name is Rahul Sharma and I live at 45 MG Road, Bangalore.
My Aadhaar number is 4821 7391 6625 and PAN is ABCDE1234F.
Contact me at rahul.sharma@gmail.com or +91 9876543210.
My bank account is 50100234567890 with IFSC HDFC0001234."""

    sample_card = """Customer: Priya Mehta
Credit Card: 4012 3456 7890 1234
CVV: 456
Expiry: 08/2027
UPI: priya.mehta@okaxis
Email: priya@example.com"""

    sample_employee = """Employee Record:
Name: Karthik Reddy, DOB: 22 Jan 1990
Phone: +91 9849077812, Email: karthik@company.com
Passport: U5529981, Aadhaar: 6652 4811 9073
IP Address: 103.54.12.77, Device: android-9f31acb8d1"""

    with col1:
        if st.button("👤 Indian PII Sample", use_container_width=True):
            st.session_state["text_input"] = sample_indian
    with col2:
        if st.button("💳 Card Data Sample", use_container_width=True):
            st.session_state["text_input"] = sample_card
    with col3:
        if st.button("🏢 Employee Record", use_container_width=True):
            st.session_state["text_input"] = sample_employee

    st.markdown('<div class="section-header">Input Text</div>', unsafe_allow_html=True)

    # Text area
    input_text = st.text_area(
        "Paste your text here",
        value=st.session_state.get("text_input", ""),
        height=200,
        placeholder="Paste any text containing PII — names, Aadhaar, PAN, emails, phone numbers, addresses...",
        label_visibility="collapsed"
    )

    # Options row
    col_o1, col_o2 = st.columns(2)
    with col_o1:
        show_highlight = st.checkbox("🎨 Highlight PII", value=True, help="Show detected PII highlighted")
    with col_o2:
        mask_mode = st.selectbox("Mask Mode", ["Partial (j***@email.com)", "Full Redact ([REDACTED])", "Token (PII_TOKEN_1)"], label_visibility="collapsed")

    if st.button("🔍 Scan & Mask PII", use_container_width=True, disabled=not input_text.strip()):
        if not input_text.strip():
            st.warning("Please enter some text first.")
            return

        with st.spinner("Scanning for PII..."):
            from pii_engine import regex_scan, name_address_scan, build_pii_summary

            # Run regex scan
            after_regex, regex_detections = regex_scan(input_text)
            regex_types = list({d["pii_type"] for d in regex_detections})

            # Run name/address pattern scan
            masked_text, pattern_detections = name_address_scan(after_regex)
            all_detections = regex_detections + pattern_detections

            # Apply token mode if selected
            if "Token" in mask_mode:
                token_map = {}
                token_count = 1
                for d in all_detections:
                    token = f"PII_TOKEN_{token_count}"
                    token_map[d["masked_value"]] = token
                    d["token"] = token
                    token_count += 1
                for orig, token in token_map.items():
                    masked_text = masked_text.replace(orig, token)
            elif "Full Redact" in mask_mode:
                for d in all_detections:
                    masked_text = masked_text.replace(d["masked_value"], "[REDACTED]")
                    d["masked_value"] = "[REDACTED]"

            summary = build_pii_summary(all_detections)

        # ── Results ──────────────────────────────────────────────
        st.markdown('<div class="section-header">Results</div>', unsafe_allow_html=True)

        # Stats row
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(f'<div class="metric-card"><div class="metric-number">{len(all_detections)}</div><div class="metric-label">PII Found</div></div>', unsafe_allow_html=True)
        with c2:
            st.markdown(f'<div class="metric-card"><div class="metric-number">{len(regex_detections)}</div><div class="metric-label">Via Regex</div></div>', unsafe_allow_html=True)
        with c3:
            pattern_count = len(all_detections) - len(regex_detections)
            st.markdown(f'<div class="metric-card"><div class="metric-number">{pattern_count}</div><div class="metric-label">Via Pattern</div></div>', unsafe_allow_html=True)
        with c4:
            st.markdown(f'<div class="metric-card"><div class="metric-number">{len(summary)}</div><div class="metric-label">PII Types</div></div>', unsafe_allow_html=True)

        # Side by side
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown('<div class="section-header">Original</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="diff-original">{input_text}</div>', unsafe_allow_html=True)
        with col_b:
            st.markdown('<div class="section-header">Sanitized</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="diff-sanitized">{masked_text}</div>', unsafe_allow_html=True)

        # PII type chips
        if summary:
            st.markdown('<div class="section-header">PII Breakdown</div>', unsafe_allow_html=True)
            chips = "".join([f'<span class="pii-chip">{k}: {v}</span>' for k, v in summary.items()])
            st.markdown(f'<div style="margin-bottom:16px;">{chips}</div>', unsafe_allow_html=True)

        # Detections table
        if all_detections:
            df = pd.DataFrame(all_detections)[["pii_type", "original_value", "masked_value", "detection_method"]]
            df.columns = ["Type", "Original", "Masked As", "Method"]
            st.dataframe(df, use_container_width=True, hide_index=True)

        # Download sanitized text
        st.download_button(
            "⬇️ Download Sanitized Text",
            data=masked_text,
            file_name="sanitized_text.txt",
            mime="text/plain",
            use_container_width=True
        )

        # Log action
        log_action(current_user()["id"], "text_scan", details={
            "pii_count": len(all_detections),
            "char_count": len(input_text)
        })


# ── MY FILES PAGE (user-scoped) ──────────────────────────────────

def page_my_files():
    require_login()
    user = current_user()
    st.markdown('<div class="page-title">My Files</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Files you have uploaded and sanitized</div>', unsafe_allow_html=True)

    files = get_files_by_user(user["id"])

    if not files:
        st.info("You haven't uploaded any files yet. Go to Upload to get started!")
        return

    done_files = [f for f in files if f["status"] == "done"]
    total_pii = sum(f["pii_count"] or 0 for f in done_files)

    # Stats
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f'<div class="metric-card"><div class="metric-number">{len(files)}</div><div class="metric-label">My Files</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="metric-card"><div class="metric-number">{len(done_files)}</div><div class="metric-label">Sanitized</div></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="metric-card"><div class="metric-number">{total_pii}</div><div class="metric-label">PII Masked</div></div>', unsafe_allow_html=True)

    st.markdown('<div class="section-header">My Uploaded Files</div>', unsafe_allow_html=True)

    for f in files:
        pii_count = f["pii_count"] or 0
        status = f["status"]
        col1, col2, col3 = st.columns([3, 1, 1])
        with col1:
            st.markdown(f"**{f['original_filename']}**")
            st.caption(f"{f['file_type'].upper()} · {str(f['upload_time'])[:16]}")
        with col2:
            st.markdown(f"🔴 **{pii_count} PII**")
        with col3:
            if status == "done":
                if st.button("👁️ Preview", key=f"prev_my_{f['id']}", use_container_width=True):
                    st.session_state["preview_file_id"] = str(f["id"])
                    st.session_state["preview_from"] = "my_files"
                    st.rerun()
            else:
                st.caption(f"`{status}`")
        st.divider()

    # If a file was selected for preview, redirect to Files page logic
    if st.session_state.get("preview_file_id") and st.session_state.get("preview_from") == "my_files":
        fid = st.session_state["preview_file_id"]
        f = next((x for x in files if str(x["id"]) == fid), None)
        if f and f.get("sanitized_r2_key"):
            st.markdown('---')
            st.markdown(f'<div class="section-header">📖 Preview: {f["original_filename"]}</div>', unsafe_allow_html=True)
            if st.button("✕ Close Preview"):
                st.session_state["preview_file_id"] = None
                st.session_state["preview_from"] = None
                st.rerun()
            try:
                from storage import download_file as _dl
                sanitized_bytes = _dl(f["sanitized_r2_key"])
                _render_file_preview(sanitized_bytes, f["original_filename"], fid)
                st.download_button(
                    "⬇️ Download Sanitized File",
                    data=sanitized_bytes,
                    file_name=f"sanitized_{f['original_filename']}",
                    mime=get_content_type(f["original_filename"]),
                    use_container_width=True,
                    key=f"dl_my_prev_{fid}"
                )
            except Exception as e:
                st.error(f"Preview error: {e}")


# ── PASSWORD CHANGE PAGE ─────────────────────────────────────────

def page_change_password():
    require_login()
    user = current_user()
    st.markdown('<div class="page-title">Change Password</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Update your account password</div>', unsafe_allow_html=True)

    with st.form("change_pw_form"):
        current_pw  = st.text_input("Current Password", type="password")
        new_pw      = st.text_input("New Password", type="password")
        confirm_pw  = st.text_input("Confirm New Password", type="password")

        submitted = st.form_submit_button("🔒 Update Password", use_container_width=True)

        if submitted:
            if not current_pw or not new_pw or not confirm_pw:
                st.error("All fields are required.")
            elif new_pw != confirm_pw:
                st.error("New passwords do not match.")
            elif len(new_pw) < 6:
                st.error("New password must be at least 6 characters.")
            else:
                from database import get_user_by_username, verify_password
                db_user = get_user_by_username(user["username"])
                if not db_user or not verify_password(current_pw, db_user["password_hash"]):
                    st.error("Current password is incorrect.")
                else:
                    try:
                        change_password(user["id"], new_pw)
                        log_action(user["id"], "password_change", details={"username": user["username"]})
                        st.success("✅ Password updated successfully!")
                    except Exception as e:
                        st.error(f"Failed to update password: {e}")


# ── MAIN ROUTER ──────────────────────────────────────────────────

def main():
    if not current_user():
        show_login_page()
        return

    page = render_sidebar()

    if page == "Dashboard":
        page_dashboard()
    elif page == "Files":
        page_files()
    elif page == "Text Scan":
        page_text_scan()
    elif page == "Upload":
        page_upload()
    elif page == "My Files":
        page_my_files()
    elif page == "Audit Logs":
        page_audit_logs()
    elif page == "Users":
        page_users()
    elif page == "Change Password":
        page_change_password()


if __name__ == "__main__":
    main()
