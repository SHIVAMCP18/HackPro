"""
auth.py — Session management and role-based access control
"""
import streamlit as st
from datetime import datetime, timezone
from database import get_user_by_username, verify_password, log_action, record_failed_login

# ── SESSION TIMEOUT (minutes) ─────────────────────────────────────
SESSION_TIMEOUT_MINUTES = 30


def _check_session_timeout():
    """Auto-logout user if inactive for SESSION_TIMEOUT_MINUTES."""
    last_active = st.session_state.get("last_active")
    if last_active and st.session_state.get("user"):
        elapsed = (datetime.now(timezone.utc) - last_active).total_seconds() / 60
        if elapsed > SESSION_TIMEOUT_MINUTES:
            user = st.session_state.get("user")
            if user:
                log_action(user["id"], "session_timeout", details={"username": user["username"]})
            st.session_state.pop("user", None)
            st.session_state.pop("last_active", None)
            st.warning(f"⏱️ You were automatically logged out after {SESSION_TIMEOUT_MINUTES} minutes of inactivity.")
            st.stop()

    # Refresh last_active on every interaction
    if st.session_state.get("user"):
        st.session_state["last_active"] = datetime.now(timezone.utc)


def login(username: str, password: str) -> bool:
    user = get_user_by_username(username)
    if user and verify_password(password, user["password_hash"]):
        st.session_state["user"] = {
            "id": str(user["id"]),
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
        }
        st.session_state["last_active"] = datetime.now(timezone.utc)
        log_action(str(user["id"]), "login", details={"username": username})
        return True
    else:
        record_failed_login(username)
        return False


def logout():
    user = current_user()
    if user:
        log_action(user["id"], "logout", details={"username": user["username"]})
    st.session_state.pop("user", None)
    st.session_state.pop("last_active", None)
    st.rerun()


def current_user():
    _check_session_timeout()
    return st.session_state.get("user")


def is_admin() -> bool:
    user = st.session_state.get("user")
    return user is not None and user["role"] == "admin"


def require_login():
    if not current_user():
        show_login_page()
        st.stop()


def require_admin():
    require_login()
    if not is_admin():
        st.error("⛔ Access denied. Admin privileges required.")
        st.stop()


def show_login_page():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;600&display=swap');
    .login-wrap {
        max-width: 420px;
        margin: 80px auto 0;
        background: #0f1117;
        border: 1px solid #2a2d3e;
        border-radius: 16px;
        padding: 48px 40px;
        box-shadow: 0 0 60px rgba(255,59,100,0.08);
    }
    .login-logo { font-family: 'Space Mono', monospace; font-size: 22px; color: #ff3b64; letter-spacing: -0.5px; margin-bottom: 8px; }
    .login-sub  { font-family: 'DM Sans', sans-serif; color: #6b7280; font-size: 13px; margin-bottom: 36px; }
    </style>
    <div class="login-wrap">
        <div class="login-logo">🔐 PII Sanitizer</div>
        <div class="login-sub">Secure data redaction platform</div>
    </div>
    """, unsafe_allow_html=True)

    with st.form("login_form"):
        username = st.text_input("Username", placeholder="Enter username")
        password = st.text_input("Password", type="password", placeholder="Enter password")
        submitted = st.form_submit_button("Sign In", width='stretch')
        if submitted:
            if login(username, password):
                st.rerun()
            else:
                st.error("Invalid username or password.")

    st.markdown("""
    <div style="text-align:center; margin-top:24px; font-family:'DM Sans',sans-serif; font-size:12px; color:#4b5563;">
    Default: <code>admin / admin123</code> &nbsp;|&nbsp; <code>user1 / user123</code>
    </div>
    """, unsafe_allow_html=True)
