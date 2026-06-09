import csv
import io
import json
from typing import Any

import httpx
import pandas as pd
import plotly.express as px
import streamlit as st

from src.core.config import get_config

cfg = get_config()

st.set_page_config(
    page_title="SOC Dashboard - Wazuh AI Correlation Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

_CSS = """
<style>
    /* Base */
    .stApp { background: #0e1117; }
    .main > div { padding: 1rem 2rem; }
    h1, h2, h3, h4, h5, h6 { color: #e0e0e0 !important; }
    p, li, span, div { color: #c0c0c0; }

    /* Metric cards (styled buttons + caption) */
    div[data-testid="column"]:has(div[data-testid="stButton"]) {
        background: #1a1d24;
        border: 1px solid #2e3138;
        border-radius: 12px;
        padding: 1rem 0.5rem 0.5rem;
        transition: all 0.2s ease;
        text-align: center;
    }
    div[data-testid="column"]:has(div[data-testid="stButton"]):hover {
        border-color: #4a9eff;
        box-shadow: 0 4px 20px rgba(74,158,255,0.15);
    }
    div[data-testid="stButton"] button[kind="secondary"] {
        background: transparent !important;
        border: none !important;
        box-shadow: none !important;
        padding: 0.5rem !important;
        font-size: 1.3rem !important;
        height: auto !important;
        min-height: 0 !important;
        color: #f0f0f0 !important;
        font-weight: 700 !important;
    }
    div[data-testid="stButton"] button[kind="secondary"]:hover {
        background: transparent !important;
        border: none !important;
        box-shadow: none !important;
    }
    div[data-testid="stButton"] button[kind="secondary"] p {
        font-size: 1.3rem !important;
        font-weight: 700 !important;
    }
    div[data-testid="column"]:has(div[data-testid="stButton"]) [data-testid="stCaptionContainer"] {
        text-align: center;
        font-size: 0.75rem;
        color: #8a8f9a;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        padding-bottom: 0.25rem;
    }

    /* Severity badges */
    .badge {
        display: inline-block;
        padding: 0.15rem 0.6rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.3px;
    }
    .badge-critical { background: #dc354522; color: #dc3545; border: 1px solid #dc354544; }
    .badge-high { background: #fd7e1422; color: #fd7e14; border: 1px solid #fd7e1444; }
    .badge-medium { background: #ffc10722; color: #ffc107; border: 1px solid #ffc10744; }
    .badge-low { background: #28a74522; color: #28a745; border: 1px solid #28a74544; }

    /* Status badges */
    .badge-open { background: #0d6efd22; color: #0d6efd; border: 1px solid #0d6efd44; }
    .badge-investigating { background: #ffc10722; color: #ffc107; border: 1px solid #ffc10744; }
    .badge-resolved { background: #28a74522; color: #28a745; border: 1px solid #28a74544; }
    .badge-false_positive { background: #6c757d22; color: #6c757d; border: 1px solid #6c757d44; }
    .badge-pending { background: #6c757d22; color: #6c757d; border: 1px solid #6c757d44; }
    .badge-retried { background: #0dcaf022; color: #0dcaf0; border: 1px solid #0dcaf044; }
    .badge-discarded { background: #dc354522; color: #dc3545; border: 1px solid #dc354544; }

    /* Status indicators */
    .status-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 6px; }
    .status-dot.green { background: #28a745; box-shadow: 0 0 6px #28a74566; }
    .status-dot.yellow { background: #ffc107; box-shadow: 0 0 6px #ffc10766; }
    .status-dot.red { background: #dc3545; box-shadow: 0 0 6px #dc354566; }

    /* Login card */
    .login-card {
        background: #1a1d24;
        border: 1px solid #2e3138;
        border-radius: 16px;
        padding: 2.5rem;
        max-width: 420px;
        margin: 3rem auto;
    }
    .login-card h1 { text-align: center; margin-bottom: 0.5rem; }
    .login-card .subtitle { text-align: center; color: #6c757d; margin-bottom: 2rem; }

    /* Data tables */
    [data-testid="stDataFrame"] { border: 1px solid #2e3138; border-radius: 8px; overflow: hidden; }
    [data-testid="stDataFrame"] th { background: #1a1d24 !important; color: #8a8f9a !important; font-size: 0.75rem !important; text-transform: uppercase; letter-spacing: 0.5px; }
    [data-testid="stDataFrame"] td { background: #0e1117 !important; color: #c0c0c0 !important; }

    /* Sidebar */
    section[data-testid="stSidebar"] { background: #111318; border-right: 1px solid #2e3138; }
    section[data-testid="stSidebar"] .stButton button { background: transparent; border: 1px solid #2e3138; color: #c0c0c0; }
    section[data-testid="stSidebar"] .stButton button:hover { border-color: #4a9eff; color: #fff; }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] { gap: 0; border-bottom: 1px solid #2e3138; }
    .stTabs [data-baseweb="tab"] { color: #8a8f9a; }
    .stTabs [aria-selected="true"] { color: #4a9eff; }

    /* Dividers */
    hr { border-color: #2e3138 !important; }

    /* Expanders */
    .streamlit-expanderHeader { color: #c0c0c0 !important; background: #1a1d24; border-radius: 8px; }
    .streamlit-expanderContent { border: 1px solid #2e3138; border-top: none; border-radius: 0 0 8px 8px; background: #0e1117; }

    /* Form inputs */
    .stTextInput input, .stSelectbox div[data-baseweb="select"] div, .stTextArea textarea {
        background: #1a1d24 !important; border-color: #2e3138 !important; color: #e0e0e0 !important;
    }
    .stTextInput label, .stSelectbox label, .stTextArea label { color: #8a8f9a !important; }

    /* Info/Warning boxes */
    .stAlert { background: #1a1d24 !important; border: 1px solid #2e3138 !important; border-radius: 8px; }
    .stAlert > div { color: #c0c0c0 !important; }
</style>
"""


def load_css():
    st.markdown(_CSS, unsafe_allow_html=True)


def badge_html(text: str, kind: str = "severity") -> str:
    css_map = {
        "critical": "badge-critical", "high": "badge-high",
        "medium": "badge-medium", "low": "badge-low",
        "open": "badge-open", "investigating": "badge-investigating",
        "resolved": "badge-resolved", "false_positive": "badge-false_positive",
        "pending": "badge-pending", "retried": "badge-retried",
        "discarded": "badge-discarded",
    }
    cls = css_map.get(text.lower(), "badge-low")
    return f'<span class="badge {cls}">{text}</span>'


def metric_label(icon: str, label: str, value: Any) -> str:
    return f"{icon}  **{value}**"

API_BASE = cfg.dashboard_api_base or f"http://{cfg.api_host if cfg.api_host != '0.0.0.0' else 'localhost'}:{cfg.api_port}/api/v1"

if "token" not in st.session_state:
    st.session_state.token = st.query_params.get("token")
if "user_role" not in st.session_state:
    st.session_state.user_role = None
if "user_id" not in st.session_state:
    st.session_state.user_id = None


@st.cache_data(ttl=20, show_spinner=False)
def _cached_get(path: str, params_json: str, token: str) -> str | None:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    params = json.loads(params_json) if params_json else None
    try:
        resp = httpx.get(f"{API_BASE}{path}", headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            return json.dumps(resp.json())
        return None
    except httpx.HTTPError:
        return None


def api_get(path: str, params: dict | None = None) -> Any | None:
    params_json = json.dumps(params, sort_keys=True) if params else ""
    token = st.session_state.get("token", "") or ""
    result = _cached_get(path, params_json, token)
    return json.loads(result) if result else None


def api_get_fresh(path: str, params: dict | None = None) -> Any | None:
    """Bypass cache — always hits the API."""
    headers = {}
    if st.session_state.token:
        headers["Authorization"] = f"Bearer {st.session_state.token}"
    try:
        resp = httpx.get(f"{API_BASE}{path}", headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        return None
    except httpx.HTTPError:
        return None


def api_post(path: str, data: dict | None = None) -> Any | None:
    headers = {"Content-Type": "application/json"}
    if st.session_state.token:
        headers["Authorization"] = f"Bearer {st.session_state.token}"
    try:
        resp = httpx.post(
            f"{API_BASE}{path}", headers=headers, json=data, timeout=10
        )
        if resp.status_code in (200, 201):
            return resp.json()
        return None
    except httpx.HTTPError:
        return None


def api_put(path: str, data: dict | None = None) -> Any | None:
    headers = {"Content-Type": "application/json"}
    if st.session_state.token:
        headers["Authorization"] = f"Bearer {st.session_state.token}"
    try:
        resp = httpx.put(
            f"{API_BASE}{path}", headers=headers, json=data, timeout=10
        )
        if resp.status_code == 200:
            return resp.json()
        return None
    except httpx.HTTPError:
        return None


def clear_cache():
    st.cache_data.clear()


def login_page():
    load_css()
    _, col, _ = st.columns([1, 2, 1])
    with col:
        st.markdown(
            '<div class="login-card">'
            '<div style="text-align:center;font-size:2.5rem;margin-bottom:0.5rem;">🛡️</div>'
            '<h1 style="text-align:center;margin-bottom:0.25rem;">SOC Dashboard</h1>'
            '<p class="subtitle">Wazuh AI Correlation Engine</p>',
            unsafe_allow_html=True,
        )

        with st.form("login_form"):
            st.text_input("Username", key="login_user")
            st.text_input("Password", type="password", key="login_pass")
            submitted = st.form_submit_button(
                "🔐 Sign In", use_container_width=True,
            )

            if submitted:
                username = st.session_state.get("login_user", "")
                password = st.session_state.get("login_pass", "")
                with st.spinner("Authenticating..."):
                    result = api_post("/auth/login", {"username": username, "password": password})
                if result:
                    token = result["access_token"]
                    st.session_state.token = token
                    st.query_params["token"] = token
                    payload = jwt_decode(token)
                    if payload:
                        st.session_state.user_id = payload.get("sub")
                        st.session_state.user_role = payload.get("role")
                    st.session_state.password_change_required = result.get("password_change_required", False)
                    st.rerun()
                else:
                    st.error("Invalid credentials")

        st.markdown(
            '<p style="text-align:center;color:#6c757d;font-size:0.8rem;margin-top:1rem;">'
            "Default: <strong>admin</strong> / <strong>admin123</strong></p>"
            "</div>",
            unsafe_allow_html=True,
        )
        if st.button("❓ Forgot Password?", use_container_width=True):
            st.session_state.show_forgot_password = True
            st.rerun()


def forgot_password_page():
    st.markdown(
        "<h2 style='text-align:center;'>🔐 Reset Your Password</h2>"
        "<p style='text-align:center;color:#8a8f9a;'>Enter your username to receive a reset code.</p>",
        unsafe_allow_html=True,
    )
    _, col, _ = st.columns([1, 2, 1])
    with col:
        step = st.session_state.get("fpr_step", "request")

        if step == "request":
            with st.form("fpr_request_form"):
                st.text_input("Username", key="fpr_user")
                if st.form_submit_button("Send Reset Code", use_container_width=True):
                    username = st.session_state.get("fpr_user", "").strip()
                    if not username:
                        st.error("Username is required")
                    else:
                        with st.spinner("Requesting reset code..."):
                            result = api_post("/auth/forgot-password", {"username": username})
                        if result and result.get("sent"):
                            st.session_state.fpr_mode = result.get("mode", "onscreen")
                            st.session_state.fpr_token = result.get("token", "")
                            st.session_state.fpr_username = username
                            st.session_state.fpr_step = "reset"
                            st.rerun()
                        else:
                            st.info("If the user exists, a reset code has been generated.")

        elif step == "reset":
            mode = st.session_state.get("fpr_mode", "onscreen")
            if mode == "onscreen" and st.session_state.get("fpr_token"):
                token_display = st.session_state.fpr_token
                st.markdown(
                    f"<div style='text-align:center;padding:1.5rem;background:#1a1d24;"
                    f"border:1px solid #4a9eff44;border-radius:8px;margin:1rem 0;'>"
                    f"<div style='font-size:0.75rem;color:#8a8f9a;'>Your reset code</div>"
                    f"<div style='font-size:2rem;font-weight:700;color:#4a9eff;letter-spacing:4px;"
                    f"font-family:monospace;'>{token_display}</div>"
                    f"<div style='font-size:0.75rem;color:#ffc107;margin-top:0.5rem;'>"
                    f"⏱ Expires in 15 minutes</div></div>",
                    unsafe_allow_html=True,
                )
            else:
                st.info("📧 A reset code has been sent to your email.")

            with st.form("fpr_reset_form"):
                st.text_input("Reset Code", key="fpr_code")
                st.text_input("New Password", type="password", key="fpr_new")
                st.text_input("Confirm New Password", type="password", key="fpr_confirm")
                if st.form_submit_button("Reset Password", use_container_width=True):
                    code = st.session_state.get("fpr_code", "").strip()
                    new_pw = st.session_state.get("fpr_new", "")
                    confirm = st.session_state.get("fpr_confirm", "")
                    if not code or not new_pw:
                        st.error("All fields are required")
                    elif new_pw != confirm:
                        st.error("Passwords do not match")
                    elif len(new_pw) < 6:
                        st.error("Password must be at least 6 characters")
                    else:
                        with st.spinner("Resetting password..."):
                            result = api_post("/auth/reset-with-token", {"token": code, "new_password": new_pw})
                        if result:
                            st.success("✅ Password reset! You can now log in with your new password.")
                            st.session_state.fpr_step = "done"
                            st.rerun()
                        else:
                            st.error("Invalid or expired reset code")

        elif step == "done":
            st.success("✅ Password reset successfully!")
            if st.button("← Back to Sign In", use_container_width=True):
                st.session_state.show_forgot_password = False
                st.session_state.fpr_step = "request"
                st.session_state.fpr_token = ""
                st.rerun()

        if step != "done":
            if st.button("← Back to Sign In", use_container_width=True):
                st.session_state.show_forgot_password = False
                st.session_state.fpr_step = "request"
                st.session_state.fpr_token = ""
                st.rerun()


def jwt_decode(token: str | None) -> dict | None:
    if not token:
        return None
    try:
        from jose import jwt as jose_jwt
        return jose_jwt.decode(token, cfg.jwt_secret, algorithms=[cfg.jwt_algorithm])
    except Exception:
        return None


def change_password_page():
    st.markdown(
        "<h2 style='text-align:center;'>🔐 Change Your Password</h2>"
        "<p style='text-align:center;color:#ffc107;'>You are required to change your password before continuing.</p>",
        unsafe_allow_html=True,
    )
    _, col, _ = st.columns([1, 2, 1])
    with col:
        with st.form("change_password_form"):
            st.text_input("Current Password", type="password", key="cp_old")
            st.text_input("New Password", type="password", key="cp_new")
            st.text_input("Confirm New Password", type="password", key="cp_confirm")
            if st.form_submit_button("Change Password", use_container_width=True):
                old = st.session_state.get("cp_old", "")
                new = st.session_state.get("cp_new", "")
                confirm = st.session_state.get("cp_confirm", "")
                if not old or not new:
                    st.error("All fields are required")
                elif old == new:
                    st.error("New password must be different from current password")
                elif new != confirm:
                    st.error("New passwords do not match")
                elif len(new) < 6:
                    st.error("Password must be at least 6 characters")
                else:
                    with st.spinner("Changing password..."):
                        result = api_post("/auth/change-password", {"old_password": old, "new_password": new})
                    if result:
                        st.session_state.password_change_required = False
                        st.success("Password changed successfully!")
                        st.rerun()
                    else:
                        st.error("Failed. Check your current password.")


def _render_df_with_badges(df: pd.DataFrame, badge_cols: dict[str, str] | None = None) -> None:
    html = '<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;font-size:0.85rem;">'
    html += "<thead><tr>"
    for c in df.columns:
        html += f'<th style="padding:0.5rem 0.75rem;background:#1a1d24;color:#8a8f9a;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid #2e3138;text-align:left;">{c}</th>'
    html += "</tr></thead><tbody>"
    for _, row in df.iterrows():
        html += "<tr>"
        for c in df.columns:
            val = row[c]
            if badge_cols and c in badge_cols:
                val = badge_html(str(val) if val else "unknown", badge_cols[c])
            else:
                val = str(val) if val is not None else ""
            html += f'<td style="padding:0.4rem 0.75rem;border-bottom:1px solid #2e3138;color:#c0c0c0;">{val}</td>'
        html += "</tr>"
    html += "</tbody></table></div>"
    st.markdown(html, unsafe_allow_html=True)
    st.caption(f"{len(df)} records")


def _show_alert_detail():
    st.subheader("📋 All Alerts")
    if "alert_page" not in st.session_state:
        st.session_state.alert_page = 1
    page = st.session_state.alert_page
    page_size = 50
    with st.spinner("Loading alerts..."):
        alerts_resp = api_get("/alerts", {"page_size": page_size, "page": page})
    if alerts_resp and alerts_resp.get("items"):
        df = pd.DataFrame(alerts_resp["items"])
        cols = ["event_id", "rule_description", "rule_level", "source_ip", "timestamp", "event_type"]
        display_df = df[[c for c in cols if c in df.columns]].copy()
        _render_df_with_badges(display_df)
        pagination_row(alerts_resp, "alert_page", "alert_page")
    else:
        st.info("No alerts found")
    if st.button("← Back to Overview", key="back_alerts"):
        st.session_state.metric_view = None
        st.rerun()


def _show_incident_detail(status: str | None = None, critical_only: bool = False):
    label = "🔥 Critical Incidents" if critical_only else "📌 Active Incidents"
    st.subheader(label)
    if "incident_page" not in st.session_state:
        st.session_state.incident_page = 1
    page = st.session_state.incident_page
    page_size = 50
    params = {"page_size": page_size, "page": page}
    if status:
        params["status"] = status
    if critical_only:
        params["severity"] = "critical"
    with st.spinner("Loading incidents..."):
        incidents_resp = api_get("/incidents", params)
    if incidents_resp and incidents_resp.get("items"):
        df = pd.DataFrame(incidents_resp["items"])
        cols = ["id", "title", "severity", "status", "risk_score", "alert_count", "created_at", "mitre_technique"]
        display_df = df[[c for c in cols if c in df.columns]].copy()
        _render_df_with_badges(display_df, badge_cols={"severity": "severity", "status": "status"})
        pagination_row(incidents_resp, "incident_page", "incident_page")
    else:
        st.info("No incidents found")
    if st.button("← Back to Overview", key=f"back_{status or 'critical'}"):
        st.session_state.metric_view = None
        st.rerun()


def _show_dlq_detail():
    st.subheader("📦 Dead-Letter Queue Records")
    if "dlq_page" not in st.session_state:
        st.session_state.dlq_page = 1
    page = st.session_state.dlq_page
    page_size = 50
    with st.spinner("Loading DLQ records..."):
        dlq_resp = api_get("/admin/dlq", {"page_size": page_size, "page": page})
    if dlq_resp and dlq_resp.get("items"):
        df = pd.DataFrame(dlq_resp["items"])
        cols = ["id", "error", "error_type", "source", "status", "retry_count", "created_at"]
        display_df = df[[c for c in cols if c in df.columns]].copy()
        _render_df_with_badges(display_df, badge_cols={"status": "status"})
        pagination_row(dlq_resp, "dlq_page", "dlq_page")
    else:
        st.info("No DLQ records")
    if st.button("← Back to Overview", key="back_dlq"):
        st.session_state.metric_view = None
        st.rerun()


def pagination_row(resp: dict, page_key: str, namespace: str) -> None:
    total = resp.get("total", 0)
    page = st.session_state.get(page_key, 1)
    page_size = resp.get("page_size", 50)
    total_pages = max(1, (total + page_size - 1) // page_size)
    cols = st.columns([1, 2, 1, 2, 1])
    with cols[0]:
        if st.button("⏮ First", key=f"{namespace}_first", disabled=(page <= 1)):
            st.session_state[page_key] = 1
            st.rerun()
    with cols[1]:
        if st.button("◀ Prev", key=f"{namespace}_prev", disabled=(page <= 1)):
            st.session_state[page_key] = max(1, page - 1)
            st.rerun()
    with cols[2]:
        st.markdown(
            f"<div style='text-align:center;color:#8a8f9a;padding:0.25rem;'>{page}/{total_pages}</div>",
            unsafe_allow_html=True,
        )
    with cols[3]:
        if st.button("Next ▶", key=f"{namespace}_next", disabled=(page >= total_pages)):
            st.session_state[page_key] = min(total_pages, page + 1)
            st.rerun()
    with cols[4]:
        if st.button("⏭ Last", key=f"{namespace}_last", disabled=(page >= total_pages)):
            st.session_state[page_key] = total_pages
            st.rerun()
    st.caption(f"{total} total records — page {page} of {total_pages}")


def soc_overview():
    st.header("SOC Overview")
    load_css()

    refresh_col1, refresh_col2 = st.columns([6, 1])
    with refresh_col2:
        if st.button("🔄 Refresh", use_container_width=True):
            clear_cache()
            st.rerun()

    if "metric_view" not in st.session_state:
        st.session_state.metric_view = None

    if st.session_state.metric_view == "alerts":
        _show_alert_detail()
        return
    if st.session_state.metric_view == "incidents":
        _show_incident_detail(status="open")
        return
    if st.session_state.metric_view == "critical":
        _show_incident_detail(critical_only=True)
        return
    if st.session_state.metric_view == "dlq":
        _show_dlq_detail()
        return

    with st.spinner("Loading dashboard..."):
        stats = api_get("/admin/stats")
    if not stats:
        st.warning("Unable to fetch stats. Is the API running?")
        return

    metric_config = [
        ("📊", "Total Alerts", "total_alerts", "alerts"),
        ("🚨", "Active Incidents", "open_incidents", "incidents"),
        ("🔥", "Critical Incidents", "critical_incidents", "critical"),
        ("📦", "DLQ Records", "dlq_total", "dlq"),
    ]

    cols = st.columns(4)
    for idx, (icon, label, key, view) in enumerate(metric_config):
        with cols[idx]:
            value = stats.get(key, 0)
            if st.button(metric_label(icon, label, value), key=f"metric_{view}", use_container_width=True):
                st.session_state.metric_view = view
                st.rerun()
            st.caption(label)

    with st.spinner("Loading incident data..."):
        incidents = api_get("/incidents", {"page_size": 100})
    if incidents and incidents.get("items"):
        df = pd.DataFrame(incidents["items"])

        st.markdown("<h3 style='margin-top:1.5rem;'>📈 Incident Trends</h3>", unsafe_allow_html=True)
        if "created_at" in df.columns:
            df_ts = df.copy()
            df_ts["created_at"] = pd.to_datetime(df_ts["created_at"])
            date_span = (df_ts["created_at"].max() - df_ts["created_at"].min()).total_seconds()
            freq = "h" if date_span < 86400 else "D"
            trend = df_ts.set_index("created_at").resample(freq).size().reset_index()
            trend.columns = ["Date", "Count"]
            if len(trend) <= 1:
                trend = df_ts[["created_at"]].rename(columns={"created_at": "Date"})
                trend["Count"] = 1
            use_line = len(trend) >= 3
            chart_fn = px.line if use_line else px.bar
            label = "hourly" if freq == "h" else "daily"
            fig = chart_fn(
                trend, x="Date", y="Count",
                title=f"Incidents Over Time ({label})",
            )
            fig.update_layout(
                paper_bgcolor="#0e1117", plot_bgcolor="#0e1117",
                font_color="#c0c0c0", title_font_color="#e0e0e0",
                xaxis_gridcolor="#2e3138", yaxis_gridcolor="#2e3138",
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No timestamp data for trend chart")

        mitre_col, geo_col = st.columns(2)
        with mitre_col:
            st.markdown("<h4>🕸 MITRE ATT&CK Heatmap</h4>", unsafe_allow_html=True)
            if "mitre_tactic" in df.columns and "mitre_technique" in df.columns:
                valid = df[df["mitre_tactic"].notna() & df["mitre_technique"].notna()]
                if not valid.empty:
                    heat = valid.groupby(["mitre_tactic", "mitre_technique"]).size().reset_index(name="count")
                    fig = px.density_heatmap(
                        heat, x="mitre_technique", y="mitre_tactic", z="count",
                        color_continuous_scale="Viridis",
                    )
                    fig.update_layout(
                        paper_bgcolor="#0e1117", plot_bgcolor="#0e1117",
                        font_color="#c0c0c0", title_font_color="#e0e0e0",
                        xaxis_gridcolor="#2e3138", yaxis_gridcolor="#2e3138",
                        xaxis_tickangle=-45,
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No MITRE data available")
            else:
                st.info("No MITRE data available")

        with geo_col:
            st.markdown("<h4>🌍 Top Source IPs</h4>", unsafe_allow_html=True)
            if "source_ips" in df.columns:
                all_ips = []
                for ips in df["source_ips"].dropna():
                    if isinstance(ips, list):
                        all_ips.extend(ips)
                if all_ips:
                    ip_counts = pd.Series(all_ips).value_counts().head(20).reset_index()
                    ip_counts.columns = ["Source IP", "Count"]
                    fig = px.bar(
                        ip_counts, x="Count", y="Source IP",
                        orientation="h",
                        color="Count", color_continuous_scale="Reds",
                    )
                    fig.update_layout(
                        paper_bgcolor="#0e1117", plot_bgcolor="#0e1117",
                        font_color="#c0c0c0", title_font_color="#e0e0e0",
                        xaxis_gridcolor="#2e3138", yaxis_gridcolor="#2e3138",
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No source IPs found")
            else:
                st.info("No source IP data")

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("<h4>🎯 Severity Distribution</h4>", unsafe_allow_html=True)
            if "severity" in df.columns:
                sev_counts = df["severity"].value_counts().reset_index()
                sev_counts.columns = ["Severity", "Count"]
                fig = px.pie(
                    sev_counts, values="Count", names="Severity",
                    color="Severity",
                    color_discrete_map={
                        "critical": "#dc3545", "high": "#fd7e14",
                        "medium": "#ffc107", "low": "#28a745",
                    },
                )
                fig.update_layout(
                    paper_bgcolor="#0e1117", plot_bgcolor="#0e1117",
                    font_color="#c0c0c0", title_font_color="#e0e0e0",
                )
                st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.markdown("<h4>🏆 Top Attack Sources</h4>", unsafe_allow_html=True)
            if "source_ips" in df.columns:
                all_ips = []
                for ips in df["source_ips"].dropna():
                    if isinstance(ips, list):
                        all_ips.extend(ips)
                if all_ips:
                    ip_counts = pd.Series(all_ips).value_counts().head(10).reset_index()
                    ip_counts.columns = ["Source IP", "Count"]
                    fig = px.bar(
                        ip_counts, x="Count", y="Source IP",
                        orientation="h",
                        color="Count", color_continuous_scale="Viridis",
                    )
                    fig.update_layout(
                        paper_bgcolor="#0e1117", plot_bgcolor="#0e1117",
                        font_color="#c0c0c0", title_font_color="#e0e0e0",
                        xaxis_gridcolor="#2e3138", yaxis_gridcolor="#2e3138",
                    )
                    st.plotly_chart(fig, use_container_width=True)

    with st.spinner("Loading health..."):
        health = api_get_fresh("/health")
    if health:
        st.markdown("<h3 style='margin-top:1rem;'>🖥 System Health</h3>", unsafe_allow_html=True)
        col1, col2, col3, col4 = st.columns(4)
        api_ok = (health.get("status") or "").lower() in ("healthy", "ok")
        db_ok = (health.get("database") or "").lower() in ("healthy", "ok")
        uptime = health.get("uptime_seconds", 0)
        uptime_str = f"{int(uptime // 3600)}h {int((uptime % 3600) // 60)}m" if uptime else "N/A"
        with col1:
            dot = "green" if api_ok else "red"
            st.markdown(
                f"<div style='background:#1a1d24;border:1px solid #2e3138;border-radius:8px;padding:1rem;'>"
                f"<div style='font-size:0.75rem;color:#8a8f9a;'>API</div>"
                f"<div style='font-size:1.3rem;font-weight:700;'><span class='status-dot {dot}'></span>{'Healthy' if api_ok else 'Down'}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )
        with col2:
            dot = "green" if db_ok else "red"
            st.markdown(
                f"<div style='background:#1a1d24;border:1px solid #2e3138;border-radius:8px;padding:1rem;'>"
                f"<div style='font-size:0.75rem;color:#8a8f9a;'>Database</div>"
                f"<div style='font-size:1.3rem;font-weight:700;'><span class='status-dot {dot}'></span>{'Healthy' if db_ok else 'Down'}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )
        with col3:
            ts = health.get("timestamp", "")
            st.markdown(
                f"<div style='background:#1a1d24;border:1px solid #2e3138;border-radius:8px;padding:1rem;'>"
                f"<div style='font-size:0.75rem;color:#8a8f9a;'>Last Check</div>"
                f"<div style='font-size:1rem;font-weight:600;color:#e0e0e0;'>{str(ts)[:19]}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )
        with col4:
            st.markdown(
                f"<div style='background:#1a1d24;border:1px solid #2e3138;border-radius:8px;padding:1rem;'>"
                f"<div style='font-size:0.75rem;color:#8a8f9a;'>Uptime</div>"
                f"<div style='font-size:1.3rem;font-weight:700;color:#e0e0e0;'>{uptime_str}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )


def threat_intel_page():
    load_css()
    st.header("Threat Intelligence")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("<h4>🕸 MITRE ATT&CK Breakdown</h4>", unsafe_allow_html=True)
        with st.spinner("Loading MITRE data..."):
            incidents = api_get("/incidents", {"page_size": 200})
        if incidents and incidents.get("items"):
            df = pd.DataFrame(incidents["items"])
            if "mitre_tactic" in df.columns and "mitre_technique" in df.columns:
                valid = df[df["mitre_tactic"].notna() & df["mitre_technique"].notna()]
                if not valid.empty:
                    heat = valid.groupby(["mitre_tactic", "mitre_technique"]).size().reset_index(name="count")
                    fig = px.density_heatmap(
                        heat, x="mitre_technique", y="mitre_tactic", z="count",
                        color_continuous_scale="Viridis",
                        text_auto=True,
                    )
                    fig.update_layout(
                        xaxis_tickangle=-45, height=500,
                        paper_bgcolor="#0e1117", plot_bgcolor="#0e1117",
                        font_color="#c0c0c0", title_font_color="#e0e0e0",
                        xaxis_gridcolor="#2e3138", yaxis_gridcolor="#2e3138",
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No MITRE data available")

            with st.expander("📋 MITRE Technique Details"):
                if "mitre_technique" in df.columns:
                    tech_counts = df["mitre_technique"].value_counts().reset_index()
                    tech_counts.columns = ["Technique", "Count"]
                    _render_df_with_badges(tech_counts)
        else:
            st.info("No incident data available")

    with col2:
        st.markdown("<h4>🌍 Source IP Threat Landscape</h4>", unsafe_allow_html=True)
        with st.spinner("Loading IP data..."):
            incidents = api_get("/incidents", {"page_size": 200})
        if incidents and incidents.get("items"):
            df = pd.DataFrame(incidents["items"])
            if "source_ips" in df.columns:
                all_ips = []
                for ips in df["source_ips"].dropna():
                    if isinstance(ips, list):
                        all_ips.extend(ips)
                if all_ips:
                    ip_counts = pd.Series(all_ips).value_counts().head(15).reset_index()
                    ip_counts.columns = ["Source IP", "Incidents"]
                    fig = px.bar(
                        ip_counts, x="Incidents", y="Source IP",
                        orientation="h",
                        color="Incidents", color_continuous_scale="Reds",
                    )
                    fig.update_layout(
                        paper_bgcolor="#0e1117", plot_bgcolor="#0e1117",
                        font_color="#c0c0c0", title_font_color="#e0e0e0",
                        xaxis_gridcolor="#2e3138", yaxis_gridcolor="#2e3138",
                    )
                    st.plotly_chart(fig, use_container_width=True)

                    csv_buf = io.StringIO()
                    writer = csv.writer(csv_buf)
                    writer.writerow(["Source IP", "Incidents"])
                    writer.writerows(zip(ip_counts["Source IP"], ip_counts["Incidents"]))
                    st.download_button(
                        "⬇ Download IP Report (CSV)",
                        data=csv_buf.getvalue(),
                        file_name="threat_ips.csv",
                        mime="text/csv",
                        use_container_width=True,
                    )
                else:
                    st.info("No source IPs found")

            with st.expander("📊 Risk Score Distribution"):
                if "risk_score" in df.columns:
                    fig = px.histogram(
                        df, x="risk_score", nbins=20,
                        color_discrete_sequence=["#dc3545"],
                    )
                    fig.update_layout(
                        paper_bgcolor="#0e1117", plot_bgcolor="#0e1117",
                        font_color="#c0c0c0", title_font_color="#e0e0e0",
                        xaxis_gridcolor="#2e3138", yaxis_gridcolor="#2e3138",
                    )
                    st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No incident data available")

    st.markdown("<h4 style='margin-top:1rem;'>⚡ Recent Activity Feed</h4>", unsafe_allow_html=True)
    with st.spinner("Loading activity..."):
        incidents = api_get("/incidents", {"page_size": 20})
    if incidents and incidents.get("items"):
        items = incidents["items"]
        for item in items:
            sev = item.get("severity", "unknown")
            sev_badge = badge_html(sev, "severity")
            stat = item.get("status", "")
            stat_badge = badge_html(stat, "status")
            st.markdown(
                f"<div style='padding:0.4rem 0;border-bottom:1px solid #2e3138;'>"
                f"{sev_badge} "
                f"<strong style='color:#e0e0e0;'>{item.get('title', 'Untitled')}</strong> "
                f"{stat_badge} "
                f"<span style='color:#6c757d;font-size:0.8em;'>{item.get('id', '')[:8]}...</span>"
                f"</div>",
                unsafe_allow_html=True,
            )


def incident_explorer():
    load_css()
    st.header("Incident Explorer")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        severity_filter = st.selectbox("Severity", ["All", "critical", "high", "medium", "low"])
    with col2:
        status_filter = st.selectbox("Status", ["All", "open", "investigating", "resolved", "false_positive"])
    with col3:
        host_filter = st.text_input("Host contains")
    with col4:
        page_size = st.selectbox("Page size", [20, 50, 100], index=0)

    params = {"page_size": page_size}
    if severity_filter != "All":
        params["severity"] = severity_filter
    if status_filter != "All":
        params["status"] = status_filter
    if host_filter:
        params["host"] = host_filter

    if "inc_explorer_page" not in st.session_state:
        st.session_state.inc_explorer_page = 1
    params["page"] = st.session_state.inc_explorer_page

    with st.spinner("Loading incidents..."):
        incidents = api_get("/incidents", params)

    if incidents and incidents.get("items"):
        df = pd.DataFrame(incidents["items"])
        display_cols = ["id", "severity", "title", "status", "risk_score", "alert_count", "created_at", "mitre_technique"]
        display_df = df[[c for c in display_cols if c in df.columns]].copy()
        _render_df_with_badges(display_df, badge_cols={"severity": "severity", "status": "status"})

        pagination_row(incidents, "inc_explorer_page", "inc_explorer")

        export_col1, export_col2, export_col3 = st.columns([1, 1, 3])
        with export_col1:
            csv_buf = io.StringIO()
            display_df.to_csv(csv_buf, index=False)
            st.download_button(
                "⬇ Export CSV", data=csv_buf.getvalue(),
                file_name="incidents.csv", mime="text/csv",
                use_container_width=True,
            )
        with export_col2:
            json_buf = io.StringIO()
            json.dump(incidents["items"], json_buf, indent=2, default=str)
            st.download_button(
                "⬇ Export JSON", data=json_buf.getvalue(),
                file_name="incidents.json", mime="application/json",
                use_container_width=True,
            )
        with export_col3:
            if st.button("🔄 Refresh", use_container_width=True):
                clear_cache()
                st.rerun()

        selected_id = st.text_input("🔍 View incident by ID:")
        if selected_id:
            with st.spinner("Loading incident..."):
                incident = api_get(f"/incidents/{selected_id}")
            if incident:
                with st.expander("Incident Detail", expanded=True):
                    st.json(incident)
                    col_a, col_b, col_c, col_d = st.columns(4)
                    with col_a:
                        if st.button("🤖 Run AI Analysis", key="ai_btn"):
                            with st.spinner("Analyzing..."):
                                analysis = api_post("/analyze", {"incident_id": selected_id})
                            if analysis:
                                st.success("Analysis complete")
                                st.json(analysis)
                            else:
                                st.error("Analysis failed")
                    with col_b:
                        if st.button("📄 Generate Report", key="report_btn"):
                            with st.spinner("Generating report..."):
                                report = api_post(f"/incidents/{selected_id}/report", {"formats": ["json", "html"]})
                            if report:
                                st.success(f"Report generated: {report}")
                            else:
                                st.error("Report generation failed")
                    with col_c:
                        if st.button("🗑 Delete", key="del_btn"):
                            headers = {}
                            if st.session_state.token:
                                headers["Authorization"] = f"Bearer {st.session_state.token}"
                            with st.spinner("Deleting..."):
                                resp = httpx.delete(f"{API_BASE}/incidents/{selected_id}", headers=headers, timeout=10)
                            if resp.status_code == 200:
                                st.success("Incident deleted")
                                st.rerun()
                            else:
                                st.error("Delete failed")
                    with col_d:
                        feedback_resp = api_get(f"/incidents/{selected_id}/feedback")
                        fb_count = feedback_resp.get("total", 0) if feedback_resp else 0
                        if st.button(f"💬 Feedback ({fb_count})", key="fb_btn"):
                            st.session_state.show_feedback = selected_id

                if st.session_state.get("show_feedback") == selected_id:
                    with st.expander("Analyst Feedback", expanded=True):
                        with st.spinner("Loading feedback..."):
                            feedback_resp = api_get(f"/incidents/{selected_id}/feedback")
                        if feedback_resp and feedback_resp.get("items"):
                            for fb in feedback_resp["items"]:
                                sev = fb.get("action", "")
                                st.markdown(
                                    f"**{sev}** by `{fb.get('analyst_id', 'unknown')[:8]}` "
                                    f"- {fb.get('reason', '')} "
                                    f"<span style='color:#6c757d;font-size:0.8em;'>{fb.get('timestamp', '')}</span>",
                                    unsafe_allow_html=True,
                                )
                        else:
                            st.info("No feedback yet")

                        with st.form("feedback_form"):
                            fb_action = st.selectbox("Action", ["note", "score_adjustment", "fp_mark", "ai_override"])
                            fb_reason = st.text_area("Notes / Reason")
                            if st.form_submit_button("Submit Feedback"):
                                with st.spinner("Submitting..."):
                                    result = api_post(f"/incidents/{selected_id}/feedback", {"action": fb_action, "reason": fb_reason})
                                if result:
                                    st.success("Feedback submitted")
                                    st.rerun()
                                else:
                                    st.error("Failed to submit feedback")
            else:
                st.error("Incident not found")

        st.markdown("---")
        st.markdown("<h4>📝 Update Incident Status</h4>", unsafe_allow_html=True)
        with st.form("update_status_form"):
            up_col1, up_col2, up_col3 = st.columns([2, 1, 1])
            with up_col1:
                upd_id = st.text_input("Incident ID", placeholder="Paste incident ID from table above")
            with up_col2:
                new_status = st.selectbox("New Status", ["open", "investigating", "resolved", "false_positive"])
            with up_col3:
                st.write("")
                st.write("")
                submitted = st.form_submit_button("Update Status", use_container_width=True)
            if submitted and upd_id:
                headers = {"Content-Type": "application/json"}
                if st.session_state.token:
                    headers["Authorization"] = f"Bearer {st.session_state.token}"
                with st.spinner("Updating..."):
                    try:
                        r = httpx.put(f"{API_BASE}/incidents/{upd_id}", headers=headers,
                                      json={"status": new_status}, timeout=10)
                        if r.status_code == 200:
                            st.success(f"Incident {upd_id} status changed to {new_status}")
                            st.rerun()
                        else:
                            detail = r.json().get("detail", "Unknown error")
                            st.error(f"Failed ({r.status_code}): {detail}")
                    except httpx.HTTPError as exc:
                        st.error(f"Connection error: {exc}")

        st.markdown("<h4>🔗 Merge Incidents</h4>", unsafe_allow_html=True)
        with st.form("merge_form"):
            merge_ids = st.text_input("Incident IDs (comma-separated)", placeholder="id1, id2, id3")
            merge_title = st.text_input("New title (optional)")
            if st.form_submit_button("Merge"):
                ids = [x.strip() for x in merge_ids.split(",") if x.strip()]
                if len(ids) >= 2:
                    with st.spinner("Merging..."):
                        result = api_post("/incidents/merge", {"incident_ids": ids, "title": merge_title or None})
                    if result:
                        st.success(f"Merged into {result.get('merged_incident_id')}")
                        st.rerun()
                    else:
                        st.error("Merge failed. Check IDs and permissions.")
                else:
                    st.error("At least 2 incident IDs required")

        st.markdown("<h4>✂️ Split Incident</h4>", unsafe_allow_html=True)
        with st.form("split_form"):
            split_id = st.text_input("Incident ID to split")
            split_alert_ids = st.text_input("Alert IDs to move (comma-separated)")
            split_title = st.text_input("New incident title (optional)")
            if st.form_submit_button("Split"):
                aids = [x.strip() for x in split_alert_ids.split(",") if x.strip()]
                if split_id and aids:
                    with st.spinner("Splitting..."):
                        result = api_post(f"/incidents/{split_id}/split", {"incident_id": split_id, "alert_ids": aids, "title": split_title or None})
                    if result:
                        st.success(f"Split into {result.get('new_incident_id')}")
                        st.rerun()
                    else:
                        st.error("Split failed")
                else:
                    st.error("Incident ID and at least 1 alert ID required")
    else:
        st.info("No incidents found matching the filters.")


def admin_panel():
    load_css()
    st.header("Admin Panel")

    if st.session_state.user_role != "admin":
        st.warning("Admin access required")
        return

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "📦 DLQ Management", "👥 Users", "🔗 Webhooks", "📋 Audit Log", "⚙ Configuration", "📊 System Stats",
    ])

    with tab1:
        st.subheader("Dead-Letter Queue")
        with st.spinner("Loading DLQ..."):
            dlq = api_get("/admin/dlq")
        if dlq and dlq.get("items"):
            df = pd.DataFrame(dlq["items"])
            display_cols = ["id", "error", "error_type", "source", "status", "retry_count", "created_at"]
            display_df = df[[c for c in display_cols if c in df.columns]].copy()
            _render_df_with_badges(display_df, badge_cols={"status": "status"})

            col1, col2 = st.columns(2)
            with col1:
                dlq_id = st.text_input("DLQ Record ID to retry:")
                if st.button("🔄 Retry", key="dlq_retry") and dlq_id:
                    with st.spinner("Retrying..."):
                        result = api_post(f"/admin/dlq/{dlq_id}/retry")
                    if result:
                        st.success("Retried")
                    else:
                        st.error("Failed")
            with col2:
                dlq_discard_id = st.text_input("DLQ Record ID to discard:")
                if st.button("🗑 Discard", key="dlq_discard") and dlq_discard_id:
                    with st.spinner("Discarding..."):
                        result = api_post(f"/admin/dlq/{dlq_discard_id}/discard")
                    if result:
                        st.success("Discarded")
                    else:
                        st.error("Failed")

            if st.button("🔄 Retry All Pending"):
                with st.spinner("Retrying all..."):
                    result = api_post("/admin/dlq/retry-all")
                if result:
                    st.success(f"Retried {result.get('retried', 0)} records")
        else:
            st.info("No DLQ records")

    with tab2:
        st.subheader("👥 User Management")
        with st.spinner("Loading..."):
            token = st.session_state.get("token", "")
            resp = httpx.get(f"{API_BASE}/admin/users", headers={"Authorization": f"Bearer {token}"}, timeout=10)
            users = resp.json() if resp.status_code == 200 else None
        if users and users.get("users"):
            df = pd.DataFrame(users["users"])
            disp_cols = ["username", "role", "active", "force_password_change", "password_changed_at", "created_at"]
            disp = df[[c for c in disp_cols if c in df.columns]].copy()
            _render_df_with_badges(disp)

            st.markdown("---")

            create_tab, edit_tab, reset_tab, delete_tab = st.tabs(["➕ Create", "✏ Edit / Toggle", "🔑 Reset Password", "🗑 Delete"])

            with create_tab:
                with st.form("create_user_form"):
                    col1, col2 = st.columns(2)
                    with col1:
                        new_user = st.text_input("Username")
                        new_pw = st.text_input("Password", type="password")
                    with col2:
                        new_role = st.selectbox("Role", ["analyst", "senior_analyst", "admin"])
                        new_email = st.text_input("Email (optional)")
                    if st.form_submit_button("➕ Create User", use_container_width=True):
                        if not new_user or not new_pw:
                            st.error("Username and password are required")
                        elif len(new_pw) < 6:
                            st.error("Password must be at least 6 characters")
                        else:
                            headers = {"Content-Type": "application/json"}
                            if st.session_state.token:
                                headers["Authorization"] = f"Bearer {st.session_state.token}"
                            with st.spinner("Creating..."):
                                try:
                                    r = httpx.post(f"{API_BASE}/admin/users", headers=headers,
                                                   json={"username": new_user, "password": new_pw,
                                                          "role": new_role, "email": new_email or None},
                                                   timeout=10)
                                    if r.status_code == 200:
                                        st.success(f"User '{new_user}' created!")
                                        st.rerun()
                                    elif r.status_code == 409:
                                        st.error(f"User '{new_user}' already exists")
                                    else:
                                        detail = r.json().get("detail", "Unknown error")
                                        st.error(f"Failed ({r.status_code}): {detail}")
                                except httpx.HTTPError as exc:
                                    st.error(f"Connection error: {exc}")

            with edit_tab:
                with st.form("edit_user_form"):
                    target_user = st.selectbox("User", [u["username"] for u in users["users"]], key="edit_user_sel")
                    target = next((u for u in users["users"] if u["username"] == target_user), None)
                    if target:
                        edit_role = st.selectbox("Role", ["analyst", "senior_analyst", "admin"],
                                                 index=["analyst", "senior_analyst", "admin"].index(target["role"]))
                        edit_active = st.checkbox("Active", value=target.get("active", True))
                        if st.form_submit_button("💾 Save Changes", use_container_width=True):
                            with st.spinner("Updating..."):
                                result = api_put(f"/admin/users/{target['id']}", {
                                    "role": edit_role, "active": edit_active,
                                })
                            if result:
                                st.success(f"User '{target_user}' updated")
                                st.rerun()
                            else:
                                st.error("Failed to update user")

            with reset_tab:
                with st.form("reset_pw_form"):
                    target_user = st.selectbox("User", [u["username"] for u in users["users"]], key="reset_user_sel")
                    new_pw = st.text_input("New Password", type="password")
                    if st.form_submit_button("🔑 Reset Password", use_container_width=True):
                        target = next((u for u in users["users"] if u["username"] == target_user), None)
                        if target and new_pw:
                            with st.spinner("Resetting..."):
                                result = api_post("/auth/reset-password", {"user_id": target["id"], "new_password": new_pw})
                            if result:
                                st.success(f"Password reset for {target_user}. They must change on next login.")
                                st.rerun()
                            else:
                                st.error("Failed to reset password")

            with delete_tab:
                with st.form("delete_user_form"):
                    target_user = st.selectbox("User", [u["username"] for u in users["users"]], key="delete_user_sel")
                    confirm = st.text_input("Type 'yes' to confirm deletion")
                    if st.form_submit_button("🗑 Delete User", use_container_width=True, type="primary"):
                        if confirm != "yes":
                            st.error("Type 'yes' to confirm")
                        else:
                            target = next((u for u in users["users"] if u["username"] == target_user), None)
                            if target:
                                with st.spinner("Deleting..."):
                                    r = httpx.delete(
                                        f"{API_BASE}/admin/users/{target['id']}",
                                        headers={"Authorization": f"Bearer {st.session_state.token}"},
                                        timeout=10,
                                    )
                                if r.status_code == 200:
                                    st.success(f"User '{target_user}' deleted")
                                    st.rerun()
                                else:
                                    st.error(r.json().get("detail", "Failed to delete user"))
        else:
            st.info("Unable to load users")

    with tab3:
        st.subheader("🔗 Webhooks")
        with st.spinner("Loading webhooks..."):
            webhooks = api_get("/webhooks")
        if webhooks and webhooks.get("webhooks"):
            st.json(webhooks["webhooks"])
        else:
            st.info("No webhooks configured")

        with st.form("webhook_form"):
            st.markdown("**Register New Webhook**")
            url = st.text_input("Webhook URL")
            secret = st.text_input("Secret (optional)", type="password")
            events = st.multiselect(
                "Events",
                ["incident_created", "incident_updated", "critical_alert"],
                default=["incident_created", "critical_alert"],
            )
            if st.form_submit_button("Register"):
                with st.spinner("Registering..."):
                    result = api_post("/webhooks/configure", {"url": url, "secret": secret or None, "events": events})
                if result:
                    st.success(f"Webhook registered: {result.get('id')}")
                else:
                    st.error("Failed to register webhook")

    with tab4:
        st.subheader("📋 Audit Log")
        with st.spinner("Loading audit log..."):
            audit = api_get("/admin/audit-log", {"page_size": 100})
        if audit and audit.get("items"):
            df = pd.DataFrame(audit["items"])
            disp_cols = ["created_at", "actor_id", "action", "resource_type", "resource_id"]
            disp = df[[c for c in disp_cols if c in df.columns]].copy()
            _render_df_with_badges(disp)
        else:
            st.info("No audit log entries")

    with tab5:
        st.subheader("⚙ System Configuration")
        with st.spinner("Loading config..."):
            config = api_get("/admin/config")
        if config:
            st.json(config)
            cfg_buf = io.StringIO()
            json.dump(config, cfg_buf, indent=2)
            st.download_button(
                "⬇ Download Config (JSON)", data=cfg_buf.getvalue(),
                file_name="system_config.json", mime="application/json",
                use_container_width=False,
            )
        else:
            st.info("Unable to fetch configuration")

    with tab6:
        st.subheader("📊 System Statistics")
        with st.spinner("Loading stats..."):
            stats = api_get("/admin/stats")
        if stats:
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Total Alerts", stats.get("total_alerts", 0))
                st.metric("Open Incidents", stats.get("open_incidents", 0))
                st.metric("Critical Incidents", stats.get("critical_incidents", 0))
            with col2:
                st.metric("DLQ Records", stats.get("dlq_total", 0))
                st.metric("Alerts Today", stats.get("alerts_today", 0))


def main():
    load_css()

    if "password_change_required" not in st.session_state:
        st.session_state.password_change_required = False
    if "show_forgot_password" not in st.session_state:
        st.session_state.show_forgot_password = False
    if "fpr_step" not in st.session_state:
        st.session_state.fpr_step = "request"

    if not st.session_state.token and "token" in st.query_params:
        st.session_state.token = st.query_params["token"]
    if st.session_state.token and not st.session_state.user_id:
        _payload = jwt_decode(st.session_state.token)
        if _payload:
            st.session_state.user_id = _payload.get("sub")
            st.session_state.user_role = _payload.get("role")

    if not st.session_state.token:
        if st.session_state.get("show_forgot_password"):
            forgot_password_page()
            return
        login_page()
        return

    if st.session_state.get("password_change_required", False):
        change_password_page()
        return

    role_icon = {"admin": "🔑", "analyst": "🔍", "viewer": "👁️"}.get(
        st.session_state.user_role or "", "👤"
    )

    st.sidebar.markdown(
        f"<div style='display:flex;align-items:center;gap:10px;padding:0.5rem 0;'>"
        f"<span style='font-size:1.8rem;'>🛡️</span>"
        f"<div><strong style='font-size:1.1rem;color:#e0e0e0;'>SOC Dashboard</strong>"
        f"<br><span style='font-size:0.75rem;color:#6c757d;'>Wazuh AI Correlation Engine</span></div>"
        f"</div>",
        unsafe_allow_html=True,
    )

    st.sidebar.markdown(
        f"<div style='padding:0.75rem;background:#1a1d24;border-radius:8px;border:1px solid #2e3138;margin-bottom:1rem;'>"
        f"<div style='font-size:0.75rem;color:#6c757d;'>Logged in as</div>"
        f"<div style='font-weight:600;color:#e0e0e0;'>{role_icon} {st.session_state.user_id or 'Unknown'}</div>"
        f"<div style='font-size:0.75rem;color:#8a8f9a;'>{st.session_state.user_role or 'N/A'}</div>"
        f"</div>",
        unsafe_allow_html=True,
    )

    page = st.sidebar.radio(
        "Navigation",
        ["SOC Overview", "Threat Intelligence", "Incident Explorer", "Admin Panel"],
        index=0,
    )

    st.sidebar.markdown("---")
    if st.sidebar.button("🔐 Change Password", use_container_width=True):
        st.session_state.show_change_password = True
        st.rerun()
    st.sidebar.markdown("---")
    if st.sidebar.button("🔄 Refresh Data", use_container_width=True):
        clear_cache()
        st.rerun()
    if st.sidebar.button("🚪 Logout", use_container_width=True):
        st.session_state.token = None
        st.session_state.user_role = None
        st.session_state.user_id = None
        st.query_params.clear()
        st.session_state.password_change_required = False
        st.rerun()

    if st.session_state.get("show_change_password"):
        st.markdown("---")
        change_password_page()
        if st.button("← Back"):
            st.session_state.show_change_password = False
            st.rerun()
        return

    if page == "SOC Overview":
        soc_overview()
    elif page == "Threat Intelligence":
        threat_intel_page()
    elif page == "Incident Explorer":
        incident_explorer()
    elif page == "Admin Panel":
        admin_panel()


if __name__ == "__main__":
    main()
