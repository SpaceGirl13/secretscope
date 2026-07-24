"""
SecretScope - Streamlit frontend
Run with: streamlit run app.py
"""

import streamlit as st
import time
import tempfile

# Team imports
from ai_layer import analyze_findings_batch, simulate_attack

# Detector - real if available, mock otherwise.
# scan_for_ai() is the safe entrypoint: it redacts the actual secret value
# out of both `match` and `context` before findings ever reach the AI layer.
try:
    from detector import scan_for_ai, decode_text_bytes
except ImportError:
    def scan_for_ai(code, filename="input"):
        return [
            {"type": "AWS Access Key", "service": "aws", "severity": "critical",
             "line": 8, "match": "AKIA************7890",
             "context": 'AWS_ACCESS_KEY = "[REDACTED]"',
             "file": filename},
            {"type": "OpenAI API Key", "service": "openai", "severity": "critical",
             "line": 12, "match": "sk-*******************defg",
             "context": 'openai.api_key = "[REDACTED]"',
             "file": filename},
            {"type": "Stripe Secret Key", "service": "stripe", "severity": "critical",
             "line": 15, "match": "sk_live_************3210",
             "context": 'stripe.api_key = "[REDACTED]"',
             "file": filename},
            {"type": "GitHub Token", "service": "github", "severity": "high",
             "line": 18, "match": "ghp_************xyz123",
             "context": 'GH_TOKEN = "[REDACTED]"',
             "file": filename},
        ]
    def decode_text_bytes(data):
        return data.decode("utf-8", errors="replace")

# Person 4's modules - graceful fallback if not ready
try:
    from diff_view import render_diff
except ImportError:
    def render_diff(original_line, fixed_line, line_num):
        st.code(f"- {original_line}\n+ {fixed_line}", language="diff")

try:
    from bundle import create_fix_bundle
except ImportError:
    def create_fix_bundle(findings, analyses):
        return None

try:
    from report import generate_report
except ImportError:
    def generate_report(findings, output_path="report.pdf"):
        return None


# ---------- Sample code for demo ----------
SAMPLE_VULNERABLE_CODE = '''# config.py - Application configuration
import os
import boto3
import openai
import stripe

# AWS credentials for S3 backup uploads
AWS_ACCESS_KEY = "AWS_KEY_PLACEHOLDER_NOT_REAL_1234567890"
AWS_REGION = "us-east-1"

# OpenAI for the chatbot feature
openai.api_key = "OPENAI_KEY_PLACEHOLDER_NOT_REAL_abcdefg"

# Stripe for payment processing
stripe.api_key = "STRIPE_KEY_PLACEHOLDER_NOT_REAL_9876543210"

# GitHub token for CI/CD pipeline
GH_TOKEN = "GITHUB_TOKEN_PLACEHOLDER_NOT_REAL_xyz123"

def upload_backup(data):
    client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY,
        region_name=AWS_REGION,
    )
    client.put_object(Bucket="my-app-backups", Key="latest.json", Body=data)
'''


# ---------- Page config ----------
st.set_page_config(
    page_title="SecretScope",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------- Custom CSS ----------
st.markdown("""
<style>
    :root {
        --bg: #0b1220;
        --panel: #111a2b;
        --panel-soft: #152036;
        --border: rgba(255,255,255,0.08);
        --text: #f7f9fc;
        --muted: #98a6ba;
        --accent: #6f8cff;
        --accent-2: #54d2b3;
        --danger: #ff6b7a;
        --warning: #f0b45a;
    }

    .stApp {
        background: var(--bg);
        color: var(--text);
    }

    .block-container {
        max-width: 1180px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    .brand-lockup {
        display: flex;
        align-items: center;
        gap: 1rem;
        margin-bottom: 1.25rem;
    }

    .brand-mark {
        width: 48px;
        height: 48px;
        border-radius: 14px;
        display: grid;
        place-items: center;
        background: var(--accent);
        box-shadow: 0 14px 34px rgba(84, 210, 179, 0.18);
    }

    .lock-icon {
        position: relative;
        width: 18px;
        height: 15px;
        border-radius: 4px;
        background: #07111f;
        display: block;
        margin-top: 7px;
    }

    .lock-icon::before {
        content: "";
        position: absolute;
        left: 3px;
        top: -9px;
        width: 12px;
        height: 11px;
        border: 3px solid #07111f;
        border-bottom: 0;
        border-radius: 8px 8px 0 0;
    }

    .lock-icon::after {
        content: "";
        position: absolute;
        left: 8px;
        top: 5px;
        width: 2px;
        height: 5px;
        border-radius: 2px;
        background: var(--accent);
    }

    .main-header {
        margin: 0;
        font-size: 2.5rem;
        line-height: 1;
        font-weight: 800;
        letter-spacing: -0.045em;
        color: var(--text);
    }

    .subtitle {
        margin: 0.45rem 0 0;
        color: var(--muted);
        font-size: 1rem;
    }

    [data-testid="stSidebar"] {
        background: rgba(9, 17, 31, 0.96);
        border-right: 1px solid var(--border);
    }

    [data-testid="stSidebar"] .block-container {
        padding-top: 1.5rem;
    }

    .sidebar-brand {
        margin-bottom: 0;
        color: var(--text);
        font-size: 1.25rem;
        font-weight: 800;
    }

    .sidebar-tagline {
        margin-top: 0.25rem;
        color: var(--muted);
        font-size: 0.84rem;
    }

    [data-testid="stSidebar"] div[role="radiogroup"] {
        gap: 0.2rem;
    }

    [data-testid="stSidebar"] div[role="radiogroup"] > label {
        width: 100%;
        padding: 0.6rem 0.75rem;
        border: 1px solid transparent;
        border-radius: 11px;
        transition: background 120ms ease, border-color 120ms ease;
    }

    [data-testid="stSidebar"] div[role="radiogroup"] > label:hover {
        background: rgba(111, 140, 255, 0.08);
    }

    [data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) {
        background: rgba(111, 140, 255, 0.12);
        border-color: rgba(111, 140, 255, 0.25);
    }

    [data-testid="stMetric"] {
        background: rgba(255,255,255,0.025);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 0.85rem 1rem;
    }

    [data-testid="stMetricLabel"] {
        color: var(--muted);
    }

    [data-testid="stMetricValue"] {
        color: var(--text);
    }

    [data-testid="stVerticalBlockBorderWrapper"] {
        border-color: var(--border) !important;
        border-radius: 18px !important;
        background: rgba(17, 26, 43, 0.55);
    }

    .stTextArea textarea,
    .stTextInput input {
        background: #0d1728;
        color: var(--text);
        border: 1px solid var(--border);
        border-radius: 12px;
    }

    .stTextArea textarea:focus,
    .stTextInput input:focus {
        border-color: var(--accent);
        box-shadow: 0 0 0 3px rgba(111, 140, 255, 0.12);
    }

    .stButton > button,
    .stDownloadButton > button,
    .stLinkButton > a {
        border-radius: 11px;
        font-weight: 700;
        min-height: 44px;
        transition: transform 120ms ease, border-color 120ms ease;
    }

    .stButton > button[kind="primary"] {
        color: var(--text);
        background: #1b2a44;
        border: 1px solid rgba(111, 140, 255, 0.45);
        box-shadow: none;
    }

    .stButton > button[kind="primary"]:hover {
        color: var(--text);
        background: #243654;
        border-color: var(--accent);
    }

    .stButton > button:hover,
    .stDownloadButton > button:hover,
    .stLinkButton > a:hover {
        transform: translateY(-1px);
        border-color: rgba(255,255,255,0.16);
    }

    [data-testid="stExpander"] {
        background: rgba(17, 26, 43, 0.84);
        border: 1px solid var(--border);
        border-radius: 16px;
        overflow: hidden;
    }

    [data-testid="stExpander"] summary {
        font-weight: 700;
    }

    .blast-radius-box {
        background: rgba(255, 107, 122, 0.08);
        padding: 1rem;
        border-radius: 12px;
        border: 1px solid rgba(255, 107, 122, 0.18);
        margin: 0.5rem 0 1rem;
        font-size: 1rem;
        line-height: 1.65;
    }

    .attack-step {
        background: rgba(111, 140, 255, 0.08);
        padding: 0.85rem 1rem;
        border-radius: 12px;
        border: 1px solid rgba(111, 140, 255, 0.16);
        margin: 0.55rem 0;
        font-family: "SFMono-Regular", Consolas, monospace;
        font-size: 0.92rem;
        line-height: 1.55;
    }

    .env-chip {
        display: inline-block;
        background: rgba(111, 140, 255, 0.10);
        border: 1px solid rgba(111, 140, 255, 0.24);
        color: #b9c9ff;
        padding: 0.18rem 0.62rem;
        border-radius: 999px;
        font-family: "SFMono-Regular", Consolas, monospace;
        font-size: 0.85rem;
    }

    hr {
        border-color: var(--border) !important;
    }

    .stAlert {
        border-radius: 12px;
    }
</style>
""", unsafe_allow_html=True)


def normalize_severity(value):
    """Return a consistent lowercase severity label."""
    return str(value or "low").strip().lower()


# ---------- Session state ----------
if "findings" not in st.session_state:
    st.session_state.findings = []
if "analyses" not in st.session_state:
    st.session_state.analyses = []
if "attack_revealed" not in st.session_state:
    st.session_state.attack_revealed = {}
if "scan_ran" not in st.session_state:
    st.session_state.scan_ran = False
NAV_OPTIONS = ["Paste Code", "Upload Files"]
NAV_CAPTIONS = ["Scan a snippet directly", "Scan one or more local files"]
if "nav_page" not in st.session_state:
    st.session_state.nav_page = NAV_OPTIONS[0]


# ---------- Header ----------
st.markdown(
    """
    <div class="brand-lockup">
        <div class="brand-mark"><span class="lock-icon"></span></div>
        <div>
            <h1 class="main-header">SecretScope</h1>
            <p class="subtitle">Find leaked secrets before attackers do. Understand the damage. Fix it in one click.</p>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)
st.divider()


# ---------- Sidebar (primary navigation) ----------
with st.sidebar:
    st.markdown('<p class="sidebar-brand">SecretScope</p>', unsafe_allow_html=True)
    st.markdown('<p class="sidebar-tagline">Secret detection, triage &amp; auto-fix</p>', unsafe_allow_html=True)
    st.divider()

    st.markdown("#### Scan source")
    previous_nav_page = st.session_state.nav_page
    st.session_state.nav_page = st.radio(
        "Choose where to scan for secrets",
        NAV_OPTIONS,
        captions=NAV_CAPTIONS,
        key="nav_radio",
        index=NAV_OPTIONS.index(st.session_state.nav_page),
        label_visibility="collapsed",
    )
    if st.session_state.nav_page != previous_nav_page:
        st.session_state.findings = []
        st.session_state.analyses = []
        st.session_state.attack_revealed = {}
        st.session_state.scan_ran = False

    st.divider()
    with st.expander("About SecretScope"):
        st.markdown("""
Unlike other scanners, we:
- **Detect** hardcoded secrets
- **Explain** the blast radius
- **Auto-fix** with one click
- **Simulate** attacker behavior
        """)

    st.divider()
    st.caption("BWSI Cyber Hackathon 2026")


# ---------- Helper functions ----------
SEV_COLOR = {"critical": "red", "high": "orange", "medium": "yellow", "low": "blue"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}



def run_scan(findings):
    """Analyze redacted findings and store the results."""
    st.session_state.scan_ran = True

    try:
        if not findings:
            st.session_state.findings = []
            st.session_state.analyses = []
            st.session_state.attack_revealed = {}
            return

        with st.status("Analyzing findings...", expanded=True) as status:
            st.write(f"Analyzing {len(findings)} finding(s)...")
            analyses = analyze_findings_batch(findings)
            status.update(
                label=f"Found {len(findings)} finding(s)",
                state="complete",
            )

        st.session_state.findings = findings
        st.session_state.analyses = analyses
        st.session_state.attack_revealed = {}

    except Exception as error:
        st.error(f"Scan failed: {error}")
        st.exception(error)


def display_metrics(findings):
    critical = sum(
        1
        for finding in findings
        if normalize_severity(finding.get("severity")) == "critical"
    )
    high = sum(
        1
        for finding in findings
        if normalize_severity(finding.get("severity")) == "high"
    )
    medium = sum(
        1
        for finding in findings
        if normalize_severity(finding.get("severity")) == "medium"
    )
    low = sum(
        1
        for finding in findings
        if normalize_severity(finding.get("severity")) == "low"
    )

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Findings", len(findings))
    c2.metric("Critical", critical)
    c3.metric("High", high)
    c4.metric("Medium", medium)
    c5.metric("Low", low)


def display_findings(findings, analyses):
    if not findings:
        st.success("No secrets detected. Your code is clean.")
        return

    st.markdown(f"### Found {len(findings)} potential secret(s)")
    display_metrics(findings)
    st.divider()

    paired = sorted(
        zip(findings, analyses),
        key=lambda p: SEV_ORDER.get(normalize_severity(p[0].get("severity")), 99)
    )

    for idx, (finding, analysis) in enumerate(paired):
        # Skip AI-flagged false positives
        if not analysis.get("is_real", True) and analysis.get("confidence", 0) < 30:
            continue

        sev = normalize_severity(finding.get("severity"))
        with st.expander(
            f"{sev.upper()} | {finding['type']} | line {finding['line']} | {finding.get('file', 'input')}",
            expanded=(idx == 0),
        ):
            st.markdown("#### Blast radius")
            st.markdown(
                f'<div class="blast-radius-box">{analysis.get("blast_radius", "No analysis available.")}</div>',
                unsafe_allow_html=True
            )

            st.markdown("#### Recommended fix")
            render_diff(
                finding.get("context", ""),
                analysis.get("fixed_line", ""),
                finding.get("line", 0)
            )

            col1, col2 = st.columns([2, 1])
            with col1:
                st.markdown(
                    f'**Env variable:** <span class="env-chip">{analysis.get("env_var_name", "SECRET_KEY")}</span>',
                    unsafe_allow_html=True,
                )
            with col2:
                rot = analysis.get("rotation_url", "")
                if rot.startswith("http"):
                    st.link_button("Rotate this key", rot, type="tertiary")
                else:
                    st.caption(rot)

            st.divider()

            # Attack simulation button
            attack_key = f"attack_{idx}_{finding.get('line', 0)}"
            if st.button("View attack scenario", key=f"btn_{attack_key}"):
                st.session_state.attack_revealed[attack_key] = True

            if st.session_state.attack_revealed.get(attack_key):
                st.markdown("#### Example attack path")
                with st.spinner("Simulating attack..."):
                    steps = simulate_attack(finding, analysis)
                step_container = st.empty()
                revealed = []
                for step in steps:
                    revealed.append(step)
                    html = "".join(f'<div class="attack-step">{s}</div>' for s in revealed)
                    step_container.markdown(html, unsafe_allow_html=True)
                    time.sleep(0.6)


def display_download_options(findings, analyses):
    if not findings:
        return
    st.divider()
    st.markdown("### Export and remediate")
    c1, c2, c3 = st.columns(3)

    with c1:
        try:
            data = create_fix_bundle(findings, analyses)
            if data:
                st.download_button("Download fix bundle", data=data,
                    file_name="secretscope_fixes.zip", mime="application/zip", use_container_width=True)
            else:
                st.caption("Fix bundle: Person 4 building")
        except Exception:
            st.caption("Bundle unavailable")

    with c2:
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
                path = generate_report(
                    [{**f, **a} for f, a in zip(findings, analyses)],
                    output_path=tmp.name
                )
                if path:
                    with open(path, "rb") as pf:
                        st.download_button("Download PDF report", data=pf.read(),
                            file_name="secretscope_report.pdf", mime="application/pdf", use_container_width=True)
                else:
                    st.caption("PDF: Person 4 building")
        except Exception:
            st.caption("PDF unavailable")

    with c3:
        if st.button("Start new scan", use_container_width=True):
            st.session_state.findings = []
            st.session_state.analyses = []
            st.session_state.attack_revealed = {}
            st.session_state.scan_ran = False
            st.rerun()


# ---------- Main panel (driven by sidebar navigation) ----------
page = st.session_state.nav_page

with st.container(border=True):
    if page == "Paste Code":
        st.markdown("### Paste code to scan")

        if st.button("Load sample code"):
            st.session_state.paste_input = SAMPLE_VULNERABLE_CODE
            st.rerun()

        code = st.text_area(
            "Your code:", height=350, key="paste_input",
            help="Paste a file's contents to check for hardcoded secrets.",
        )

        if st.button("Scan for secrets", type="primary", key="scan_paste"):
            if code.strip():
                run_scan(scan_for_ai(code, filename="pasted_input.py"))
            else:
                st.warning("Please paste some code first.")

    elif page == "Upload Files":
        st.markdown("### Upload files to scan")
        uploaded = st.file_uploader(
            "Choose files", accept_multiple_files=True,
            type=["py", "js", "ts", "env", "yml", "yaml", "json", "txt", "md", "sh", "rb", "go", "java", "conf", "ini", "cfg"],
            help="Accepted: py, js, ts, env, yml, yaml, json, txt, md, sh, rb, go, java, conf, ini, cfg",
        )
        if uploaded and st.button("Scan uploaded files", type="primary", key="scan_upload"):
            all_findings = []
            for f in uploaded:
                try:
                    text = decode_text_bytes(f.getvalue())
                except ValueError as e:
                    st.warning(f"Skipped {f.name}: {e}")
                    continue
                all_findings.extend(scan_for_ai(text, filename=f.name))
            run_scan(all_findings)



# ---------- Results ----------
if st.session_state.scan_ran:
    st.divider()
    st.markdown("## Scan Results")
    display_findings(st.session_state.findings, st.session_state.analyses)
    display_download_options(st.session_state.findings, st.session_state.analyses)