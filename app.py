"""
SecretScope — Streamlit frontend
Run with: streamlit run app.py
"""

import streamlit as st
import time
import tempfile

# Team imports
from ai_layer import analyze_findings_batch, simulate_attack

# Detector — real if available, mock otherwise.
# scan_for_ai() is the safe entrypoint: it redacts the actual secret value
# out of both `match` and `context` before findings ever reach the AI layer.
try:
    from detector import scan_for_ai, decode_text_bytes
except ImportError:
    def scan_for_ai(code, filename="input"):
        return [
            {"type": "AWS Access Key", "service": "aws", "severity": "critical",
             "line": 8, "match": "AKIA••••••••••••7890",
             "context": 'AWS_ACCESS_KEY = "[REDACTED]"',
             "file": filename},
            {"type": "OpenAI API Key", "service": "openai", "severity": "critical",
             "line": 12, "match": "sk-•••••••••••••••••••defg",
             "context": 'openai.api_key = "[REDACTED]"',
             "file": filename},
            {"type": "Stripe Secret Key", "service": "stripe", "severity": "critical",
             "line": 15, "match": "sk_live_••••••••••••3210",
             "context": 'stripe.api_key = "[REDACTED]"',
             "file": filename},
            {"type": "GitHub Token", "service": "github", "severity": "high",
             "line": 18, "match": "ghp_••••••••••••xyz123",
             "context": 'GH_TOKEN = "[REDACTED]"',
             "file": filename},
        ]
    def decode_text_bytes(data):
        return data.decode("utf-8", errors="replace")

# Real GitHub repository scanning isn't implemented yet (git_scanner.py is
# an empty stub) — this always returns safe, synthetic demo findings so the
# tab has something to show without pretending to have cloned a real repo.
def scan_github_repo(url):
    return scan_for_ai("mock", "mock_repo/config.py")

# Person 4's modules — graceful fallback if not ready
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
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------- Custom CSS ----------
st.markdown("""
<style>
    :root {
        --primary: #2F6FED;
        --primary-hover: #1E54D6;
        --primary-soft: rgba(47, 111, 237, 0.12);
        --primary-border: rgba(47, 111, 237, 0.35);
        --text-muted: #8A93A6;
        --danger: #EF4444;
        --danger-soft: rgba(239, 68, 68, 0.10);
    }

    .kicker {
        text-transform: uppercase;
        letter-spacing: 0.14em;
        font-size: 0.75rem;
        font-weight: 700;
        color: var(--primary);
        margin: 0 0 0.4rem 0;
    }
    .main-header {
        font-size: 2.75rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        background: linear-gradient(90deg, #7FA8F5 0%, var(--primary) 55%, #14338F 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0;
    }
    .subtitle {
        font-size: 1.1rem;
        color: var(--text-muted);
        margin-top: 0.3rem;
    }
    .blast-radius-box {
        background: var(--danger-soft);
        color: #F5D5D5;
        padding: 1rem;
        border-radius: 8px;
        border-left: 3px solid var(--danger);
        margin: 0.5rem 0;
        font-size: 1.05rem;
    }
    .attack-step {
        background: var(--primary-soft);
        color: #CFE0FF;
        padding: 0.8rem 1rem;
        border-radius: 8px;
        border-left: 3px solid var(--primary);
        margin: 0.5rem 0;
        font-family: 'SF Mono', 'Monaco', monospace;
        font-size: 0.95rem;
    }
    .env-chip {
        display: inline-block;
        background: var(--primary-soft);
        border: 1px solid var(--primary-border);
        color: #9DBBFF;
        padding: 0.15rem 0.6rem;
        border-radius: 999px;
        font-family: 'SF Mono', 'Monaco', monospace;
        font-size: 0.85rem;
    }

    /* ---- Buttons ---- */
    .stButton>button,
    .stDownloadButton>button,
    .stLinkButton>a {
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.15s ease;
    }
    .stButton>button:hover,
    .stDownloadButton>button:hover,
    .stLinkButton>a:hover {
        border-color: var(--primary);
        color: var(--primary);
        transform: translateY(-1px);
    }

    /* ---- Accessibility: visible focus rings everywhere ---- */
    button:focus-visible,
    a:focus-visible,
    input:focus-visible,
    textarea:focus-visible,
    [role="radio"]:focus-visible,
    label:has(input:focus-visible) {
        outline: 2px solid var(--primary) !important;
        outline-offset: 2px;
    }

    /* ---- Sidebar branding ---- */
    section[data-testid="stSidebar"] {
        border-right: 1px solid var(--primary-border);
    }
    .sidebar-brand {
        font-size: 1.3rem;
        font-weight: 800;
        letter-spacing: -0.01em;
        color: #EAF0FF;
        margin-bottom: 0;
    }
    .sidebar-tagline {
        font-size: 0.85rem;
        color: var(--text-muted);
        margin-top: 0;
    }

    /* ---- Sidebar nav (radio styled as nav list) ---- */
    section[data-testid="stSidebar"] div[role="radiogroup"] {
        gap: 0.15rem;
    }
    section[data-testid="stSidebar"] div[role="radiogroup"] > label {
        display: flex;
        align-items: center;
        width: 100%;
        padding: 0.55rem 0.75rem;
        border-radius: 8px;
        margin-bottom: 0.15rem;
        border-left: 3px solid transparent;
        cursor: pointer;
        transition: background 0.15s ease, border-color 0.15s ease;
    }
    section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {
        background: var(--primary-soft);
    }
    section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) {
        background: var(--primary-soft);
        border-left: 3px solid var(--primary);
    }

    /* ---- Cards for scan panels & result groups ---- */
    div[data-testid="stVerticalBlockBorderWrapper"] {
        border-radius: 12px !important;
    }

    /* ---- Metric styling ---- */
    div[data-testid="stMetric"] {
        background: var(--primary-soft);
        border: 1px solid var(--primary-border);
        border-radius: 8px;
        padding: 0.6rem 0.8rem;
    }

    /* ---- Expander polish ---- */
    div[data-testid="stExpander"] summary {
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)


# ---------- Session state ----------
if "findings" not in st.session_state:
    st.session_state.findings = []
if "analyses" not in st.session_state:
    st.session_state.analyses = []
if "attack_revealed" not in st.session_state:
    st.session_state.attack_revealed = {}
if "scan_ran" not in st.session_state:
    st.session_state.scan_ran = False
NAV_OPTIONS = ["Paste Code", "Upload Files", "GitHub Repo"]
NAV_CAPTIONS = ["Scan a snippet directly", "Scan one or more local files", "Scan a public repository"]
if "nav_page" not in st.session_state:
    st.session_state.nav_page = NAV_OPTIONS[0]


# ---------- Header ----------
st.markdown('<p class="kicker">Secret Detection &amp; Auto-Remediation</p>', unsafe_allow_html=True)
st.markdown('<h1 class="main-header">SecretScope</h1>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">Find leaked secrets before attackers do. Understand the damage. Fix it in one click.</p>', unsafe_allow_html=True)
st.divider()


# ---------- Sidebar (primary navigation) ----------
with st.sidebar:
    st.markdown('<p class="sidebar-brand">SecretScope</p>', unsafe_allow_html=True)
    st.markdown('<p class="sidebar-tagline">Secret detection, triage &amp; auto-fix</p>', unsafe_allow_html=True)
    st.divider()

    st.markdown("#### Scan source")
    st.session_state.nav_page = st.radio(
        "Choose where to scan for secrets",
        NAV_OPTIONS,
        captions=NAV_CAPTIONS,
        key="nav_radio",
        index=NAV_OPTIONS.index(st.session_state.nav_page),
        label_visibility="collapsed",
    )

    st.divider()
    st.markdown("#### Scan stats")
    if st.session_state.findings:
        f = st.session_state.findings
        s1, s2 = st.columns(2)
        s1.metric("Critical", sum(1 for x in f if x.get("severity") == "critical"))
        s2.metric("High", sum(1 for x in f if x.get("severity") == "high"))
        s3, s4 = st.columns(2)
        s3.metric("Medium", sum(1 for x in f if x.get("severity") == "medium"))
        s4.metric("Total", len(f))
    else:
        st.info("No scan run yet.")

    st.divider()
    with st.expander("About SecretScope", icon=":material/info:"):
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
    """Analyze already-detected findings with AI and store the results.

    `findings` must already be in the redacted `scan_for_ai()` shape — no
    raw secret values should reach this point.
    """
    st.session_state.scan_ran = True
    if not findings:
        st.session_state.findings = []
        st.session_state.analyses = []
        st.session_state.attack_revealed = {}
        return
    with st.status("Analyzing findings...", expanded=True) as status:
        st.write(f"Analyzing {len(findings)} finding(s)...")
        analyses = analyze_findings_batch(findings)
        status.update(label=f"Found {len(findings)} finding(s)", state="complete")
    st.session_state.findings = findings
    st.session_state.analyses = analyses
    st.session_state.attack_revealed = {}


def display_metrics(findings):
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Findings", len(findings))
    c2.metric("Critical", critical)
    c3.metric("High", high)
    c4.metric("Medium", medium)


def display_findings(findings, analyses):
    if not findings:
        st.success("No secrets detected. Your code is clean.")
        return

    st.markdown(f"### Found {len(findings)} potential secret(s)")
    display_metrics(findings)
    st.divider()

    paired = sorted(
        zip(findings, analyses),
        key=lambda p: SEV_ORDER.get(p[0].get("severity", "low"), 99)
    )

    for idx, (finding, analysis) in enumerate(paired):
        # Skip AI-flagged false positives
        if not analysis.get("is_real", True) and analysis.get("confidence", 0) < 30:
            continue

        sev = finding.get("severity", "low")
        color = SEV_COLOR.get(sev, "gray")

        with st.expander(
            f":{color}-badge[{sev.upper()}] {finding['type']} · line {finding['line']} · {finding.get('file', 'input')}",
            expanded=(idx == 0),
            icon=":material/key:",
        ):
            st.markdown("#### Blast radius")
            st.markdown(
                f'<div class="blast-radius-box">{analysis.get("blast_radius", "No analysis available.")}</div>',
                unsafe_allow_html=True
            )

            st.markdown("#### Suggested fix")
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
                    st.link_button("Rotate this key", rot, icon=":material/sync:", type="tertiary")
                else:
                    st.caption(rot)

            st.divider()

            # Attack simulation button
            attack_key = f"attack_{idx}_{finding.get('line', 0)}"
            if st.button("See attack scenario", key=f"btn_{attack_key}", icon=":material/bug_report:"):
                st.session_state.attack_revealed[attack_key] = True

            if st.session_state.attack_revealed.get(attack_key):
                st.markdown("#### Attack walkthrough")
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
    st.markdown("### Take action")
    c1, c2, c3 = st.columns(3)

    with c1:
        try:
            data = create_fix_bundle(findings, analyses)
            if data:
                st.download_button("Fix bundle (.zip)", data=data,
                    file_name="secretscope_fixes.zip", mime="application/zip",
                    icon=":material/download:", use_container_width=True)
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
                        st.download_button("PDF report", data=pf.read(),
                            file_name="secretscope_report.pdf", mime="application/pdf",
                            icon=":material/picture_as_pdf:", use_container_width=True)
                else:
                    st.caption("PDF: Person 4 building")
        except Exception:
            st.caption("PDF unavailable")

    with c3:
        if st.button("New scan", icon=":material/refresh:", use_container_width=True):
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

        if st.button("Load sample vulnerable code (for demo)", icon=":material/auto_awesome:"):
            st.session_state.paste_input = SAMPLE_VULNERABLE_CODE
            st.rerun()

        code = st.text_area(
            "Your code:", height=350, key="paste_input",
            help="Paste a file's contents to check for hardcoded secrets.",
        )

        if st.button("Scan for Secrets", type="primary", key="scan_paste", icon=":material/search:"):
            if code.strip():
                run_scan(scan_for_ai(code, filename="pasted_input"))
            else:
                st.warning("Please paste some code first.")

    elif page == "Upload Files":
        st.markdown("### Upload files to scan")
        uploaded = st.file_uploader(
            "Choose files", accept_multiple_files=True,
            type=["py", "js", "ts", "env", "yml", "yaml", "json", "txt", "md", "sh", "rb", "go", "java", "conf", "ini", "cfg"],
            help="Accepted: py, js, ts, env, yml, yaml, json, txt, md, sh, rb, go, java, conf, ini, cfg",
        )
        if uploaded and st.button("Scan uploaded files", type="primary", key="scan_upload", icon=":material/search:"):
            all_findings = []
            for f in uploaded:
                try:
                    text = decode_text_bytes(f.getvalue())
                except ValueError as e:
                    st.warning(f"Skipped {f.name}: {e}")
                    continue
                all_findings.extend(scan_for_ai(text, filename=f.name))
            run_scan(all_findings)

    elif page == "GitHub Repo":
        st.markdown("### Scan a public GitHub repository")
        st.caption("Demo mode — real repository cloning isn't wired up yet, so this scans safe synthetic data.")
        repo_url = st.text_input(
            "GitHub URL:", placeholder="https://github.com/username/repository",
            help="Paste the full URL of a public GitHub repository.",
        )
        if st.button("Scan repository", type="primary", key="scan_repo", icon=":material/search:"):
            if repo_url.strip():
                try:
                    run_scan(scan_github_repo(repo_url.strip()))
                except Exception as e:
                    st.error(f"Failed to scan repo: {e}")


# ---------- Results ----------
if st.session_state.scan_ran:
    st.divider()
    st.markdown("## Scan Results")
    display_findings(st.session_state.findings, st.session_state.analyses)
    display_download_options(st.session_state.findings, st.session_state.analyses)