"""
SecretScope — Streamlit frontend
Run with: streamlit run app.py
"""

import streamlit as st
import time
import os
import tempfile

# Team imports
from ai_layer import analyze_findings_batch, simulate_attack

# Detector — real if available, mock otherwise
try:
    from detector import scan_text, scan_files, scan_github_repo
except ImportError:
    def scan_text(code, filename="input"):
        return [
            {"type": "AWS Access Key", "service": "aws", "severity": "critical",
             "line": 8, "match": "AWS_KEY_PLACEHOLDER_NOT_REAL_1234567890",
             "context": 'AWS_ACCESS_KEY = "AWS_KEY_PLACEHOLDER_NOT_REAL_1234567890"',
             "file": filename},
            {"type": "OpenAI API Key", "service": "openai", "severity": "critical",
             "line": 12, "match": "OPENAI_KEY_PLACEHOLDER_NOT_REAL_abcdefg",
             "context": 'openai.api_key = "OPENAI_KEY_PLACEHOLDER_NOT_REAL_abcdefg"',
             "file": filename},
            {"type": "Stripe Secret Key", "service": "stripe", "severity": "critical",
             "line": 15, "match": "STRIPE_KEY_PLACEHOLDER_NOT_REAL_9876543210",
             "context": 'stripe.api_key = "STRIPE_KEY_PLACEHOLDER_NOT_REAL_9876543210"',
             "file": filename},
            {"type": "GitHub Token", "service": "github", "severity": "high",
             "line": 18, "match": "GITHUB_TOKEN_PLACEHOLDER_NOT_REAL_xyz123",
             "context": 'GH_TOKEN = "GITHUB_TOKEN_PLACEHOLDER_NOT_REAL_xyz123"',
             "file": filename},
        ]
    def scan_files(paths):
        return scan_text("mock", paths[0] if paths else "mock_file.py")
    def scan_github_repo(url):
        return scan_text("mock", "mock_repo/config.py")

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
    .main-header {
        font-size: 3rem;
        font-weight: 800;
        background: linear-gradient(90deg, #ff4b4b 0%, #ff9500 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0;
    }
    .subtitle {
        font-size: 1.2rem;
        color: #888;
        margin-top: 0;
    }
    .blast-radius-box {
        background: #2a1e1e;
        padding: 1rem;
        border-radius: 6px;
        border-left: 3px solid #ff4b4b;
        margin: 0.5rem 0;
        font-size: 1.05rem;
    }
    .attack-step {
        background: #1e1e2e;
        padding: 0.8rem 1rem;
        border-radius: 6px;
        border-left: 3px solid #ff9500;
        margin: 0.5rem 0;
        font-family: 'SF Mono', 'Monaco', monospace;
        font-size: 0.95rem;
    }
    .stButton>button {
        border-radius: 6px;
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
if "demo_code" not in st.session_state:
    st.session_state.demo_code = ""


# ---------- Header ----------
st.markdown('<h1 class="main-header">🔒 SecretScope</h1>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">Find leaked secrets before attackers do. Understand the damage. Fix it in one click.</p>', unsafe_allow_html=True)
st.divider()


# ---------- Sidebar ----------
with st.sidebar:
    st.markdown("### 🛡️ About SecretScope")
    st.markdown("""
Unlike other scanners, we:
- 🎯 **Detect** hardcoded secrets
- 💥 **Explain** the blast radius
- 🔧 **Auto-fix** with one click
- 🎬 **Simulate** attacker behavior
    """)
    st.divider()
    st.markdown("### 📊 Scan Stats")
    if st.session_state.findings:
        f = st.session_state.findings
        st.metric("🔴 Critical", sum(1 for x in f if x.get("severity") == "critical"))
        st.metric("🟠 High", sum(1 for x in f if x.get("severity") == "high"))
        st.metric("🟡 Medium", sum(1 for x in f if x.get("severity") == "medium"))
    else:
        st.info("No scan run yet.")
    st.divider()
    st.caption("BWSI Cyber Hackathon 2026")


# ---------- Helper functions ----------
SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def run_scan(scan_fn, *args, **kwargs):
    with st.spinner("🔍 Scanning for secrets..."):
        findings = scan_fn(*args, **kwargs)
    if not findings:
        st.session_state.findings = []
        st.session_state.analyses = []
        return
    with st.spinner(f"🧠 AI analyzing {len(findings)} finding(s)..."):
        analyses = analyze_findings_batch(findings)
    st.session_state.findings = findings
    st.session_state.analyses = analyses
    st.session_state.attack_revealed = {}


def display_metrics(findings):
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Findings", len(findings))
    c2.metric("🔴 Critical", critical)
    c3.metric("🟠 High", high)
    c4.metric("🟡 Medium", medium)


def display_findings(findings, analyses):
    if not findings:
        st.success("✅ No secrets detected! Your code is clean.")
        st.balloons()
        return
    
    st.markdown(f"### ⚠️ Found {len(findings)} potential secret(s)")
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
        emoji = SEV_EMOJI.get(sev, "⚪")
        
        with st.expander(
            f"{emoji} **{sev.upper()}**: {finding['type']} on line {finding['line']} · {finding.get('file', 'input')}",
            expanded=(idx == 0)
        ):
            st.markdown("#### 💥 What could go wrong")
            st.markdown(
                f'<div class="blast-radius-box">{analysis.get("blast_radius", "No analysis available.")}</div>',
                unsafe_allow_html=True
            )
            
            st.markdown("#### 🔧 The fix")
            render_diff(
                finding.get("context", ""),
                analysis.get("fixed_line", ""),
                finding.get("line", 0)
            )
            
            col1, col2 = st.columns([2, 1])
            with col1:
                st.markdown(f"**Env variable:** `{analysis.get('env_var_name', 'SECRET_KEY')}`")
            with col2:
                rot = analysis.get("rotation_url", "")
                if rot.startswith("http"):
                    st.markdown(f"[🔗 Rotate this key]({rot})")
                else:
                    st.caption(rot)
            
            st.divider()
            
            # Attack simulation button
            attack_key = f"attack_{idx}_{finding.get('line', 0)}"
            if st.button("🎬 See attack scenario", key=f"btn_{attack_key}"):
                st.session_state.attack_revealed[attack_key] = True
            
            if st.session_state.attack_revealed.get(attack_key):
                st.markdown("#### 🎭 How an attacker would exploit this")
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
    st.markdown("### 📦 Take action")
    c1, c2, c3 = st.columns(3)
    
    with c1:
        try:
            data = create_fix_bundle(findings, analyses)
            if data:
                st.download_button("⬇️ Fix bundle (.zip)", data=data,
                    file_name="secretscope_fixes.zip", mime="application/zip",
                    use_container_width=True)
            else:
                st.caption("Fix bundle: Person 4 building")
        except Exception as e:
            st.caption(f"Bundle unavailable")
    
    with c2:
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
                path = generate_report(
                    [{**f, **a} for f, a in zip(findings, analyses)],
                    output_path=tmp.name
                )
                if path:
                    with open(path, "rb") as pf:
                        st.download_button("📄 PDF report", data=pf.read(),
                            file_name="secretscope_report.pdf", mime="application/pdf",
                            use_container_width=True)
                else:
                    st.caption("PDF: Person 4 building")
        except Exception:
            st.caption("PDF unavailable")
    
    with c3:
        if st.button("🔄 New scan", use_container_width=True):
            st.session_state.findings = []
            st.session_state.analyses = []
            st.session_state.attack_revealed = {}
            st.rerun()


# ---------- Tabs ----------
tab1, tab2, tab3 = st.tabs(["📝 Paste Code", "📁 Upload Files", "🔗 GitHub Repo"])

with tab1:
    st.markdown("### Paste code to scan")
    
    if st.button("✨ Load sample vulnerable code (for demo)"):
        st.session_state.demo_code = SAMPLE_VULNERABLE_CODE
        st.rerun()
    
    code = st.text_area("Your code:", value=st.session_state.demo_code, height=350, key="paste_input")
    
    if st.button("🔍 Scan for Secrets", type="primary", key="scan_paste"):
        if code.strip():
            run_scan(scan_text, code, filename="pasted_input")
        else:
            st.warning("Please paste some code first.")

with tab2:
    st.markdown("### Upload files to scan")
    uploaded = st.file_uploader(
        "Choose files", accept_multiple_files=True,
        type=["py", "js", "ts", "env", "yml", "yaml", "json", "txt", "md", "sh", "rb", "go", "java", "conf", "ini", "cfg"],
    )
    if uploaded and st.button("🔍 Scan uploaded files", type="primary", key="scan_upload"):
        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for f in uploaded:
                p = os.path.join(tmp, f.name)
                with open(p, "wb") as out:
                    out.write(f.getbuffer())
                paths.append(p)
            run_scan(scan_files, paths)

with tab3:
    st.markdown("### Scan a public GitHub repository")
    repo_url = st.text_input("GitHub URL:", placeholder="https://github.com/username/repository")
    if st.button("🔍 Scan repository", type="primary", key="scan_repo"):
        if repo_url.strip():
            try:
                run_scan(scan_github_repo, repo_url.strip())
            except Exception as e:
                st.error(f"Failed to scan repo: {e}")


# ---------- Results ----------
if st.session_state.findings:
    st.divider()
    st.markdown("## 🎯 Scan Results")
    display_findings(st.session_state.findings, st.session_state.analyses)
    display_download_options(st.session_state.findings, st.session_state.analyses)