"""
report.py — SecretScope PDF Report Generator

Generates a professional PDF security report from scan findings + AI analyses.
Called by the frontend when the user clicks "Download PDF report".

Usage:
    from report import generate_report
    path = generate_report(merged_findings, output_path="report.pdf")
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from datetime import datetime
import html


# ---------- Colors ----------
COLOR_CRITICAL = colors.HexColor("#ff4b4b")
COLOR_HIGH = colors.HexColor("#ff9500")
COLOR_MEDIUM = colors.HexColor("#ffd700")
COLOR_LOW = colors.HexColor("#4b9eff")
COLOR_HEADER_BG = colors.HexColor("#1a1a2e")
COLOR_TEXT_MUTED = colors.HexColor("#666666")
COLOR_CODE_BG = colors.HexColor("#f5f5f5")

SEVERITY_COLORS = {
    "critical": COLOR_CRITICAL,
    "high": COLOR_HIGH,
    "medium": COLOR_MEDIUM,
    "low": COLOR_LOW,
}


# ---------- Custom styles ----------
def _build_styles():
    styles = getSampleStyleSheet()
    
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontSize=28,
        textColor=COLOR_HEADER_BG,
        spaceAfter=6,
        alignment=TA_LEFT,
    ))
    
    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        parent=styles["Normal"],
        fontSize=12,
        textColor=COLOR_TEXT_MUTED,
        spaceAfter=20,
    ))
    
    styles.add(ParagraphStyle(
        name="SectionHeader",
        parent=styles["Heading2"],
        fontSize=16,
        textColor=COLOR_HEADER_BG,
        spaceBefore=16,
        spaceAfter=10,
    ))
    
    styles.add(ParagraphStyle(
        name="FindingTitle",
        parent=styles["Heading3"],
        fontSize=14,
        spaceBefore=12,
        spaceAfter=6,
    ))
    
    styles.add(ParagraphStyle(
        name="RiskBox",
        parent=styles["Normal"],
        fontSize=11,
        leading=15,
        leftIndent=10,
        rightIndent=10,
        spaceAfter=10,
        backColor=colors.HexColor("#fff5f5"),
        borderColor=COLOR_CRITICAL,
        borderWidth=1,
        borderPadding=8,
    ))
    
    styles.add(ParagraphStyle(
        name="CodeBlock",
        parent=styles["Code"],
        fontSize=9,
        leading=12,
        leftIndent=10,
        rightIndent=10,
        backColor=COLOR_CODE_BG,
        borderColor=colors.HexColor("#dddddd"),
        borderWidth=1,
        borderPadding=6,
        spaceAfter=8,
    ))
    
    styles.add(ParagraphStyle(
        name="Meta",
        parent=styles["Normal"],
        fontSize=9,
        textColor=COLOR_TEXT_MUTED,
        spaceAfter=4,
    ))
    
    return styles


# ---------- Helpers ----------
def _safe(text):
    """Escape HTML in text for ReportLab paragraphs."""
    if text is None:
        return ""
    return html.escape(str(text)).replace("\n", "<br/>")


def _severity_badge(severity):
    """Colored severity label in HTML for paragraph."""
    color = SEVERITY_COLORS.get(severity, colors.grey)
    return f'<font color="{color.hexval()}"><b>{severity.upper()}</b></font>'


def _summary_table(findings):
    """Build the top-of-report summary table."""
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    low = sum(1 for f in findings if f.get("severity") == "low")
    total = len(findings)
    
    data = [
        ["Severity", "Count"],
        ["🔴 Critical", str(critical)],
        ["🟠 High", str(high)],
        ["🟡 Medium", str(medium)],
        ["🔵 Low", str(low)],
        ["Total", str(total)],
    ]
    
    table = Table(data, colWidths=[3 * inch, 1.5 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 11),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#fff0f0")),
        ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#fff8ee")),
        ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#fffdee")),
        ("BACKGROUND", (0, 4), (-1, 4), colors.HexColor("#eef4ff")),
        ("BACKGROUND", (0, 5), (-1, 5), COLOR_HEADER_BG),
        ("TEXTCOLOR", (0, 5), (-1, 5), colors.white),
        ("FONTNAME", (0, 5), (-1, 5), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return table


# ---------- Main entry point ----------
def generate_report(findings, output_path="report.pdf"):
    """
    Generate a PDF report from scan findings.
    
    Args:
        findings: list of dicts. Each dict should have finding fields merged with
                  analysis fields: type, severity, line, file, context, blast_radius,
                  fixed_line, env_var_name, rotation_url.
        output_path: where to save the PDF.
    
    Returns:
        The output_path on success, None on failure.
    """
    try:
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            leftMargin=0.75 * inch,
            rightMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )
        
        styles = _build_styles()
        story = []
        
        # ---------- Cover / header ----------
        story.append(Paragraph("🔒 SecretScope Security Report", styles["ReportTitle"]))
        story.append(Paragraph(
            f"Generated {datetime.now().strftime('%B %d, %Y at %I:%M %p')}",
            styles["ReportSubtitle"]
        ))
        
        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings_sorted = sorted(
            findings,
            key=lambda f: sev_order.get(f.get("severity", "low"), 99)
        )
        
        # ---------- Executive summary ----------
        story.append(Paragraph("Executive Summary", styles["SectionHeader"]))
        
        critical_count = sum(1 for f in findings if f.get("severity") == "critical")
        total = len(findings)
        
        if critical_count > 0:
            summary_text = (
                f"This scan identified <b>{total} potential secret{'s' if total != 1 else ''}</b> "
                f"in your codebase, including <b><font color='{COLOR_CRITICAL.hexval()}'>"
                f"{critical_count} critical finding{'s' if critical_count != 1 else ''}</font></b> "
                f"that require immediate action. Critical findings represent credentials that, "
                f"if exposed, could lead to significant financial loss, data breach, or "
                f"unauthorized access to production systems."
            )
        elif total > 0:
            summary_text = (
                f"This scan identified <b>{total} potential secret{'s' if total != 1 else ''}</b>. "
                f"While no critical findings were detected, we recommend reviewing and "
                f"remediating all identified issues to reduce security risk."
            )
        else:
            summary_text = (
                "No hardcoded secrets were detected in the scanned code. "
                "Continue following secure coding practices."
            )
        
        story.append(Paragraph(summary_text, styles["Normal"]))
        story.append(Spacer(1, 12))
        
        # ---------- Summary table ----------
        if findings:
            story.append(_summary_table(findings))
            story.append(Spacer(1, 20))
        
        # ---------- Recommendations ----------
        story.append(Paragraph("Immediate Actions Required", styles["SectionHeader"]))
        actions = (
            "<b>1. Rotate exposed credentials immediately.</b> Any credential identified in this "
            "report should be considered compromised and rotated at the corresponding service.<br/><br/>"
            "<b>2. Remove hardcoded secrets from source code.</b> Replace with environment variables "
            "or a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.).<br/><br/>"
            "<b>3. Audit version control history.</b> If any secrets were committed to a repository, "
            "they may exist in git history even after removal. Use tools like git-filter-repo to "
            "purge them.<br/><br/>"
            "<b>4. Enable pre-commit hooks.</b> Install SecretScope or similar tools to prevent "
            "future accidental commits of secrets."
        )
        story.append(Paragraph(actions, styles["Normal"]))
        
        # ---------- Detailed findings ----------
        if findings_sorted:
            story.append(PageBreak())
            story.append(Paragraph("Detailed Findings", styles["SectionHeader"]))
            story.append(Paragraph(
                "The following findings are sorted by severity, with the most critical issues first.",
                styles["Normal"]
            ))
            story.append(Spacer(1, 12))
            
            for i, finding in enumerate(findings_sorted, 1):
                severity = finding.get("severity", "low")
                
                # Group each finding together so it doesn't split awkwardly across pages
                finding_block = []
                
                # Finding header
                finding_block.append(Paragraph(
                    f"Finding #{i}: {_severity_badge(severity)} — {_safe(finding.get('type', 'Unknown'))}",
                    styles["FindingTitle"]
                ))
                
                # Metadata
                meta = (
                    f"<b>File:</b> {_safe(finding.get('file', 'unknown'))} · "
                    f"<b>Line:</b> {finding.get('line', '?')} · "
                    f"<b>Service:</b> {_safe(finding.get('service', 'unknown'))}"
                )
                finding_block.append(Paragraph(meta, styles["Meta"]))
                finding_block.append(Spacer(1, 6))
                
                # Risk / blast radius
                blast = finding.get("blast_radius", "Analysis unavailable.")
                finding_block.append(Paragraph(
                    f"<b>Risk Analysis:</b><br/>{_safe(blast)}",
                    styles["RiskBox"]
                ))
                
                # Vulnerable code
                context = finding.get("context", "")
                if context:
                    finding_block.append(Paragraph(
                        "<b>Vulnerable code:</b>",
                        styles["Normal"]
                    ))
                    finding_block.append(Paragraph(
                        _safe(context),
                        styles["CodeBlock"]
                    ))
                
                # Recommended fix
                fixed = finding.get("fixed_line", "")
                if fixed:
                    finding_block.append(Paragraph(
                        "<b>Recommended fix:</b>",
                        styles["Normal"]
                    ))
                    finding_block.append(Paragraph(
                        _safe(fixed),
                        styles["CodeBlock"]
                    ))
                
                # Env var + rotation
                env_var = finding.get("env_var_name", "SECRET_KEY")
                rotation = finding.get("rotation_url", "")
                
                action_text = f"<b>Environment variable:</b> <font face='Courier'>{_safe(env_var)}</font>"
                if rotation:
                    action_text += f"<br/><b>Rotate at:</b> {_safe(rotation)}"
                finding_block.append(Paragraph(action_text, styles["Normal"]))
                
                finding_block.append(Spacer(1, 16))
                
                # Keep each finding block together on one page if possible
                try:
                    story.append(KeepTogether(finding_block))
                except Exception:
                    story.extend(finding_block)
        
        # ---------- Footer / disclaimer ----------
        story.append(PageBreak())
        story.append(Paragraph("About This Report", styles["SectionHeader"]))
        story.append(Paragraph(
            "This report was generated by <b>SecretScope</b>, a defensive security tool built "
            "for the MIT BWSI Cyber Operations Hackathon 2026. SecretScope combines pattern-based "
            "detection with AI-powered risk analysis to help developers identify and remediate "
            "hardcoded secrets before they can be exploited.<br/><br/>"
            "This report is provided for informational purposes only. Findings should be reviewed "
            "by a qualified security professional. False positives are possible; false negatives "
            "are also possible — this tool is one layer of defense, not a complete security audit.",
            styles["Normal"]
        ))
        
        # ---------- Build ----------
        doc.build(story)
        return output_path
    
    except Exception as e:
        print(f"[report] generate_report failed: {e}")
        import traceback
        traceback.print_exc()
        return None


# ---------- CLI test harness ----------
if __name__ == "__main__":
    # Sample data — matches the shape frontend passes in
    test_findings = [
        {
            "type": "AWS Access Key",
            "service": "aws",
            "severity": "critical",
            "line": 12,
            "file": "config.py",
            "context": 'AWS_ACCESS_KEY = "AKIAFAKEKEY1234567890"',
            "blast_radius": "An attacker with this AWS key can spin up EC2 instances for cryptocurrency mining (typically $20,000+ in charges within hours), read/delete data from S3 buckets, and pivot to other AWS services.",
            "fixed_line": 'AWS_ACCESS_KEY = os.environ["AWS_ACCESS_KEY_ID"]',
            "env_var_name": "AWS_ACCESS_KEY_ID",
            "rotation_url": "https://console.aws.amazon.com/iam/home#/security_credentials",
        },
        {
            "type": "OpenAI API Key",
            "service": "openai",
            "severity": "critical",
            "line": 18,
            "file": "config.py",
            "context": 'openai.api_key = "sk-FAKE-not-real"',
            "blast_radius": "A leaked OpenAI API key lets attackers rack up thousands of dollars in API charges by running GPT-4 queries on your account. Public GitHub scanners routinely detect and abuse these within minutes.",
            "fixed_line": 'openai.api_key = os.environ["OPENAI_API_KEY"]',
            "env_var_name": "OPENAI_API_KEY",
            "rotation_url": "https://platform.openai.com/api-keys",
        },
        {
            "type": "GitHub Token",
            "service": "github",
            "severity": "high",
            "line": 31,
            "file": "config.py",
            "context": 'GH_TOKEN = "ghp_fake_token_here"',
            "blast_radius": "A leaked GitHub PAT grants an attacker access to every repository the token owner can see, including private repos and any secrets committed to them.",
            "fixed_line": 'GH_TOKEN = os.environ["GITHUB_TOKEN"]',
            "env_var_name": "GITHUB_TOKEN",
            "rotation_url": "https://github.com/settings/tokens",
        },
    ]
    
    path = generate_report(test_findings, output_path="test_report.pdf")
    if path:
        print(f"✓ Report generated: {path}")
        print(f"  Open it: open {path}")
    else:
        print("✗ Report generation failed")