"""
report.py - SecretScope PDF Report Generator

Creates a clean PDF report from detector findings and optional AI analysis.

Usage:
    from report import generate_report
    generate_report(findings, "report.pdf")
"""

from datetime import datetime
import html
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    CondPageBreak,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


COLOR_CRITICAL = colors.HexColor("#D92D20")
COLOR_HIGH = colors.HexColor("#E56A00")
COLOR_MEDIUM = colors.HexColor("#B68A00")
COLOR_LOW = colors.HexColor("#246BCE")
COLOR_NAVY = colors.HexColor("#182033")
COLOR_MUTED = colors.HexColor("#667085")
COLOR_LINE = colors.HexColor("#D0D5DD")
COLOR_CODE_BG = colors.HexColor("#F7F8FA")

SEVERITY_COLORS = {
    "critical": COLOR_CRITICAL,
    "high": COLOR_HIGH,
    "medium": COLOR_MEDIUM,
    "low": COLOR_LOW,
}


def _normalize_severity(value):
    return str(value or "low").strip().lower()


def _safe(value):
    """Escape text for ReportLab while preserving ordinary quote characters."""
    if value is None:
        return ""

    # quote=False prevents code quotes from appearing literally as &quot;.
    text = html.escape(str(value), quote=False)
    return text.replace("\n", "<br/>")


def _build_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=25,
        leading=29,
        textColor=COLOR_NAVY,
        alignment=TA_LEFT,
        spaceAfter=5,
    ))

    styles.add(ParagraphStyle(
        name="Subtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=COLOR_MUTED,
        spaceAfter=18,
    ))

    styles.add(ParagraphStyle(
        name="Section",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        textColor=COLOR_NAVY,
        spaceBefore=14,
        spaceAfter=9,
    ))

    styles.add(ParagraphStyle(
        name="FindingTitle",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=COLOR_NAVY,
        spaceBefore=8,
        spaceAfter=4,
        splitLongWords=True,
        wordWrap="CJK",
    ))

    styles.add(ParagraphStyle(
        name="Meta",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=COLOR_MUTED,
        spaceAfter=8,
        splitLongWords=True,
        wordWrap="CJK",
    ))

    styles.add(ParagraphStyle(
        name="Body",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#101828"),
        spaceAfter=7,
        splitLongWords=True,
        wordWrap="CJK",
    ))

    styles.add(ParagraphStyle(
        name="Label",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#101828"),
        spaceBefore=7,
        spaceAfter=7,
    ))

    styles.add(ParagraphStyle(
        name="RiskText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#101828"),
        splitLongWords=True,
        wordWrap="CJK",
    ))

    styles.add(ParagraphStyle(
        name="FindingCode",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=8.3,
        leading=11,
        textColor=colors.HexColor("#1D2939"),
        leftIndent=0,
        rightIndent=0,
        splitLongWords=True,
        wordWrap="CJK",
    ))

    styles.add(ParagraphStyle(
        name="Small",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=COLOR_MUTED,
        splitLongWords=True,
        wordWrap="CJK",
    ))

    return styles



def _boxed_paragraph(text, style, background, border, padding=9):
    """Create a padded one-cell table that cannot overlap nearby content."""
    table = Table(
        [[Paragraph(text, style)]],
        colWidths=[7.06 * inch],
        hAlign="LEFT",
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), background),
        ("BOX", (0, 0), (-1, -1), 0.8, border),
        ("LEFTPADDING", (0, 0), (-1, -1), padding),
        ("RIGHTPADDING", (0, 0), (-1, -1), padding),
        ("TOPPADDING", (0, 0), (-1, -1), padding),
        ("BOTTOMPADDING", (0, 0), (-1, -1), padding),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return table


def _code_box(text, styles):
    return _boxed_paragraph(
        _safe(text),
        styles["FindingCode"],
        COLOR_CODE_BG,
        COLOR_LINE,
        padding=8,
    )


def _summary_table(findings):
    counts = {
        severity: sum(
            1 for finding in findings
            if _normalize_severity(finding.get("severity")) == severity
        )
        for severity in ("critical", "high", "medium", "low")
    }

    data = [
        ["Severity", "Count"],
        ["Critical", str(counts["critical"])],
        ["High", str(counts["high"])],
        ["Medium", str(counts["medium"])],
        ["Low", str(counts["low"])],
        ["Total", str(len(findings))],
    ]

    table = Table(data, colWidths=[3.4 * inch, 1.2 * inch], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_LINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -2),
         [colors.white, colors.HexColor("#F9FAFB")]),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#EAECF0")),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
    ]))
    return table


def _draw_footer(canvas, doc):
    canvas.saveState()
    width, _ = letter

    canvas.setStrokeColor(colors.HexColor("#E4E7EC"))
    canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, 0.52 * inch, width - doc.rightMargin, 0.52 * inch)

    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(COLOR_MUTED)
    canvas.drawString(doc.leftMargin, 0.32 * inch, "SecretScope Security Report")
    canvas.drawRightString(
        width - doc.rightMargin,
        0.32 * inch,
        f"Page {doc.page}",
    )
    canvas.restoreState()


def _finding_context(finding):
    # Prefer the detector's redacted context. Never require raw credentials.
    return (
        finding.get("context_redacted")
        or finding.get("context")
        or ""
    )


def _fixed_line(finding):
    return (
        finding.get("fixed_line")
        or finding.get("recommended_fix")
        or ""
    )


def _environment_variable(finding):
    return (
        finding.get("env_var_name")
        or finding.get("environment_variable")
        or "SECRET_KEY"
    )


def generate_report(findings, output_path="report.pdf"):
    """Generate the complete SecretScope PDF report."""
    try:
        findings = list(findings or [])
        styles = _build_styles()

        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            leftMargin=0.72 * inch,
            rightMargin=0.72 * inch,
            topMargin=0.68 * inch,
            bottomMargin=0.75 * inch,
            title="SecretScope Security Report",
            author="SecretScope",
        )

        story = [
            Paragraph("SecretScope Security Report", styles["ReportTitle"]),
            Paragraph(
                f"Generated {datetime.now().strftime('%B %d, %Y at %I:%M %p')}",
                styles["Subtitle"],
            ),
            Paragraph("Executive Summary", styles["Section"]),
        ]

        total = len(findings)
        critical_count = sum(
            1 for finding in findings
            if _normalize_severity(finding.get("severity")) == "critical"
        )

        if total == 0:
            summary = (
                "No hardcoded secrets were detected in the scanned code. "
                "Continue using environment variables, a secrets manager, "
                "and automated pre-commit scanning."
            )
        elif critical_count:
            summary = (
                f"This scan identified <b>{total} potential "
                f"secret{'s' if total != 1 else ''}</b>, including "
                f"<b>{critical_count} critical finding"
                f"{'s' if critical_count != 1 else ''}</b>. "
                "Critical findings should be reviewed and rotated immediately."
            )
        else:
            summary = (
                f"This scan identified <b>{total} potential "
                f"secret{'s' if total != 1 else ''}</b>. "
                "Review and remediate every finding to reduce exposure."
            )

        story.extend([
            Paragraph(summary, styles["Body"]),
            Spacer(1, 6),
        ])

        if findings:
            story.extend([
                _summary_table(findings),
                Spacer(1, 14),
            ])

        story.extend([
            Paragraph("Immediate Actions", styles["Section"]),
            Paragraph(
                "<b>1. Rotate exposed credentials.</b> Treat detected credentials "
                "as compromised until verified otherwise.<br/><br/>"
                "<b>2. Remove secrets from source code.</b> Use environment variables "
                "or a managed secrets service.<br/><br/>"
                "<b>3. Review version-control history.</b> Deleting a secret from the "
                "latest file does not remove it from earlier commits.<br/><br/>"
                "<b>4. Add preventive scanning.</b> Use pre-commit and CI checks to stop "
                "new secrets before they are merged.",
                styles["Body"],
            ),
        ])

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings_sorted = sorted(
            findings,
            key=lambda item: severity_order.get(
                _normalize_severity(item.get("severity")), 99
            ),
        )

        if findings_sorted:
            story.extend([
                PageBreak(),
                Paragraph("Detailed Findings", styles["Section"]),
                Paragraph(
                    "Findings are ordered from highest to lowest severity.",
                    styles["Body"],
                ),
                Spacer(1, 5),
            ])

        for index, finding in enumerate(findings_sorted, 1):
            severity = _normalize_severity(finding.get("severity"))
            severity_color = SEVERITY_COLORS.get(severity, COLOR_MUTED)
            risk_background = {
                "critical": "#FFF3F2",
                "high": "#FFF6ED",
                "medium": "#FFFAEB",
                "low": "#EFF8FF",
            }.get(severity, "#F9FAFB")

            # Only keep enough room for the title and metadata. The full finding
            # is intentionally allowed to flow onto the next page.
            story.append(CondPageBreak(1.05 * inch))

            title = (
                f"Finding #{index}: "
                f"<font color='{severity_color.hexval()}'>{severity.upper()}</font>"
                f" - {_safe(finding.get('type', 'Unknown finding'))}"
            )
            story.append(Paragraph(title, styles["FindingTitle"]))

            metadata = (
                f"<b>File:</b> {_safe(finding.get('file', 'unknown'))}"
                f" &nbsp;&nbsp; | &nbsp;&nbsp; "
                f"<b>Line:</b> {_safe(finding.get('line', '?'))}"
                f" &nbsp;&nbsp; | &nbsp;&nbsp; "
                f"<b>Service:</b> {_safe(finding.get('service', 'unknown'))}"
            )
            story.append(Paragraph(metadata, styles["Meta"]))

            blast_radius = finding.get("blast_radius") or "Analysis unavailable."
            story.append(_boxed_paragraph(
                f"<b>Risk analysis</b><br/>{_safe(blast_radius)}",
                styles["RiskText"],
                colors.HexColor(risk_background),
                severity_color,
                padding=10,
            ))
            story.append(Spacer(1, 12))

            context = _finding_context(finding)
            if context:
                story.append(Paragraph("Vulnerable code", styles["Label"]))
                story.append(Spacer(1, 4))
                story.append(_code_box(context, styles))
                story.append(Spacer(1, 12))

            fixed = _fixed_line(finding)
            if fixed:
                story.append(Paragraph("Recommended fix", styles["Label"]))
                story.append(Spacer(1, 4))
                story.append(_code_box(fixed, styles))
                story.append(Spacer(1, 12))

            environment_variable = _environment_variable(finding)
            story.append(Paragraph(
                f"<b>Environment variable:</b> "
                f"<font face='Courier'>{_safe(environment_variable)}</font>",
                styles["Body"],
            ))

            rotation_url = finding.get("rotation_url") or ""
            if rotation_url:
                story.append(Paragraph(
                    f"<b>Rotate at:</b> {_safe(rotation_url)}",
                    styles["Small"],
                ))

            story.append(Spacer(1, 15))

        story.extend([
            PageBreak(),
            Paragraph("About This Report", styles["Section"]),
            Paragraph(
                "This report was generated by <b>SecretScope</b>, a defensive "
                "security tool created for the MIT BWSI Cyber Operations Hackathon "
                "2026. It combines pattern-based detection with risk analysis to help "
                "developers identify and remediate exposed credentials.<br/><br/>"
                "Findings may contain false positives or false negatives. This report "
                "is one layer of defense and is not a complete security audit.",
                styles["Body"],
            ),
        ])

        doc.build(
            story,
            onFirstPage=_draw_footer,
            onLaterPages=_draw_footer,
        )
        return output_path

    except Exception as exc:
        print(f"[report] generate_report failed: {exc}")
        import traceback
        traceback.print_exc()
        return None