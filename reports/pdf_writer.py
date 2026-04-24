from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image,
)

from config import SIGNATURE_ENABLED, SIGNATURE_FILE


def add_signature_block(story, width=2.2 * inch, height=1.0 * inch):
    if not SIGNATURE_ENABLED:
        return

    signature_path = Path(SIGNATURE_FILE)
    if not signature_path.exists():
        return

    try:
        img = Image(str(signature_path), width=width, height=height)

        signature_table = Table([[img]], colWidths=[520])
        signature_table.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "RIGHT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ]))

        story.append(signature_table)

    except Exception:
        pass


def make_metric_box(title, value, bg_color, text_color=colors.white):
    data = [[str(value)], [title]]

    table = Table(
        data,
        colWidths=[1.45 * inch],
        rowHeights=[0.48 * inch, 0.35 * inch]
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg_color),
        ("TEXTCOLOR", (0, 0), (-1, -1), text_color),
        ("FONTNAME", (0, 0), (0, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (0, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (0, 0), 22),
        ("FONTSIZE", (0, 1), (0, 1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.white),
    ]))

    return table


def section_title(text):
    title = Table([[text]], colWidths=[520])
    title.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0F4C81")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return title


def write_pdf_report(
    pdf_name,
    findings,
    host_profiles,
    total_open_ports,
    high_risk,
    medium_risk,
    low_risk,
    unknown_risk,
    timestamp,
    targets
):
    doc = SimpleDocTemplate(
        str(pdf_name),
        pagesize=A4,
        rightMargin=28,
        leftMargin=28,
        topMargin=26,
        bottomMargin=26
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0B1F4D"),
        alignment=0,
    )

    subtitle_style = ParagraphStyle(
        "SubtitleStyle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#1D4ED8"),
        alignment=0,
    )

    body_style = ParagraphStyle(
        "BodyStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#1F2937"),
    )

    small_style = ParagraphStyle(
        "SmallStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#374151"),
    )

    story = []

    left_header = [
        Paragraph("NETWORK SECURITY SCANNER & ANALYSIS REPORT", title_style),
        Paragraph("SCAN & REPORTING DASHBOARD", subtitle_style),
    ]

    shown_targets = ", ".join(targets[:3])
    if len(targets) > 3:
        shown_targets += " ..."

    if " " in timestamp:
        date_part, time_part = timestamp.split(" ", 1)
    else:
        date_part, time_part = timestamp, ""

    right_header_text = "<br/>".join([
        f"<b>Date:</b> {date_part}",
        f"<b>Time:</b> {time_part}",
        f"<b>Targets:</b> {shown_targets}",
        f"<b>Total Hosts:</b> {len(host_profiles)}",
    ])

    header_table = Table([
        [left_header, Paragraph(right_header_text, body_style)]
    ], colWidths=[330, 190])

    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 1.2, colors.HexColor("#0B1F4D")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))

    story.append(header_table)
    story.append(Spacer(1, 0.18 * inch))

    exec_text = (
        f"The scan completed successfully. "
        f"{len(host_profiles)} host(s) were profiled and "
        f"{total_open_ports} open port(s) were identified across the scanned targets. "
        f"The dashboard below summarizes the current exposure and key recommendations. "
        f"This assessment provides a snapshot of network exposure and potential security risks."
    )

    metrics = Table([
    [
        make_metric_box("HIGH RISK", high_risk, colors.HexColor("#DC2626")),
        make_metric_box("MEDIUM RISK", medium_risk, colors.HexColor("#F97316")),
    ],
    [
        make_metric_box("LOW RISK", low_risk, colors.HexColor("#EAB308"), text_color=colors.black),
        make_metric_box("UNKNOWN", unknown_risk, colors.HexColor("#16A34A")),
    ]
], colWidths=[130, 130])

    executive_block = Table([
        [Paragraph("<b>EXECUTIVE SUMMARY</b><br/><br/>" + exec_text, body_style)]
    ], colWidths=[250])

    executive_block.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))

    risk_block = Table([
        [Paragraph("<b>RISK SUMMARY</b>", body_style)],
        [metrics]
    ], colWidths=[260])

    risk_block.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#CBD5E1")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))

    top_dashboard = Table([
        [executive_block, risk_block]
    ], colWidths=[255, 265])

    top_dashboard.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))

    story.append(top_dashboard)
    story.append(Spacer(1, 0.18 * inch))

    story.append(section_title("DISCOVERED HOSTS"))
    story.append(Spacer(1, 0.08 * inch))

    host_rows = [["IP Address", "Device Type", "Open Ports"]]
    for host in host_profiles:
        host_rows.append([
            host["target"],
            host["device_type"],
            str(host["open_ports"]),
        ])

    hosts_table = Table(host_rows, colWidths=[150, 250, 120])
    hosts_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCE6F1")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(hosts_table)
    story.append(Spacer(1, 0.18 * inch))

    story.append(section_title("OPEN PORT FINDINGS"))
    story.append(Spacer(1, 0.08 * inch))

    findings_rows = [["Target", "Port", "Service", "Status", "Risk"]]
    for item in findings:
        findings_rows.append([
            item["target"],
            item["port"],
            item["service"],
            item["status"],
            item["risk"].upper(),
        ])

    findings_table = Table(findings_rows, colWidths=[130, 70, 120, 80, 120])
    findings_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCE6F1")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 1), (-1, -1), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(findings_table)
    story.append(Spacer(1, 0.18 * inch))

    story.append(section_title("RECOMMENDATIONS"))
    story.append(Spacer(1, 0.08 * inch))

    recommendation_rows = [["Target", "Recommendation"]]
    for host in host_profiles:
        rec_text = "<br/>".join([f"- {rec}" for rec in host["recommendations"]])
        recommendation_rows.append([
            host["target"],
            Paragraph(rec_text, small_style),
        ])

    recommendations_table = Table(recommendation_rows, colWidths=[140, 380])
    recommendations_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCE6F1")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(recommendations_table)
    story.append(Spacer(1, 0.18 * inch))

    footer_note = "This report is intended for authorized security assessment and internal review only."
    story.append(Paragraph(footer_note, small_style))
    story.append(Spacer(1, 0.15 * inch))

    add_signature_block(story)

    doc.build(story)