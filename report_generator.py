# report_generator.py

import io
from collections import Counter, defaultdict

import matplotlib
matplotlib.use("Agg")  # headless backend
import matplotlib.pyplot as plt

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Table,
    TableStyle,
    Image,
    Spacer,
)
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors


def _build_severity_stats(vulnerabilities):
    counts = Counter(v["severity"].capitalize() for v in vulnerabilities)
    high = counts.get("High", 0)
    medium = counts.get("Medium", 0)
    low = counts.get("Low", 0)
    total = high + medium + low

    if total > 0:
        risk_score = int(((high * 3) + (medium * 2) + (low * 1)) / (total * 3) * 100)
    else:
        risk_score = 0

    return high, medium, low, total, risk_score


def _build_page_stats(vulnerabilities):
    stats = defaultdict(lambda: {"High": 0, "Medium": 0, "Low": 0})
    for v in vulnerabilities:
        url = v["url"]
        sev = v["severity"].capitalize()
        if sev in stats[url]:
            stats[url][sev] += 1
    return stats


def _build_owasp_mapping(vulnerabilities):
    """Return OWASP 2021 labels + counts (all 10 categories shown)."""
    owasp_categories = [
        "A01: Broken Access Control",
        "A02: Cryptographic Failures",
        "A03: Injection",
        "A04: Insecure Design",
        "A05: Security Misconfiguration",
        "A06: Vulnerable and Outdated Components",
        "A07: Identification & Authentication Failures",
        "A08: Software & Data Integrity Failures",
        "A09: Security Logging & Monitoring Failures",
        "A10: Server-Side Request Forgery (SSRF)",
    ]
    counts = {k: 0 for k in owasp_categories}

    for v in vulnerabilities:
        t = v["type"].lower()
        if "csrf" in t:
            counts["A01: Broken Access Control"] += 1
        elif "sql injection" in t or "sqli" in t or "injection" in t or "xss" in t:
            counts["A03: Injection"] += 1

    labels = list(counts.keys())
    values = [counts[k] for k in labels]
    return labels, values


def _generate_severity_pie(high, medium, low):
    labels = []
    sizes = []
    colors_list = []

    if high > 0:
        labels.append("High")
        sizes.append(high)
        colors_list.append("#ff4c4c")
    if medium > 0:
        labels.append("Medium")
        sizes.append(medium)
        colors_list.append("#ffb74d")
    if low > 0:
        labels.append("Low")
        sizes.append(low)
        colors_list.append("#4caf50")

    if not sizes:
        labels = ["No Findings"]
        sizes = [1]
        colors_list = ["#555555"]

    fig, ax = plt.subplots(figsize=(2.3, 2.3))
    ax.pie(
        sizes,
        labels=labels,
        autopct="%1.0f%%",
        startangle=140,
        colors=colors_list,
        textprops={"color": "white", "fontsize": 8},
    )
    ax.set_title("Severity Distribution", color="white", fontsize=9)
    fig.patch.set_facecolor("#000000")
    ax.set_facecolor("#000000")

    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png", bbox_inches="tight", dpi=120)
    plt.close(fig)
    buf.seek(0)
    return buf


def _generate_owasp_barh(labels, values):
    """Horizontal OWASP bar chart (labels left, bars right)."""
    y = range(len(labels))
    fig, ax = plt.subplots(figsize=(6.0, 3.0))

    ax.barh(y, values, color="#39ff14")
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=7, color="#c8ffde")
    ax.invert_yaxis()  # first item on top

    ax.set_xlabel("Findings", color="#c8ffde", fontsize=8)
    ax.set_title("OWASP Top 10 Mapping", color="#39ff14", fontsize=10)

    ax.tick_params(axis="x", colors="#c8ffde")
    fig.patch.set_facecolor("#000000")
    ax.set_facecolor("#000000")

    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png", bbox_inches="tight", dpi=120)
    plt.close(fig)
    buf.seek(0)
    return buf


def _generate_page_barh(page_stats):
    """Horizontal stacked per-page bar chart."""
    if not page_stats:
        buf = io.BytesIO()
        fig, ax = plt.subplots(figsize=(4, 2))
        ax.text(0.5, 0.5, "No per-page data", color="white", ha="center", va="center")
        ax.set_axis_off()
        fig.patch.set_facecolor("#000000")
        plt.savefig(buf, format="png", bbox_inches="tight", dpi=120)
        plt.close(fig)
        buf.seek(0)
        return buf

    urls = list(page_stats.keys())
    high_vals = [page_stats[u]["High"] for u in urls]
    med_vals = [page_stats[u]["Medium"] for u in urls]
    low_vals = [page_stats[u]["Low"] for u in urls]

    y = range(len(urls))

    # dynamic height based on number of pages
    fig_height = max(2.5, len(urls) * 0.35)
    fig, ax = plt.subplots(figsize=(6.0, fig_height))

    # stacked horizontal bars
    ax.barh(y, low_vals, color="#4caf50", label="Low")
    ax.barh(y, med_vals, left=low_vals, color="#ffb74d", label="Medium")
    tops = [low_vals[i] + med_vals[i] for i in range(len(urls))]
    ax.barh(y, high_vals, left=tops, color="#ff4c4c", label="High")

    ax.set_yticks(y)
    ax.set_yticklabels(urls, fontsize=7, color="#c8ffde")
    ax.invert_yaxis()

    ax.set_xlabel("Findings", color="#c8ffde", fontsize=8)
    ax.set_title("Per-Page Severity Breakdown", color="#39ff14", fontsize=10)

    ax.legend(fontsize=6, facecolor="#000000", labelcolor="#c8ffde")
    ax.tick_params(axis="x", colors="#c8ffde")
    fig.patch.set_facecolor("#000000")
    ax.set_facecolor("#000000")

    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png", bbox_inches="tight", dpi=120)
    plt.close(fig)
    buf.seek(0)
    return buf


def generate_pdf_report(vulnerabilities, target_url):
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=36,
        leftMargin=36,
        topMargin=40,
        bottomMargin=36,
    )
    styles = getSampleStyleSheet()
    story = []

    # base styles in hacker green
    title_style = styles["Title"]
    normal_style = styles["Normal"]

    title_style.textColor = colors.HexColor("#39ff14")
    normal_style.textColor = colors.HexColor("#c8ffde")
    normal_style.fontName = "Helvetica"
    normal_style.fontSize = 9

    small_style = ParagraphStyle(
        "Small",
        parent=normal_style,
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#c8ffde"),
    )

    story.append(Paragraph("<b>Web Application Vulnerability Scan Report</b>", title_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph(f"<b>Target URL:</b> {target_url}", normal_style))

    high, medium, low, total, risk_score = _build_severity_stats(vulnerabilities)

    story.append(
        Paragraph(
            f"<b>Total Findings:</b> {total} &nbsp;&nbsp; "
            f"<b>High:</b> {high} &nbsp; <b>Medium:</b> {medium} &nbsp; <b>Low:</b> {low}",
            normal_style,
        )
    )
    story.append(Paragraph(f"<b>Overall Risk Score:</b> {risk_score} / 100", normal_style))
    story.append(Spacer(1, 10))

    # ---------- Severity Pie Chart ----------
    chart_buf = _generate_severity_pie(high, medium, low)
    chart_img = Image(chart_buf, width=130, height=130)
    story.append(chart_img)
    story.append(Spacer(1, 12))

    # ---------- OWASP Horizontal Bar Chart ----------
    owasp_labels, owasp_values = _build_owasp_mapping(vulnerabilities)
    owasp_buf = _generate_owasp_barh(owasp_labels, owasp_values)
    owasp_img = Image(owasp_buf, width=430, height=200)
    story.append(owasp_img)
    story.append(Spacer(1, 12))

    # ---------- Per-Page Horizontal Stacked Chart ----------
    page_stats = _build_page_stats(vulnerabilities)
    page_buf = _generate_page_barh(page_stats)
    page_img = Image(page_buf, width=430, height=230)
    story.append(page_img)
    story.append(Spacer(1, 16))

    # ---------- Detailed Vulnerability Table ----------
    story.append(Paragraph("<b>Detailed Findings</b>", normal_style))
    story.append(Spacer(1, 6))

    header = [
        Paragraph("<b>Type</b>", small_style),
        Paragraph("<b>URL</b>", small_style),
        Paragraph("<b>Parameter</b>", small_style),
        Paragraph("<b>Severity</b>", small_style),
        Paragraph("<b>Evidence</b>", small_style),
    ]
    data = [header]

    for v in vulnerabilities:
        row = [
            Paragraph(v["type"], small_style),
            Paragraph(v["url"], small_style),
            Paragraph(v["param"], small_style),
            Paragraph(v["severity"], small_style),
            Paragraph(v["evidence"][:400] + ("..." if len(v["evidence"]) > 400 else ""), small_style),
        ]
        data.append(row)

    # T1 layout: wide table with better spacing
    detail_table = Table(
        data,
        colWidths=[70, 150, 90, 50, 190],  # total 550pt (fits page)
        repeatRows=1,
    )
    detail_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#003300")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#000a05")),
                ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#c8ffde")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#39ff14")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )

    story.append(detail_table)

    doc.build(story)
    buffer.seek(0)
    return buffer
