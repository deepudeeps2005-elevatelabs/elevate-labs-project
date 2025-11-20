# app.py

from flask import Flask, render_template, request, send_file, Response
from scanner import WebScanner
from report_generator import generate_pdf_report
from collections import defaultdict
import json

app = Flask(__name__)

scan_results = []
scan_target = ""

scanner = WebScanner(max_pages=20)


def compute_severity_stats(vulnerabilities):
    high = sum(1 for v in vulnerabilities if v["severity"].lower() == "high")
    medium = sum(1 for v in vulnerabilities if v["severity"].lower() == "medium")
    low = sum(1 for v in vulnerabilities if v["severity"].lower() == "low")
    total = high + medium + low

    if total > 0:
        risk_score = int(((high * 3) + (medium * 2) + (low * 1)) / (total * 3) * 100)
    else:
        risk_score = 0

    return high, medium, low, total, risk_score


def compute_page_stats(vulnerabilities):
    stats = defaultdict(lambda: {"high": 0, "medium": 0, "low": 0})
    for v in vulnerabilities:
        url = v["url"]
        sev = v["severity"].lower()
        if sev == "high":
            stats[url]["high"] += 1
        elif sev == "medium":
            stats[url]["medium"] += 1
        elif sev == "low":
            stats[url]["low"] += 1

    page_labels = list(stats.keys())
    page_high_counts = [stats[u]["high"] for u in page_labels]
    page_medium_counts = [stats[u]["medium"] for u in page_labels]
    page_low_counts = [stats[u]["low"] for u in page_labels]

    return page_labels, page_high_counts, page_medium_counts, page_low_counts


def compute_owasp_mapping(vulnerabilities):
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
    counts = {key: 0 for key in owasp_categories}

    for v in vulnerabilities:
        t = v["type"].lower()
        if "csrf" in t:
            counts["A01: Broken Access Control"] += 1
        elif "sql injection" in t or "sqli" in t or "injection" in t or "xss" in t:
            counts["A03: Injection"] += 1

    labels = list(counts.keys())
    values = [counts[k] for k in labels]
    return labels, values


@app.route("/", methods=["GET", "POST"])
def index():
    global scan_results, scan_target

    if request.method == "POST":
        target_url = request.form.get("target_url")
        max_pages = int(request.form.get("max_pages", "10") or "10")

        if not target_url.startswith("http"):
            target_url = "http://" + target_url

        scan_target = target_url

        vulnerabilities, pages = scanner.scan(target_url, max_pages=max_pages)
        scan_results = vulnerabilities

        high_count, medium_count, low_count, total_findings, risk_score = compute_severity_stats(vulnerabilities)
        page_labels, page_high, page_medium, page_low = compute_page_stats(vulnerabilities)
        owasp_labels, owasp_values = compute_owasp_mapping(vulnerabilities)

        return render_template(
            "results.html",
            target_url=target_url,
            vulnerabilities=vulnerabilities,
            total_pages=len(pages),
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            risk_score=risk_score,
            total_findings=total_findings,
            page_labels=page_labels,
            page_high=page_high,
            page_medium=page_medium,
            page_low=page_low,
            owasp_labels=owasp_labels,
            owasp_values=owasp_values,
        )

    return render_template("index.html")


@app.route("/download_report")
def download_report():
    global scan_results, scan_target
    if not scan_results:
        return "No scan results available for report."
    pdf_buffer = generate_pdf_report(scan_results, scan_target)
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name="scan_report.pdf",
        mimetype="application/pdf",
    )


@app.route("/export/json")
def export_json():
    global scan_results, scan_target
    if not scan_results:
        return "No scan results to export."
    data = {"target": scan_target, "results": scan_results}
    return Response(
        json.dumps(data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=scan_results.json"},
    )


@app.route("/export/csv")
def export_csv():
    global scan_results, scan_target
    if not scan_results:
        return "No scan results to export."

    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["type", "url", "parameter", "severity", "evidence", "timestamp"])
    for v in scan_results:
        writer.writerow(
            [
                v.get("type", ""),
                v.get("url", ""),
                v.get("param", ""),
                v.get("severity", ""),
                v.get("evidence", ""),
                v.get("timestamp", ""),
            ]
        )
    output.seek(0)
    return Response(
        output.read(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=scan_results.csv"},
    )


if __name__ == "__main__":
    app.run(debug=True)

if __name__ == "__main__":
    import webbrowser
    import threading
    import logging

    # Disable Flask debug logs to avoid EXE issues
    log = logging.getLogger('werkzeug')
    log.disabled = True

    def open_browser():
        try:
            webbrowser.open("http://127.0.0.1:5000")
        except:
            pass

    threading.Timer(1.0, open_browser).start()

    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
