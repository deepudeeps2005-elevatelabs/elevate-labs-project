# scanner/report.py

from datetime import datetime


def make_vuln(vtype, url, param, evidence, severity="Medium"):
    return {
        "type": vtype,
        "url": url,
        "param": param,
        "evidence": evidence[:300],  # limit length for UI
        "severity": severity,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
