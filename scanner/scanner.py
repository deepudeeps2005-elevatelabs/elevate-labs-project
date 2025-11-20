# scanner/scanner.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from .crawler import SimpleCrawler
from .payloads import XSS_PAYLOADS, SQLI_PAYLOADS, SQL_ERROR_PATTERNS
from .report import make_vuln


class WebScanner:
    def __init__(self, max_pages=20, timeout=10):
        self.crawler = SimpleCrawler(max_pages=max_pages, timeout=timeout)
        self.session = requests.Session()
        self.timeout = timeout

    def scan(self, start_url, max_pages=20):
        # Reconfigure crawler for each scan
        self.crawler.max_pages = max_pages
        pages = self.crawler.crawl(start_url)
        vulnerabilities = []

        for url, html in pages:
            soup = BeautifulSoup(html, "html.parser")
            forms = soup.find_all("form")

            # Check forms for XSS/SQLi
            for form in forms:
                vulnerabilities.extend(self._test_form_xss(url, form))
                vulnerabilities.extend(self._test_form_sqli(url, form))
                vulnerabilities.extend(self._check_csrf(url, form))

        return vulnerabilities, pages

    def _get_form_details(self, url, form):
        action = form.get("action")
        method = form.get("method", "get").lower()
        form_url = urljoin(url, action) if action else url
        inputs = []

        for input_tag in form.find_all(["input", "textarea"]):
            name = input_tag.get("name")
            if not name:
                continue
            itype = input_tag.get("type", "text")
            value = input_tag.get("value", "")
            inputs.append({"name": name, "type": itype, "value": value})

        return form_url, method, inputs

    def _submit_form(self, url, form, payload_value):
        form_url, method, inputs = self._get_form_details(url, form)
        data = {}

        for input_info in inputs:
            # Only inject into text-like fields
            if input_info["type"] in ["text", "search", "email", "password", "textarea"]:
                data[input_info["name"]] = payload_value
            else:
                data[input_info["name"]] = input_info["value"]

        try:
            if method == "post":
                response = self.session.post(form_url, data=data, timeout=self.timeout)
            else:
                response = self.session.get(form_url, params=data, timeout=self.timeout)
            return response, data, form_url
        except Exception:
            return None, data, form_url

    # ---------- XSS ----------
    def _test_form_xss(self, url, form):
        vulns = []
        for payload in XSS_PAYLOADS:
            response, data, form_url = self._submit_form(url, form, payload)
            if response and payload in response.text:
                vulns.append(
                    make_vuln(
                        vtype="Reflected XSS",
                        url=form_url,
                        param=", ".join(data.keys()),
                        evidence=f"Payload reflected in response: {payload}",
                        severity="High",
                    )
                )
                break  # one finding per form is enough for demo
        return vulns

    # ---------- SQL Injection ----------
    def _test_form_sqli(self, url, form):
        vulns = []
        for payload in SQLI_PAYLOADS:
            response, data, form_url = self._submit_form(url, form, payload)
            if not response:
                continue
            for err in SQL_ERROR_PATTERNS:
                if err.lower() in response.text.lower():
                    vulns.append(
                        make_vuln(
                            vtype="SQL Injection",
                            url=form_url,
                            param=", ".join(data.keys()),
                            evidence=f"SQL error pattern found: {err}",
                            severity="High",
                        )
                    )
                    return vulns
        return vulns

    # ---------- CSRF (very basic heuristic) ----------
    def _check_csrf(self, url, form):
        vulns = []
        method = form.get("method", "get").lower()
        if method != "post":
            return vulns

        hidden_inputs = form.find_all("input", {"type": "hidden"})
        names = [h.get("name", "").lower() for h in hidden_inputs]
        has_csrf = any("csrf" in n or "token" in n for n in names)

        if not has_csrf:
            action = form.get("action", url)
            form_url = urljoin(url, action)
            vulns.append(
                make_vuln(
                    vtype="Potential CSRF",
                    url=form_url,
                    param="(no CSRF token detected)",
                    evidence="POST form without obvious CSRF/token hidden field.",
                    severity="Medium",
                )
            )
        return vulns
