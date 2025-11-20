<div align="center">

  <h1 style="color:#39ff14; text-shadow:0 0 10px #39ff14;">
    ⚡ Web Vulnerability Scanner 🔍
  </h1>

  <p>
    <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge&color=39ff14">
    <img src="https://img.shields.io/badge/Made%20With-Python-blue?style=for-the-badge">
    <img src="https://img.shields.io/badge/UI-Hacker%20Theme-brightgreen?style=for-the-badge">
  </p>

  <p style="max-width:800px">
    A powerful <b>automated Web Application Vulnerability Scanner</b> built with
    <b>Python, Flask, BeautifulSoup, Requests</b> — featuring a glowing green hacker-UI,
    PDF report generation, charts, OWASP mapping, JSON/CSV export, and more ⚡💻
  </p>

  <br>

  <img src="https://via.placeholder.com/900x420/000000/39ff14?text=Web+Vuln+Scanner+Dashboard" width="90%">

  <br><br>

</div>

<hr />

<h2>🚀 Features</h2>

<ul>
  <li>🕸️ <b>Website crawling</b> with input-field discovery across pages</li>
  <li>💉 <b>SQL Injection (SQLi)</b> test payloads on parameters and forms</li>
  <li>⚡ <b>Cross-Site Scripting (XSS)</b> injection tests</li>
  <li>🔐 <b>CSRF weakness checks</b> on sensitive forms</li>
  <li>📊 <b>Severity classification</b> into High / Medium / Low</li>
  <li>📈 <b>Visual charts</b>:
    <ul>
      <li>Severity Distribution (Pie chart)</li>
      <li>OWASP Top 10 Mapping (table/visual mapping)</li>
      <li>Per-Page Severity Breakdown</li>
    </ul>
  </li>
  <li>📄 <b>Export options</b>: PDF, JSON, CSV</li>
  <li>🖥️ <b>Hacker-theme UI</b> with neon green glowing borders</li>
  <li>⚙️ <b>Risk scoring system</b> based on severity distribution</li>
  <li>📁 <b>Per-URL vulnerability logging</b> with timestamped evidence</li>
</ul>

<hr />

<h2>📦 Project Structure (Conceptual)</h2>

<p>This project is organized into logical components to separate the web UI, scanning engine, and reporting system:</p>

<ul>
  <li><b>app.py</b> – Main Flask application, routes, and web server logic</li>
  <li><b>scanner.py</b> – Core scanning engine: crawling, payload injection, response analysis</li>
  <li><b>report_generator.py</b> – Generates professional PDF reports with charts and tables</li>
  <li><b>templates/</b> – HTML Jinja templates for:
    <ul>
      <li><b>index.html</b> – Scan input form</li>
      <li><b>results.html</b> – Results dashboard, charts, tables</li>
      <li><b>base.html</b> – Common layout and structure</li>
    </ul>
  </li>
  <li><b>static/css/style.css</b> – Hacker-style neon green themed UI styling</li>
  <li><b>requirements.txt</b> – Python dependencies (Flask, Requests, BeautifulSoup, ReportLab, etc.)</li>
  <li><b>README.md</b> – Documentation for users and contributors</li>
</ul>

<hr />

<h2>🛠️ What the Scanner Does (Theory)</h2>

<p>
The Web Vulnerability Scanner automates the process of testing a web application for common security issues:
</p>

<ul>
  <li>It starts from a target URL and <b>crawls links</b> within the same domain.</li>
  <li>For each page, it discovers <b>forms and input fields</b>.</li>
  <li>It injects crafted payloads for <b>SQL Injection</b> and <b>XSS</b>, and inspects responses for signs of vulnerability.</li>
  <li>It checks for <b>missing or weak CSRF protection</b> on sensitive actions.</li>
  <li>Each finding is tagged with:
    <ul>
      <li>Vulnerability type</li>
      <li>Target URL</li>
      <li>Parameter name</li>
      <li>Severity (High/Medium/Low)</li>
      <li>Evidence (snippet of response / behavior)</li>
      <li>Timestamp</li>
    </ul>
  </li>
  <li>Findings are then summarized into <b>severity counts</b> and mapped to <b>OWASP Top 10</b> categories.</li>
  <li>All of this is presented in a <b>dashboard-style UI</b> and can be exported as reports.</li>
</ul>

<hr />

<h2>🧠 OWASP Top 10 Mapping</h2>

<p>
Findings are mapped to OWASP 2021 categories such as:
</p>

<ul>
  <li><b>A01</b> – Broken Access Control</li>
  <li><b>A02</b> – Cryptographic Failures</li>
  <li><b>A03</b> – Injection</li>
  <li><b>A05</b> – Security Misconfiguration</li>
  <li><b>A07</b> – Identification & Authentication Failures</li>
  <li><b>A09</b> – Security Logging & Monitoring Failures</li>
</ul>

<p>
This allows security analysts and developers to understand how the detected issues relate to standard OWASP risks.
</p>

<hr />

<h2>📄 Reporting & Exports</h2>

<ul>
  <li><b>PDF Report</b> – Professional report containing:
    <ul>
      <li>Target information</li>
      <li>Total findings and risk score</li>
      <li>Severity distribution chart</li>
      <li>OWASP mapping summary</li>
      <li>Per-page breakdown charts</li>
      <li>Detailed vulnerability table with evidence</li>
    </ul>
  </li>
  <li><b>JSON Export</b> – Machine-readable export of all findings and metadata</li>
  <li><b>CSV Export</b> – Tabular format for spreadsheets or further data analysis</li>
</ul>

<hr />

<h2>🛠️ Installation & Execution (How to Run) ⚙️</h2>

<p>Use the following steps to set up and launch the Web Vulnerability Scanner:</p>

<pre><code># 🚀 Start the Hacker-Themed Web Vulnerability Scanner

# 1️⃣ Activate your virtual environment (Windows) 💻
venv\Scripts\activate

# 1️⃣ Activate on Linux/Mac 🐧
source venv/bin/activate

# 2️⃣ Install all required dependencies 📦
pip install -r requirements.txt

# 3️⃣ Run the application ⚡
python app.py

# 4️⃣ Open the tool in your browser 🌐
http://127.0.0.1:5000
</code></pre>

<p>
After starting the app, you can enter a target URL in the UI, run a scan, view charts and tables, and export a PDF/JSON/CSV report.
</p>

<hr />

<h2>🤝 Contributing</h2>

<p>
Contributions are welcome! You can:
</p>

<ul>
  <li>Add new vulnerability modules (LFI, RFI, RCE, SSRF, Open Redirect, etc.)</li>
  <li>Improve detection logic or payloads</li>
  <li>Enhance the UI/UX and dashboard visualizations</li>
  <li>Optimize performance and crawling efficiency</li>
</ul>

<p>
Before submitting a major change, consider opening an issue to discuss your idea.
</p>

<hr />

<h2>📜 License</h2>

<p>
This project is licensed under the <b>MIT License</b>, allowing free use, modification, and distribution for both personal and commercial purposes.
</p>

<hr />

<div align="center">

  <h3 style="color:#39ff14; text-shadow:0 0 8px #39ff14;">
    Thank you for using Web Vulnerability Scanner ⚡
  </h3>

  <h4 style="color:#00ff99">
    Happy Hacking 💀💚
  </h4>

</div>
