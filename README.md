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
A powerful **automated Web Application Vulnerability Scanner** built with  
<b>Python, Flask, BeautifulSoup, Requests</b> — featuring a glowing green hacker-UI,  
PDF report generation, charts, OWASP mapping, JSON/CSV export, and more ⚡💻  
</p>

<br>

<img src="https://via.placeholder.com/900x420/000000/39ff14?text=Web+Vuln+Scanner+Dashboard" width="90%">
<br><br>

</div>

---

<h2>🚀 Features</h2>

<ul>
  <li>🕸️ <b>Full website crawling</b> with input-field discovery</li>
  <li>💉 <b>SQL Injection tests</b></li>
  <li>⚡ <b>XSS Injection tests</b></li>
  <li>🔐 <b>CSRF detection</b></li>
  <li>📊 <b>Severity classification</b> (High / Medium / Low)</li>
  <li>📈 <b>Charts:</b> 
    <ul>
      <li>Pie chart – Severity Distribution</li>
      <li>OWASP Top 10 Mapping</li>
      <li>Per-Page Severity Breakdown</li>
    </ul>
  </li>
  <li>📄 <b>Export formats:</b> PDF, JSON, CSV</li>
  <li>🖥️ <b>Hacker Theme UI</b> with neon green glowing borders</li>
  <li>⚙️ <b>Risk scoring system</b></li>
  <li>📁 <b>Per-URL vulnerability logging</b></li>
</ul>

---

<h2>📦 Project Structure</h2>

```bash
web-vuln-scanner/
│
├── app.py                 # Main Flask backend
├── scanner.py             # Crawling + vulnerability tests
├── report_generator.py    # PDF report creation
│
├── templates/
│   ├── index.html
│   ├── results.html
│   └── base.html
│
├── static/
│   ├── css/style.css
│   └── charts/*.png
│
├── requirements.txt
└── README.md

<h2>🛠️ Installation</h2> <h3>1️⃣ Clone the repository</h3>
git clone https://github.com/yourusername/web-vuln-scanner.git
cd web-vuln-scanner

<h3>2️⃣ Create virtual environment</h3>
python -m venv venv
source venv/bin/activate     # Linux/Mac
venv\Scripts\activate        # Windows

<h3>3️⃣ Install dependencies</h3>
pip install -r requirements.txt

<h2>▶️ Run the Tool</h2>
python app.py


Now open your browser:

👉 http://127.0.0.1:5000

You will see the hacker-theme UI with glowing neon green matrix design.

<h2>🧪 Sample Screenshot</h2> <img src="https://via.placeholder.com/900x480/000000/39ff14?text=Scan+Results+%7C+Charts+%7C+OWASP+Mapping" width="95%">
<h2>📄 PDF Report</h2>

The tool auto-generates a professional PDF report containing:

✔ Charts
✔ Severity table
✔ OWASP mapping
✔ Findings with timestamps
✔ Risk score

Example (placeholder):

<img src="https://via.placeholder.com/900x450/000000/39ff14?text=PDF+Report+Sample" width="95%">
<h2>🧠 OWASP Top 10 Mapping</h2>

All detected vulnerabilities are mapped to:

A01: Broken Access Control

A02: Cryptographic Failures

A03: Injection

A05: Security Misconfiguration

A07: Identification & Auth Failures

A09: Security Logging & Monitoring Failures
… and more.

Charts in UI + PDF show proper alignment.

<h2>💾 Export Options</h2>

Your results can be exported as:

📄 PDF  
🧾 JSON  
📊 CSV  

<h2>🤝 Contributing</h2>

Pull requests are welcome!
If you want to add more tests (LFI, RFI, RCE, Open Redirect), open an issue first.

<h2>📜 License</h2>

This project is licensed under the MIT License — free for all usage.

<div align="center"> <h3 style="color:#39ff14; text-shadow:0 0 8px #39ff14;"> Thank you for using Web Vulnerability Scanner ⚡ </h3> <h4 style="color:#00ff99">Happy Hacking 💀💚</h4> </div> ```