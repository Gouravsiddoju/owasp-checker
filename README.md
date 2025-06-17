# 🔍 OWASP Checker – AI-Powered Vulnerability Scanner

OWASP Checker is a **static code vulnerability scanner** that combines traditional pattern-based analysis with **LLM-powered** security audits. It scans your project files for critical security flaws using **OWASP Top 10**, **CWE**, **SANS Top 25**, and **5 custom security categories**.

> ✅ Built with Python · ⚙️ LLM via TechOptima · 📄 Rich CLI + HTML reports

---

## 🚀 Features

- ✅ **Static Code Scanning** (regex-based) for:
  - Hardcoded credentials, XSS, SQLi, insecure file handling, etc.
- 🧠 **LLM-Powered Vulnerability Detection**
  - Leverages `optgpt:7b` via TechOptima’s REST API.
- 📊 **Security Score** for each file (0-100)
- 🧾 **Detailed Reports**:
  - Console: Rich tables + code snippets
  - HTML: Full audit logs with per-file summaries
  - JSON: Machine-readable format for CI/CD integration
- 🧩 Covers 5 additional security domains:
  1. Web Frontend Security (CSP, inline JS, HTML issues)
  2. API & Web Services (CORS, auth, CSRF)
  3. File Handling (path traversal, unsafe writes)
  4. Authentication (weak or hardcoded credentials)
  5. Data Protection (unencrypted logs, plain text storage)

---

## 📦 Installation

Clone the repository and install the dependencies:

```bash
git clone https://github.com/Gouravsiddoju/owasp-checker.git
cd owasp_checker
pip install -r requirements.txt
