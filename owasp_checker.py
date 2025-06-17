import os
import re
import json
import requests
import logging
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from concurrent.futures import ThreadPoolExecutor, as_completed
import configparser
import pathlib
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type

# Console for pretty output
console = Console()

# Logger
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename="owasp_checker.log"
)

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')
API_URL = config.get('DEFAULT', 'API_URL', fallback='')
API_TIMEOUT = config.getint('DEFAULT', 'API_TIMEOUT', fallback=30)
API_RETRIES = config.getint('DEFAULT', 'API_RETRIES', fallback=3)
API_KEY = config.get('DEFAULT', 'API_KEY', fallback='')

# Prompt format
PROMPT_TEMPLATE = """
You are a senior application security expert.

Your task: Analyze the following code for security vulnerabilities using:

- OWASP Top 10 (A01–A10)
- CWE (Common Weakness Enumeration)
- SANS Top 25
- Plus these 5 additional security domains:

    1. Web Frontend Security (CSP, XSS, inline JS, HTML validation)
    2. API & Web Service Security (insecure APIs, missing auth, CSRF, CORS)
    3. File Handling (path traversal, insecure writes, data leaks)
    4. Authentication (hardcoded credentials, weak auth logic, token flaws)
    5. Data Protection (unencrypted data at rest/transit, sensitive info in logs)

⚠️ Strictly return results in this **one-line-per-vulnerability format**:

[Vulnerability Name] - [Category: OWASP A## / CWE-### / SANS-##] - [Severity: Low/Medium/High] - [Fix Suggestion] - [Auto Fix Available: Yes/No]

Example:
Hardcoded API Key - [Category: OWASP A06 / CWE-798 / SANS-09] - [Severity: High] - [Fix Suggestion: Move API keys to environment variables or a secret manager] - [Auto Fix Available: Yes]

DO NOT include any commentary, explanations, or markdown. Only return the final list of vulnerabilities in the format above.
Code:
```{lang}
{code}
List all findings with proper categorization. Do not include any explanations or extra commentary.
"""

# Language mapping by file extension
LANG_MAP = {
    '.py': 'python',
    '.js': 'javascript',
    '.php': 'php',
    '.java': 'java',
    '.ts': 'typescript',
    '.go': 'go',
    '.html': 'html'
}

IGNORE_PATTERNS = ['node_modules', 'venv', 'dist', 'build', 'pycache']

def detect_language(file_path):
    _, ext = os.path.splitext(file_path)
    return LANG_MAP.get(ext.lower(), 'plaintext')

def load_code(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        logging.error(f"Failed to read file {file_path}: {e}")
        return ""

@retry(
    stop=stop_after_attempt(API_RETRIES),
    wait=wait_fixed(2),
    retry=retry_if_exception_type((requests.exceptions.RequestException,)),
    after=lambda retry_state: logging.warning(f"Retrying API call (attempt {retry_state.attempt_number}/{API_RETRIES})")
)
def run_optgpt_analysis(code, lang):
    prompt = PROMPT_TEMPLATE.replace("{lang}", lang).replace("{code}", code)
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}" if API_KEY else None
    }
    headers = {k: v for k, v in headers.items() if v is not None}
    payload = {
        "model": "optgpt:7b",
        "prompt": prompt,
        "stream": False,
        "temperature": 0,
    }
    logging.debug(f"Sending API request: URL={API_URL}, Headers={headers}, Payload={payload}")
    try:
        response = requests.post(API_URL, json=payload, headers=headers, stream=True, verify=True, timeout=API_TIMEOUT)
        response.raise_for_status()

        full_response = ""
        for line in response.iter_lines():
            if line:
                try:
                    data = json.loads(line.decode('utf-8'))
                    full_response += data.get("response", "")
                except json.JSONDecodeError as e:
                    logging.error(f"JSON parsing error: {e} - Line: {line}")
                    continue
        logging.info(f"Raw LLM response: {full_response}")
        return full_response.strip()

    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP error: {e.response.status_code} - {e.response.text}")
        raise
    except requests.exceptions.RequestException as e:
        logging.error(f"LLM API call failed: {e}")
        raise

def parse_response(response):
    results = []

    # Each vulnerability is expected on a separate line
    for line in response.strip().splitlines():
        line = line.strip()
        if not line:
            continue

        # Match and extract fields using regex
        match = re.match(
            r"^(.*?)\s*-\s*Category:\s*(.*?)\s*-\s*Severity:\s*(Low|Medium|High)\s*-\s*Fix Suggestion:\s*(.*?)\s*-\s*Auto Fix Available:\s*(Yes|No)$",
            line,
            re.IGNORECASE
        )

        if match:
            vuln, category, severity, fix, autofix = match.groups()
            results.append({
                "vuln": vuln.strip(),
                "category": category.strip(),
                "severity": severity.strip().capitalize(),
                "fix": fix.strip(),
                "autofix": autofix.strip().capitalize(),
                "line": "?"
            })
        else:
            logging.warning(f"[Parser] Skipping unrecognized format: {line}")

    return results
def group_issues_by_type(issues):
    grouped = {}
    for issue in issues:
        key = (issue["vuln"], issue["category"], issue["severity"], issue["fix"], issue["autofix"])
        if key not in grouped:
            grouped[key] = {
                "vuln": issue["vuln"],
                "category": issue["category"],
                "severity": issue["severity"],
                "fix": issue["fix"],
                "autofix": issue["autofix"],
                "lines": []
            }
        if "line" in issue:
            grouped[key]["lines"].append(issue["line"])
    return list(grouped.values())


import re

def scan_static_patterns(code, lang):
    findings = []
    lines = code.splitlines()

    for lineno, line in enumerate(lines, 1):
        line = line.strip()

        # 1. 🔐 Hardcoded secrets
        if re.search(r'^\s*(apikey|password|secret|token)\s*=\s*["\'].*["\']\s*$', line, re.I):
            findings.append({
                "vuln": "Hardcoded Secrets",
                "category": "SANS-09",
                "severity": "High",
                "fix": "Move secrets to environment variables or secret management tools.",
                "autofix": "Yes",
                "line": lineno
            })

        # 2. 💣 Dangerous functions
        if lang != 'html':
            for func in ['eval', 'exec']:
                if re.search(rf'\b{func}\s*\(', line):
                    findings.append({
                        "vuln": f"Usage of {func}()",
                        "category": "CWE-78",
                        "severity": "High",
                        "fix": f"Avoid using {func} or strictly validate inputs.",
                        "autofix": "Yes",
                        "line": lineno
                    })

        # 3. 🧬 SQL Injection pattern
        if re.search(r'(SELECT|INSERT|UPDATE|DELETE).*?(f["\']|["\']\s*\+)', line, re.I):
            findings.append({
                "vuln": "SQL Injection",
                "category": "OWASP A01 / CWE-89",
                "severity": "High",
                "fix": "Use parameterized queries or ORM to prevent SQL injection.",
                "autofix": "No",
                "line": lineno
            })

        # 4. 🦠 Cross-Site Scripting (XSS)
        if re.search(r'(print|return|render|display)\s*\([^)]*[<>"\';&]', line, re.I):
            findings.append({
                "vuln": "Cross-Site Scripting (XSS)",
                "category": "OWASP A06 / CWE-79",
                "severity": "Medium",
                "fix": "Sanitize and escape user input in output functions.",
                "autofix": "Yes",
                "line": lineno
            })

        # 5. 📁 Insecure File Write
        if re.search(r'open\s*\([^)]+,\s*[\'"]w[\'"]\)', line):
            findings.append({
                "vuln": "Insecure File Write",
                "category": "CWE-22",
                "severity": "Medium",
                "fix": "Validate file paths and use secure file access methods.",
                "autofix": "No",
                "line": lineno
            })

        # ✅ ADDITIONS BELOW (for 5 extra categories)

        # 1. Web Frontend Security – Detect XSS (naive render/return of user input)
        if re.search(r'return\s+f?["\']<.*{.*}.*>', line, re.I) or re.search(r'return\s+f?["\'].*<script>', line, re.I):
            findings.append({
                "vuln": "Cross-Site Scripting (XSS)",
                "category": "OWASP A06 / CWE-79 / SANS-14",
                "severity": "Medium",
                "fix": "Sanitize and escape user input in output functions.",
                "autofix": "Yes",
                "line": lineno
            })

        # API & Web Service - CORS misconfiguration
        if re.search(r'\bCORS\s*\(\s*app\s*\)', line):
            findings.append({
                "vuln": "CORS Global Enablement",
                "category": "OWASP A02 / CWE-346 / SANS-15",
                "severity": "High",
                "fix": "Restrict CORS to allowed origins (e.g., localhost or specific domains).",
                "autofix": "No",
                "line": lineno
            })

          # 3. File Handling – Detect path traversal risk in send_file or open
        if re.search(r'send_file\s*\(\s*f?[\'"].*?\{.*?\}', line) or re.search(r'open\s*\(\s*f?[\'"].*?\{.*?\}', line):
            findings.append({
                "vuln": "Path Traversal via File Input",
                "category": "OWASP A05 / CWE-22 / SANS-03",
                "severity": "High",
                "fix": "Validate or sanitize file path inputs using allowlists.",
                "autofix": "No",
                "line": lineno
            })

        # 4. Authentication – Hardcoded credentials
        if re.search(r'(username|user|login|email|password)\s*=\s*[\'"].+[\'"]', line, re.I):
            findings.append({
                "vuln": "Hardcoded Secrets",
                "category": "SANS-09 / CWE-798 / OWASP A07",
                "severity": "High",
                "fix": "Move secrets to environment variables or secret management tools.",
                "autofix": "Yes",
                "line": lineno
            })

        # 5. Data Protection – Logging or writing sensitive info in plain text
        if re.search(r'f\.write\(\s*f?["\'].*password.*["\']', line, re.I):
            findings.append({
                "vuln": "Sensitive Data Logged",
                "category": "OWASP A09 / CWE-532 / SANS-02",
                "severity": "High",
                "fix": "Use secure hashing (bcrypt/argon2) before storage. Avoid plain text.",
                "autofix": "Yes",
                "line": lineno
            })

    return findings



def calculate_security_score(issues):
    score = 100
    for issue in issues:
        severity = issue.get("severity", "").lower()
        if severity == "high":
            score -= 30
        elif severity == "medium":
            score -= 15
        elif severity == "low":
            score -= 5
    return max(score, 0)

from rich.syntax import Syntax

def show_rich_report_with_snippet(results, file_path, code_lines):
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    console = Console()
    console.print(f"\n[bold cyan]📄 Report for {file_path}[/bold cyan]\n")

    if not results:
        console.print("[green]✅ No issues found in this file.[/green]")
        return

    table = Table(title="LLM + Static Vulnerability Summary")
    table.add_column("Line", justify="right")
    table.add_column("Vulnerability", style="bold red")
    table.add_column("Category", style="yellow")
    table.add_column("Severity", style="magenta")
    table.add_column("Fix", style="green", width=50)
    table.add_column("Auto Fix", justify="center")

    for issue in results:
        line = str(issue.get("line", "-"))
        table.add_row(
            line,
            issue['vuln'],
            issue['category'],
            issue['severity'],
            issue['fix'],
            issue['autofix']
        )
    console.print(table)

    # Show snippets for LLM-detected issues
    for issue in results:
        if 'line' in issue:
            line_no = issue['line']
            start = max(0, line_no - 3)
            end = min(len(code_lines), line_no + 2)
            snippet = "\n".join(code_lines[start:end])
            console.print(
                Panel(
                    Syntax(snippet, "python", line_numbers=True, start_line=start + 1),
                    title=f"[bold]🔎 {issue['vuln']} (Line {line_no})[/bold]",
                    subtitle=issue['fix'],
                    expand=False,
                    border_style="red"
                )
            )

def validate_path(file_path, base_dir):
    """Sanitize and validate file path to prevent path traversal."""
    base_path = pathlib.Path(base_dir).resolve()
    file_path = pathlib.Path(file_path).resolve()
    if base_path not in file_path.parents and base_path != file_path:
        raise ValueError(f"Path {file_path} is outside of allowed directory {base_path}")
    return file_path

def analyze_file(file_path, base_dir):
    logging.info(f"Scanning file: {file_path}")
    try:
        file_path = validate_path(file_path, base_dir)
        code = load_code(file_path)
        if not code:
            return {"file": str(file_path), "score": 0, "issues": []}
        lang = detect_language(file_path)
        llm_results = []
        try:
            llm_response = run_optgpt_analysis(code, lang)
            llm_results = parse_response(llm_response)
            if not llm_results:
                logging.warning(f"No valid vulnerabilities found in LLM response for {file_path}")
        except requests.exceptions.RequestException as e:
            logging.warning(f"⚠️ LLM analysis skipped for {file_path}: {e}")
        static_results = scan_static_patterns(code, lang)
        combined = llm_results + static_results
        code_lines = code.splitlines()
        show_rich_report_with_snippet(combined, file_path, code_lines)

        return {
            "file": str(file_path),
            "score": calculate_security_score(combined),
            "issues": combined
        }
    except Exception as e:
        logging.error(f"Analysis failed for {file_path}: {e}")
        return {
            "file": str(file_path),
            "score": 0,
            "issues": []
        }

def scan_directory(path):
    results = []
    base_dir = os.path.abspath(path)
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for root, _, files in os.walk(base_dir):
            if any(ign in root for ign in IGNORE_PATTERNS):
                continue
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in LANG_MAP:
                    full_path = os.path.join(root, file)
                    futures.append(executor.submit(analyze_file, full_path, base_dir))
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
    return results

def write_report(results):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs("secure_reports", exist_ok=True, mode=0o700)
    json_file = pathlib.Path(f"secure_reports/combined_owasp_report_{timestamp}.json").resolve()
    html_file = pathlib.Path(f"secure_reports/combined_security_report_{timestamp}.html").resolve()

    with open(json_file, 'w', encoding='utf-8') as f:
        os.chmod(json_file, 0o600)
        json.dump(results, f, indent=2)

    with open(html_file, 'w', encoding='utf-8') as f:
        os.chmod(html_file, 0o600)
        f.write("<html><head><title>Security Report</title><style>table,th,td{border:1px solid black;border-collapse:collapse;padding:5px}</style></head><body>")
        f.write(f"<h2>Security Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h2>")
        for item in results:
            f.write(f"<h3>File: {item['file']}</h3>")
            f.write(f"<p>Security Score: {item['score']}/100</p>")
            if not item['issues']:
                f.write("<p>No issues found.</p>")
                continue
            f.write("<table><tr><th>Line</th><th>Vulnerability</th><th>Category</th><th>Severity</th><th>Fix</th><th>Auto Fix</th></tr>")
            for issue in item['issues']:
                f.write(
                    f"<tr><td>{issue.get('line', '-')}</td><td>{issue['vuln']}</td><td>{issue['category']}</td>"
                    f"<td>{issue['severity']}</td><td>{issue['fix']}</td><td>{issue['autofix']}</td></tr>"
                )

            f.write("</table><br>")
        f.write("</body></html>")
        console.print(f"\n✅ [green]Combined report saved to:[/green] {json_file}, {html_file}")
        generate_global_summary(results, timestamp)


def generate_global_summary(results, timestamp):
    summary = {
        "total_files_scanned": len(results),
        "total_issues_found": 0,
        "unique_vulnerability_types": 0,
        "vulnerability_breakdown": {},
        "severity_counts": {
            "High": 0,
            "Medium": 0,
            "Low": 0
        },
        "auto_fixable": {
            "Yes": 0,
            "No": 0
        },
        "files_with_most_issues": []
    }

    issue_counter = {}
    file_issue_count = {}

    for item in results:
        issues = item.get("issues", [])
        summary["total_issues_found"] += len(issues)

        file_issue_count[item["file"]] = len(issues)

        for issue in issues:
            vuln_name = issue.get("vuln", "Unknown")
            severity = issue.get("severity", "Unknown")
            autofix = issue.get("autofix", "No")

            issue_counter[vuln_name] = issue_counter.get(vuln_name, 0) + 1

            if severity in summary["severity_counts"]:
                summary["severity_counts"][severity] += 1

            if autofix in summary["auto_fixable"]:
                summary["auto_fixable"][autofix] += 1

    summary["vulnerability_breakdown"] = dict(sorted(issue_counter.items(), key=lambda x: x[1], reverse=True))
    summary["unique_vulnerability_types"] = len(issue_counter)

    top_files = sorted(file_issue_count.items(), key=lambda x: x[1], reverse=True)[:5]
    summary["files_with_most_issues"] = [{"file": f, "issues": c} for f, c in top_files]

    summary_path = pathlib.Path(f"secure_reports/global_summary_{timestamp}.json").resolve()
    with open(summary_path, "w", encoding="utf-8") as f:
        os.chmod(summary_path, 0o600)
        json.dump(summary, f, indent=2)

    console.print(f"\n📊 [cyan]Global summary saved to:[/cyan] {summary_path}")


    

def test_api():
    """Test OptGPT API connectivity."""
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {API_KEY}" if API_KEY else None
        }
        headers = {k: v for k, v in headers.items() if v is not None}
        payload = {"model": "optgpt:7b", "prompt": "Test", "stream": True}
        response = requests.post(API_URL, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        logging.info(f"API test response: {response.status_code} - {response.text}")
        console.print(f"[green]API test: Status {response.status_code}[/green]")
    except requests.exceptions.RequestException as e:
        logging.error(f"API test failed: {e}")
        console.print(f"[red]API test failed: {e}[/red]")

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="Path to file or folder")
    parser.add_argument("--test-api", action="store_true", help="Test API connectivity")
    args = parser.parse_args()

    if args.test_api:
        test_api()
        return

    path = os.path.normpath(os.path.abspath(args.path))
    if not os.path.exists(path):
        logging.error(f"Path not found: {path}")
        console.print(f"[red]❌ Path does not exist: {path}[/red]")
        return

    if os.path.isfile(path):
        results = [analyze_file(path, os.path.dirname(path))]
    else:
        results = scan_directory(path)

    write_report(results)

if __name__ == "__main__":
    main()