import re
rules = [
    {
        "name": "SQL Injection",
        "pattern": re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*?(f\"|\" \+)", re.IGNORECASE),
        "category": "OWASP A01 / CWE-89",
        "severity": "High",
        "fix": "Use parameterized queries to prevent SQL injection.",
        "autofix": "No",
    },
    {
        "name": "Command Injection",
        "pattern": re.compile(r"(os\\.system|subprocess\\.call|popen)", re.IGNORECASE),
        "category": "OWASP A01 / CWE-77",
        "severity": "High",
        "fix": "Avoid system calls with unsanitized input. Use safer APIs.",
        "autofix": "No",
    },
]