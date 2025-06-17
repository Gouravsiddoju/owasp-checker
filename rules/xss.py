import re
rules = [
    {
        "name": "Reflected XSS",
        "pattern": re.compile(r"document\.write\(|innerHTML\s*=", re.IGNORECASE),
        "category": "OWASP A03 / CWE-79",
        "severity": "High",
        "fix": "Escape and sanitize user inputs before rendering.",
        "autofix": "No",
    }
]