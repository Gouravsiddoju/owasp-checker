import re
rules = [
    {
        "name": "Exposed Debug Mode",
        "pattern": re.compile(r"DEBUG\s*=\s*True", re.IGNORECASE),
        "category": "OWASP A06 / CWE-489",
        "severity": "High",
        "fix": "Disable debug mode in production.",
        "autofix": "Yes",
    }
]