import re
rules = [
    {
        "name": "Missing CSRF Token",
        "pattern": re.compile(r"<form(?!.*csrf_token).*?>", re.IGNORECASE),
        "category": "OWASP A05 / CWE-352",
        "severity": "Medium",
        "fix": "Add CSRF tokens to forms.",
        "autofix": "No",
    }
]