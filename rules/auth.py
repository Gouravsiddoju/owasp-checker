import re
rules = [
    {
        "name": "Hardcoded Credentials",
        "pattern": re.compile(r"(password|secret|token)\s*=\s*['\"]+.+['\"]+", re.IGNORECASE),
        "category": "OWASP A02 / CWE-798",
        "severity": "High",
        "fix": "Use environment variables or a secrets manager.",
        "autofix": "Yes",
    }
]