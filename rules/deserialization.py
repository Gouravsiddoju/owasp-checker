import re
rules = [
    {
        "name": "Insecure Deserialization",
        "pattern": re.compile(r"pickle\.load|yaml\.load", re.IGNORECASE),
        "category": "OWASP A08 / CWE-502",
        "severity": "High",
        "fix": "Use safe loading functions or validate inputs.",
        "autofix": "No",
    }
]