import re
rules = [
    {
        "name": "Unrestricted File Upload",
        "pattern": re.compile(r"upload.*filename", re.IGNORECASE),
        "category": "OWASP A08 / CWE-434",
        "severity": "High",
        "fix": "Validate file extensions and scan for malware.",
        "autofix": "No",
    }
]