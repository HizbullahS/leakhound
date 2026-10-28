import math
import re

PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "GitHub Personal Access Token": r"ghp_[a-zA-Z0-9]{36}",
    "Slack Webhook URL": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "Private Key Block": r"-----BEGIN (?:RSA|EC|OPENSSH|DSA)? ?PRIVATE KEY-----",
    "Generic Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9_\-\.=:_+/]{20,}",
}

def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy value of an input string."""
    if not data:
        return 0.0
    entropy = 0.0
    for char in set(data):
        prob = data.count(char) / len(data)
        entropy -= prob * math.log2(prob)
    return entropy

def scan_text(content: str, entropy_threshold: float = 4.3):
    """Scans raw file lines for pattern matches and high-entropy sequences."""
    findings = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        # 1. Regex Match
        for rule_name, pattern in PATTERNS.items():
            if re.search(pattern, line):
                findings.append({
                    "line": line_num,
                    "type": rule_name,
                    "preview": line.strip()[:60]
                })

        # 2. High-Entropy String Extraction
        tokens = re.findall(r"[a-zA-Z0-9_\-+=/]{24,}", line)
        for token in tokens:
            if calculate_shannon_entropy(token) > entropy_threshold:
                findings.append({
                    "line": line_num,
                    "type": "High-Entropy Secret",
                    "preview": f"{token[:8]}...{token[-4:]}"
                })

    return findings
