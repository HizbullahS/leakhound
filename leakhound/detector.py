import math
import re
from collections import Counter

PATTERNS = {
    "AWS Access Key": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "GitHub Personal Access Token": r"ghp_[a-zA-Z0-9]{36}",
    "GitHub Fine-Grained Token": r"github_pat_[a-zA-Z0-9_]{22,}",
    "Slack Webhook URL": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "Private Key Block": r"-----BEGIN (?:(?:RSA|EC|OPENSSH|DSA|ENCRYPTED) )?PRIVATE KEY-----",
    "Generic Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9_\-\.=:_+/]{20,}",
}
COMPILED_PATTERNS = {name: re.compile(pattern) for name, pattern in PATTERNS.items()}
TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9_\-+=/]{24,}")

def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy value of an input string."""
    if not data:
        return 0.0
    entropy = 0.0
    for count in Counter(data).values():
        prob = count / len(data)
        entropy -= prob * math.log2(prob)
    return entropy

def scan_text(content: str, entropy_threshold: float = 4.3):
    """Scans raw file lines for pattern matches and high-entropy sequences."""
    findings = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        matched_spans = []
        for rule_name, pattern in COMPILED_PATTERNS.items():
            for match in pattern.finditer(line):
                matched_spans.append(match.span())
                findings.append({
                    "line": line_num,
                    "type": rule_name,
                    "preview": "[REDACTED]"
                })

        # 2. High-Entropy String Extraction
        for match in TOKEN_PATTERN.finditer(line):
            if any(match.start() < end and match.end() > start for start, end in matched_spans):
                continue
            token = match.group()
            if calculate_shannon_entropy(token) > entropy_threshold:
                findings.append({
                    "line": line_num,
                    "type": "High-Entropy Secret",
                    "preview": "[REDACTED]"
                })

    return findings
