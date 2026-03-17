import re
import math
from collections import Counter

# High-risk keywords used in phishing/malicious domains
PHISHING_KEYWORDS = [
    "login", "secure", "verify", "update", "banking", "account", "signin", 
    "support", "official", "billing", "confirm", "wallet", "crypto", "security",
    "password", "auth", "validate", "credential", "pay", "invoice", "gift"
]

# Common safe domains to reduce false positives
WHITELIST = ["google.com", "bing.com", "github.com", "microsoft.com", "apple.com", "amazon.com"]

class WebsiteAnalyzer:
    def __init__(self):
        pass

    def calculate_entropy(self, domain):
        """Calculates Shannon entropy of a string to detect randomized dGA domains."""
        if not domain:
            return 0
        probs = [n/len(domain) for n in Counter(domain).values()]
        return -sum(p * math.log2(p) for p in probs)

    def analyze_domain(self, domain):
        """
        Analyzes a domain for suspicious patterns.
        Returns (threat_score, reasons)
        """
        if any(white in domain.lower() for white in WHITELIST):
            return 0, []

        score = 0
        reasons = []

        # 1. Keyword Check
        for kw in PHISHING_KEYWORDS:
            if kw in domain.lower():
                score += 3
                reasons.append(f"Contains keyword: {kw}")

        # 2. Randomness Check (Entropy)
        # Higher entropy suggests random characters often used in malware C2 domains
        entropy = self.calculate_entropy(domain)
        if entropy > 3.8:
            score += 4
            reasons.append(f"High randomness (Entropy: {entropy:.2f})")

        # 3. Structural Heuristics
        # Long domains
        if len(domain) > 50:
            score += 2
            reasons.append("Excessive length")

        # Excessive numbers
        num_count = sum(c.isdigit() for c in domain)
        if num_count > 5:
            score += 2
            reasons.append(f"High number count ({num_count})")

        # Unusual TLDs
        malicious_tlds = [".xyz", ".top", ".top", ".pw", ".bid", ".icu", ".online"]
        if any(domain.lower().endswith(tld) for tld in malicious_tlds):
            score += 3
            reasons.append("Suspicious TLD")

        return min(score, 10), reasons

website_analyzer = WebsiteAnalyzer()
