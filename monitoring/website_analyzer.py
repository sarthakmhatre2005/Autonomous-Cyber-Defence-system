import re
import math
import ipaddress
from collections import Counter

# High-risk keywords used in phishing/malicious domains
PHISHING_KEYWORDS = [
    "login", "secure", "verify", "update", "banking", "account", "signin", 
    "support", "official", "billing", "confirm", "wallet", "crypto", "security",
    "password", "auth", "validate", "credential", "pay", "invoice", "gift",
    "malicious", "virus", "exploit", "hacker", "payload", "c2", "cnc", "botnet"
]

# Common safe domains to reduce false positives
WHITELIST = ["google.com", "bing.com", "github.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com", "twitter.com"]


def is_noise_domain(domain):
    if not domain:
        return True

    domain = str(domain).strip().lower().rstrip(".")

    # Reverse DNS
    if domain.endswith(".in-addr.arpa"):
        return True

    # Local network / multicast
    if domain.endswith(".local"):
        return True

    # System / internal patterns
    if "_udp." in domain or "_tcp." in domain:
        return True

    # Empty / malformed
    if domain == "unknown" or len(domain) < 4:
        return True

    # IP literals or host:port should not be treated as suspicious DNS domains.
    host = domain
    if ":" in host and host.count(":") == 1:
        left, right = host.rsplit(":", 1)
        if right.isdigit():
            host = left
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    return False

class WebsiteAnalyzer:
    def __init__(self):
        # Compiled regex for common malicious patterns
        self.ip_in_domain = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

    def calculate_entropy(self, domain):
        """Calculates Shannon entropy of a string to detect randomized dGA domains."""
        if not domain:
            return 0
        # Only check the SLD (second level domain) to avoid TLD bias
        parts = domain.split('.')
        sld = parts[-2] if len(parts) >= 2 else domain
        probs = [n/len(sld) for n in Counter(sld).values()]
        return -sum(p * math.log2(p) for p in probs)

    def analyze_domain(self, domain):
        """
        Analyzes a domain for suspicious patterns.
        Returns (threat_score, reasons)
        """
        if is_noise_domain(domain):
            return 0, []
        domain_lower = domain.lower()
        if any(white in domain_lower for white in WHITELIST):
            return 0, []

        score = 0
        reasons = []

        # 1. Keyword Check
        for kw in PHISHING_KEYWORDS:
            if kw in domain_lower:
                score += 4 # Increased weight
                reasons.append(f"Contains keyword: {kw}")

        # 2. Randomness Check (Entropy)
        # Reduced threshold slightly for more aggressive DGA detection
        entropy = self.calculate_entropy(domain_lower)
        if entropy > 3.6:
            score += 4
            reasons.append(f"High randomness (Entropy: {entropy:.2f})")

        # 3. Structural Heuristics
        # IP Address in domain
        if self.ip_in_domain.search(domain):
            score += 7
            reasons.append("IP address in domain")

        # Long domains
        if len(domain) > 40: # Lowered from 50
            score += 2
            reasons.append("Excessive length")

        # Excessive numbers
        num_count = sum(c.isdigit() for c in domain)
        if num_count > 4: # Lowered from 5
            score += 3
            reasons.append(f"High number count ({num_count})")

        # Excessive hyphens
        if domain.count('-') > 2:
            score += 2
            reasons.append(f"Excessive hyphens ({domain.count('-')})")

        # Unusual TLDs
        malicious_tlds = [
            ".xyz", ".top", ".pw", ".bid", ".icu", ".online", ".ga", ".ml", ".tk", ".cf", ".gq",
            ".download", ".review", ".zip", ".mov"
        ]
        if any(domain_lower.endswith(tld) for tld in malicious_tlds):
            score += 5 # Increased weight
            reasons.append("Suspicious TLD")

        return min(score, 10), reasons

website_analyzer = WebsiteAnalyzer()
