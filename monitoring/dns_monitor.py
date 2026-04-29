"""
DNS Monitor — Windows DNS Cache Harvester
==========================================
Supplements the Scapy UDP-53 capture by reading the Windows DNS resolver
cache via `ipconfig /displaydns` every few seconds.

This catches domains that Scapy misses:
  • DNS over HTTPS (DoH) — Chrome, Edge, Firefox, Windows 11 default
  • Browser prefetch / speculative DNS
  • Domains resolved from cache (no UDP 53 packet emitted)
  • System-level DNS calls made by any process

The monitor is read-only and requires no elevated privileges.
"""

import subprocess
import threading
import time
import re
import ipaddress

_POLL_INTERVAL_SEC = 5          # how often to query Windows DNS cache
_SEEN_DOMAINS: dict = {}        # domain -> last_logged_ts (dedup)
_DEDUP_SEC = 30                 # same domain logged at most once per 30s
_LOCK = threading.Lock()

_NOISE_SUFFIXES = (
    ".arpa", ".local", ".internal", ".corp",
    "wpad", "isatap", "_tcp", "_udp",
)
_NOISE_PREFIXES = ("_", "isatap", "wpad")

def _is_noise(domain: str) -> bool:
    d = (domain or "").lower().strip().rstrip(".")
    if not d or len(d) < 4:
        return True
    for s in _NOISE_SUFFIXES:
        if d.endswith(s):
            return True
    for p in _NOISE_PREFIXES:
        if d.startswith(p):
            return True
    # filter bare IPs
    try:
        ipaddress.ip_address(d)
        return True
    except ValueError:
        pass
    return False


def _parse_ipconfig_dns(output: str) -> list[str]:
    """
    Parse `ipconfig /displaydns` output and extract unique hostnames.
    Each record block starts with the hostname on its own line.
    """
    domains = set()
    # Line format: "    google.com"  or  "    Record Name . . . . . : google.com"
    record_name_re = re.compile(r"Record Name\s*\.+\s*:\s*(.+)", re.IGNORECASE)
    standalone_re  = re.compile(r"^    ([a-zA-Z0-9][\w\-\.]{2,})\s*$")

    for line in output.splitlines():
        m = record_name_re.search(line)
        if m:
            d = m.group(1).strip().rstrip(".")
            if d:
                domains.add(d)
            continue
        m = standalone_re.match(line)
        if m:
            d = m.group(1).strip().rstrip(".")
            if d:
                domains.add(d)

    return list(domains)


def _get_dns_cache_domains() -> list[str]:
    """Run ipconfig /displaydns and return parsed domain list."""
    try:
        result = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True, text=True,
            timeout=8, creationflags=0x08000000  # CREATE_NO_WINDOW
        )
        raw = result.stdout or ""
        return _parse_ipconfig_dns(raw)
    except Exception:
        return []


def _requesting_ip() -> str:
    """Best-effort: return local machine's outbound IP."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _monitor_loop():
    """Background loop: poll DNS cache, log new domains."""
    from monitoring.website_analyzer import website_analyzer, is_noise_domain
    from data.database import log_dns_query

    local_ip = _requesting_ip()
    # refresh local IP occasionally
    last_ip_refresh = time.time()

    while True:
        try:
            now = time.time()

            # Refresh local IP every 5 minutes
            if now - last_ip_refresh > 300:
                local_ip = _requesting_ip()
                last_ip_refresh = now

            domains = _get_dns_cache_domains()

            for domain in domains:
                d = domain.lower().strip().rstrip(".")
                if not d:
                    continue
                if _is_noise(d):
                    continue
                if is_noise_domain(d):
                    continue

                with _LOCK:
                    last_seen = _SEEN_DOMAINS.get(d, 0)
                    if now - last_seen < _DEDUP_SEC:
                        continue
                    _SEEN_DOMAINS[d] = now

                # Analyze domain threat (cached inside website_analyzer)
                try:
                    threat_score, reasons = website_analyzer.analyze_domain(d)
                except Exception:
                    threat_score, reasons = 0, []

                # Log to database
                try:
                    log_dns_query(d, local_ip, threat_score, "dns_cache_monitor")
                except Exception:
                    pass

                # If high threat, also push alert through threat engine
                if threat_score >= 4:
                    try:
                        from core.threat_engine import threat_engine
                        alert = {
                            "type": "DNS_THREAT",
                            "severity": "HIGH" if threat_score >= 7 else "MEDIUM",
                            "score": threat_score,
                            "detail": f"Suspicious DNS: {d} ({', '.join(reasons)})",
                            "reason": f"Suspicious DNS: {d} ({', '.join(reasons)})",
                            "domain": d,
                            "ip": local_ip,
                            "src_ip": local_ip,
                            "dst_ip": "DNS_SERVER",
                            "dst_port": 53,
                            "protocol": "DNS",
                            "timestamp": now,
                            "process": "dns_cache_monitor",
                        }
                        threat_engine.process_alert(alert, None)
                    except Exception:
                        pass

        except Exception:
            pass

        time.sleep(_POLL_INTERVAL_SEC)

        # Trim seen-domains dict to prevent unbounded growth
        with _LOCK:
            if len(_SEEN_DOMAINS) > 5000:
                cutoff = time.time() - 120
                to_del = [k for k, v in _SEEN_DOMAINS.items() if v < cutoff]
                for k in to_del:
                    del _SEEN_DOMAINS[k]


def start_dns_monitor():
    """Start the DNS cache monitor in a background daemon thread."""
    t = threading.Thread(target=_monitor_loop, name="DNSCacheMonitor", daemon=True)
    t.start()
    print("[DNSMonitor] Windows DNS cache monitor started (polls every 5s).")
