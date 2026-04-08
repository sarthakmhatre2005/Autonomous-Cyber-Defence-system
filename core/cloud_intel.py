"""
Lightweight cloud / CDN IPv4 hints (best-effort, not exhaustive).
Used to downgrade benign high-volume traffic from known providers.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

# Curated public prefixes commonly associated with major clouds/CDNs.
# Not a complete list; avoids false confidence on "not listed" = not cloud.
_CLOUD_CIDRS: tuple[tuple[ipaddress.IPv4Network, str], ...] = (
    # Cloudflare (published IPv4)
    (ipaddress.ip_network("173.245.48.0/20"), "CLOUDFLARE"),
    (ipaddress.ip_network("103.21.244.0/22"), "CLOUDFLARE"),
    (ipaddress.ip_network("103.22.200.0/22"), "CLOUDFLARE"),
    (ipaddress.ip_network("103.31.4.0/22"), "CLOUDFLARE"),
    (ipaddress.ip_network("141.101.64.0/18"), "CLOUDFLARE"),
    (ipaddress.ip_network("108.162.192.0/18"), "CLOUDFLARE"),
    (ipaddress.ip_network("190.93.240.0/20"), "CLOUDFLARE"),
    (ipaddress.ip_network("188.114.96.0/20"), "CLOUDFLARE"),
    (ipaddress.ip_network("197.234.240.0/22"), "CLOUDFLARE"),
    (ipaddress.ip_network("198.41.128.0/17"), "CLOUDFLARE"),
    (ipaddress.ip_network("162.158.0.0/15"), "CLOUDFLARE"),
    (ipaddress.ip_network("104.16.0.0/13"), "CLOUDFLARE"),
    (ipaddress.ip_network("104.24.0.0/14"), "CLOUDFLARE"),
    (ipaddress.ip_network("172.64.0.0/13"), "CLOUDFLARE"),
    (ipaddress.ip_network("131.0.72.0/22"), "CLOUDFLARE"),
    # Google (sample of well-known GCP / Google edge)
    (ipaddress.ip_network("34.64.0.0/10"), "GOOGLE"),
    (ipaddress.ip_network("35.184.0.0/13"), "GOOGLE"),
    (ipaddress.ip_network("35.192.0.0/12"), "GOOGLE"),
    (ipaddress.ip_network("142.250.0.0/15"), "GOOGLE"),
    # AWS (common published ranges — subset)
    (ipaddress.ip_network("3.0.0.0/9"), "AWS"),
    (ipaddress.ip_network("13.32.0.0/11"), "AWS"),
    (ipaddress.ip_network("18.128.0.0/9"), "AWS"),
    (ipaddress.ip_network("52.0.0.0/11"), "AWS"),
    (ipaddress.ip_network("54.64.0.0/11"), "AWS"),
)


@lru_cache(maxsize=4096)
def cloud_provider_hint(ip: str) -> str | None:
    """Return 'AWS' | 'GOOGLE' | 'CLOUDFLARE' | None if not matched."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return None
    except ValueError:
        return None
    for net, name in _CLOUD_CIDRS:
        if addr in net:
            return name
    return None


def is_likely_cloud_or_cdn(ip: str) -> bool:
    return cloud_provider_hint(ip) is not None
