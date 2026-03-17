"""
Attacker Fingerprinting Engine
- Tracks per-IP scan patterns, timing, tool signatures
- Lightweight and non-blocking; never holds locks during heavy computation
"""

import time
import threading
from collections import defaultdict, deque


class FingerprintEngine:
    """
    Analyzes per-IP behavior to fingerprint scan tools (nmap, masscan, etc.)
    and build attacker profiles for the threat engine.
    """

    TOOL_SIGNATURES = {
        "MASSCAN":   {"rate_min": 200, "sequential": False, "random": True},
        "NMAP_FAST": {"rate_min": 50,  "sequential": True,  "random": False},
        "NMAP_SLOW": {"rate_min": 1,   "sequential": True,  "random": False},
        "ZMAP":      {"rate_min": 500, "sequential": False, "random": True},
        "MANUAL":    {"rate_min": 0,   "sequential": False, "random": False},
    }

    def __init__(self):
        self._profiles = defaultdict(lambda: {
            "port_history":  deque(maxlen=200),  # (timestamp, port)
            "first_seen":    None,
            "last_seen":     None,
            "packet_count":  0,
            "tool_guess":    "UNKNOWN",
            "scan_pattern":  "NONE",
        })
        self._lock = threading.RLock()  # RLock: allows nested acquisition → no deadlock in get_all_profiles

    def process_network_event(self, src_ip: str, dst_port: int, timestamp: float):
        """Process a single packet event. Non-blocking fast path."""
        with self._lock:
            p = self._profiles[src_ip]
            if p["first_seen"] is None:
                p["first_seen"] = timestamp
            p["last_seen"] = timestamp
            p["packet_count"] += 1
            if dst_port:
                p["port_history"].append((timestamp, dst_port))

            # Only fingerprint every 50 packets to avoid CPU overhead
            if p["packet_count"] % 50 == 0:
                self._classify(src_ip, p)

    def _classify(self, ip: str, profile: dict):
        """Classify attacker tool based on observed scan pattern."""
        ports = [port for _, port in profile["port_history"]]
        if len(ports) < 5:
            return

        # Check sequential pattern
        sorted_ports = sorted(set(ports))
        sequential_pairs = sum(
            1 for i in range(1, len(sorted_ports))
            if sorted_ports[i] - sorted_ports[i - 1] <= 2
        )
        is_sequential = sequential_pairs >= len(sorted_ports) * 0.6

        # Calculate scan rate (ports/sec)
        history = list(profile["port_history"])
        if len(history) >= 2:
            elapsed = history[-1][0] - history[0][0]
            rate = len(history) / elapsed if elapsed > 0 else 0
        else:
            rate = 0

        # NOTE: Order matters: check highest rates first
        if rate >= 500:
            profile["tool_guess"]  = "ZMAP"
            profile["scan_pattern"] = "ULTRA_FAST"
        elif rate >= 200:
            profile["tool_guess"]  = "MASSCAN"
            profile["scan_pattern"] = "AGGRESSIVE_RANDOM"
        elif rate >= 50 and is_sequential:
            profile["tool_guess"]  = "NMAP_FAST"
            profile["scan_pattern"] = "AGGRESSIVE_SEQUENTIAL"
        elif rate >= 1 and is_sequential:
            profile["tool_guess"]  = "NMAP_SLOW"
            profile["scan_pattern"] = "SEQUENTIAL"
        else:
            profile["tool_guess"]  = "MANUAL"
            profile["scan_pattern"] = "STEALTHY"

    def get_profile(self, ip: str) -> dict:
        with self._lock:
            p = self._profiles.get(ip)
            if not p:
                return {}
            return {
                "source_ip":       ip,
                "first_seen":      p["first_seen"],
                "last_seen":       p["last_seen"],
                "packet_count":    p["packet_count"],
                "tool_guess":      p["tool_guess"],
                "scan_pattern":    p["scan_pattern"],
                "preferred_ports": list({port for _, port in p["port_history"]})[:10],
            }

    def get_all_profiles(self) -> list:
        with self._lock:
            return [
                self.get_profile(ip)
                for ip in list(self._profiles.keys())
            ]


# Global singleton
fingerprint_engine = FingerprintEngine()
