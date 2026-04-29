"""
Traffic Behavior Analyzer
- Processes packets from the capture layer
- Detects: port scans, connection bursts, brute force, traffic spikes
- Maintains per-IP behavioral profiles
- Feeds data into the Threat Scoring Engine
- OPTIMIZED: throttled logging, low-overhead hot-path, async worker pool
"""

import time
import threading
from collections import defaultdict, deque
from datetime import datetime
import queue

from monitoring.packet_capture import get_ip_type
from monitoring.website_analyzer import website_analyzer, is_noise_domain
from data.database import log_dns_query, log_event
from core.threat_engine import threat_engine
from core.fingerprint_engine import fingerprint_engine
from ml.ml_detector import ml_detector  # module-level singleton — do NOT use self.ml_detector

# ─── Per-IP throttle tables (avoid expensive ops on every identical packet) ───
_DNS_LOG_THROTTLE   = {}   # domain -> last_logged_time
_ML_CALL_THROTTLE   = {}   # src_ip -> last_ml_time
_DNS_THROTTLE_SEC   = 8    # re-log same domain at most every 8s (was 30s — missed sites)
_ML_THROTTLE_SEC    = 15.0 # Reduced frequency to lower noise (re-run ML per IP)
_FP_THROTTLE_SEC    = 0.25  # fingerprint_engine: throttle hot path
_STATS_SKIP_SEC     = 0.06  # skip heavy detection if same IP analyzed recently (non-DNS)
FAST_SAMPLE_N       = 6     # on fast path, run full detection every Nth packet


# ─── IP Behavior Profile ──────────────────────────────────────────────────────

class IPProfile:
    """Tracks behavioral history for a single IP address."""

    def __init__(self, ip):
        self.ip = ip
        self.ip_type = "UNKNOWN"
        self._lock = threading.Lock()

        # Packet history (sliding window, 60s)
        self.packet_times = deque(maxlen=500)   # timestamps (smaller = faster scans)
        self.ports_contacted = set()              # all unique ports touched
        self.port_timeline = deque(maxlen=200)    # (timestamp, port) pairs
        self.protocols_seen = set()

        # Connection tracking
        self.connection_count = 0
        self.total_bytes = 0
        self.failed_attempts = 0   # RST/rejected connections

        # Burst tracking
        self.burst_windows = deque(maxlen=50)     # (window_start, count)

        # Reputation score (0=clean, 100=malicious)
        self.reputation_score = 0.0
        self.threat_score = 0                     # Integer score per scoring engine
        self.threat_tags = []                     # e.g. ["PORT_SCAN", "BRUTE_FORCE"]

        # Timestamps
        self.first_seen = time.time()
        self.last_seen = time.time()

        # Behavior flags
        self.is_scanning = False
        self.is_bursting = False
        self.is_brute_forcing = False

        # Incremental stats for fast access
        self._packet_count_10s = 0
        self._packet_count_60s = 0
        self._recent_ports = defaultdict(int) # port -> count in current window
        self._last_cleanup = time.time()

    def record_packet(self, meta):
        """Record packet data. Optimized to minimize lock duration."""
        now = meta.get("timestamp", time.time())
        payload = meta.get("payload_size", 0)
        port = meta.get("dst_port")
        proto = meta.get("protocol")
        ip_type = meta.get("ip_type")

        with self._lock:
            self.packet_times.append(now)
            self.last_seen = now
            self.connection_count += 1
            self.total_bytes += payload
            if ip_type:
                self.ip_type = ip_type

            if port:
                self.ports_contacted.add(port)
                self.port_timeline.append((now, port))
                self._recent_ports[port] += 1
            
            if proto:
                self.protocols_seen.add(proto)
            
            # Periodic cleanup (every 10s instead of 5s to reduce lock pressure)
            if now - self._last_cleanup > 10:
                self._cleanup_incremental(now)

    def _cleanup_incremental(self, now):
        """Purge old entries from timeline to keep stats accurate."""
        cutoff_60 = now - 60
        
        # Clean port timeline - limit cleanup work per call
        count = 0
        while self.port_timeline and self.port_timeline[0][0] < cutoff_60 and count < 100:
            ts, port = self.port_timeline.popleft()
            self._recent_ports[port] -= 1
            if self._recent_ports[port] <= 0:
                del self._recent_ports[port]
            count += 1
        
        self._last_cleanup = now

    def get_packet_rate(self, window_sec=10):
        """Packets per second in last window_sec. Optimized for small windows."""
        with self._lock:
            now = time.time()
            # If window is recent, use the already filtered list
            cutoff = now - window_sec
            count = 0
            for i in range(len(self.packet_times) - 1, -1, -1):
                if self.packet_times[i] < cutoff:
                    break
                count += 1
            return count / window_sec if window_sec > 0 else 0

    def get_recent_port_count(self, window_sec=60):
        """Number of unique ports contacted in last window_sec. Optimized."""
        with self._lock:
            # Ensure cleanup is relatively fresh
            now = time.time()
            if now - self._last_cleanup > 1:
                self._cleanup_incremental(now)
            return len(self._recent_ports)

    def get_distinct_ports(self, window_sec=60):
        """Returns set of distinct ports in window. Optimized."""
        with self._lock:
            now = time.time()
            if now - self._last_cleanup > 1:
                self._cleanup_incremental(now)
            return set(self._recent_ports.keys())

    def to_dict(self):
        with self._lock:
            return {
                "ip": self.ip,
                "ip_type": self.ip_type,
                "connection_count": self.connection_count,
                "total_bytes": self.total_bytes,
                "unique_ports": len(self.ports_contacted),
                "recent_port_count": self.get_recent_port_count(),
                "protocols": list(self.protocols_seen),
                "threat_score": self.threat_score,
                "threat_tags": list(self.threat_tags),
                "reputation": round(self.reputation_score, 2),
                "first_seen": datetime.fromtimestamp(self.first_seen).isoformat(),
                "last_seen": datetime.fromtimestamp(self.last_seen).isoformat(),
                "is_scanning": self.is_scanning,
                "is_bursting": self.is_bursting,
                "is_brute_forcing": self.is_brute_forcing,
            }


# ─── Ports of Interest ────────────────────────────────────────────────────────

# Common brute-force targets
BRUTE_FORCE_PORTS = {22, 23, 3389, 5900, 21, 25, 110, 143, 445, 1433, 3306, 5432, 6379}

# High-risk ports
HIGH_RISK_PORTS = {
    4444, 1234, 31337, 12345, 54321,  # common malware/RAT ports
    8080, 8443, 8888,                  # common web shells
    6666, 6667, 6668, 6669,            # IRC (often C2)
    9001, 9030,                        # Tor
}

# Well-known safe ports (reduce noise)
SAFE_PORTS = {80, 443, 53, 123, 67, 68, 5353}

# Thresholds
SUSPICIOUS_THRESHOLD = 15


# ─── Traffic Analyzer ─────────────────────────────────────────────────────────

class TrafficAnalyzer:
    """
    Central traffic analysis engine.
    Processes packets → updates IP profiles → generates alerts.
    """

    def __init__(self):
        self.profiles = defaultdict(lambda: None)  # ip -> IPProfile
        self._lock = threading.Lock()

        # Global counters
        self.total_packets = 0
        self.external_packets = 0
        self.alert_queue = deque(maxlen=500)  # Alerts waiting to be acted on

        # Network baseline (for anomaly detection)
        self.baseline_rate = 0.0      # packets/sec average
        self._rate_samples = deque(maxlen=120)  # 2-min rolling baseline

        # IP -> (last_analysis_time, last_stats) cache to avoid lock contention
        self._stats_cache = {}
        self._stats_cache_lock = threading.Lock()

        # Async worker pool — fewer threads reduces lock contention on shared profiles
        self.num_workers = 10
        self.packet_queue = queue.Queue(maxsize=50000)
        self._workers = []
        for i in range(self.num_workers):
            t = threading.Thread(target=self._worker_loop, name=f"AnalyzerWorker-{i}", daemon=True)
            t.start()
            self._workers.append(t)

        # LRU cache for domain analysis to avoid repeated computation
        self._domain_cache = {}

        # Brute-force port attempt timeline per IP
        self.connection_attempts = defaultdict(lambda: deque(maxlen=150))

        # Last fingerprint update time per IP (throttle hot path)
        self._fp_last_ts = {}

        # Cache common objects (module-level singletons referenced directly)
        self.threat_engine = threat_engine
        self.website_analyzer = website_analyzer
        self.ml_detector = ml_detector  # explicitly bind so self.ml_detector works too

    def _worker_loop(self):
        while True:
            try:
                meta = self.packet_queue.get()
                if meta is None:
                    continue
                self._analyze_packet(meta)
            except Exception:
                pass

    def _get_or_create_profile(self, ip):
        """Optimized lookup: check without lock first."""
        profile = self.profiles.get(ip)
        if profile is not None:
            return profile

        with self._lock:
            # Re-check inside the lock (double-checked lock pattern)
            profile = self.profiles.get(ip)
            if profile is None:
                profile = IPProfile(ip)
                profile.ip_type = get_ip_type(ip)
                self.profiles[ip] = profile
            return profile

    def process_packet(self, meta):
        """Main entry point — enqueues the packet for async processing. Non-blocking."""
        try:
            self.packet_queue.put_nowait(meta)
        except queue.Full:
            pass  # Drop under extreme load — never block the capture thread

    def _analyze_packet(self, meta):
        """Internal processing function run by the worker thread."""
        src_ip = meta.get("src_ip", "")
        if not src_ip:
            return

        # ─── Process Correlation (Offloaded from capture thread) ───
        dst_port = meta.get("dst_port")
        src_port = meta.get("src_port")
        
        # Safety: Ignore local dashboard traffic (port 5000) to maximize throughput
        if dst_port == 5000 or src_port == 5000:
            return

        ip_type = get_ip_type(src_ip)

        if dst_port is not None or src_port is not None:
            from monitoring.packet_capture import get_process_for_packet
            proto = meta.get("protocol", "TCP")
            sip = src_ip
            dip = meta.get("dst_ip", "0.0.0.0")
            proc_name, pid = get_process_for_packet(proto, sip, src_port or 0, dip, dst_port or 0)
            meta["process"] = proc_name
            meta["pid"] = pid

        # ─── DNS Decoding (Offloaded from capture thread) ───
        dns_query = None
        if meta.get("has_dns") and meta.get("_dns_raw_qname"):
            try:
                dns_query = meta["_dns_raw_qname"].decode('utf-8').strip('.')
                meta["dns_query"] = dns_query
            except:
                pass

        meta["ip_type"] = ip_type

        # QUIC detection (UDP 443)
        if meta["protocol"] == "UDP" and (dst_port == 443 or src_port == 443):
            meta["protocol"] = "QUIC"

        # Update global packet store ring buffer (always — keeps UI packet stream continuous)
        from monitoring.packet_capture import packet_store
        packet_store.add(meta)

        profile = self._get_or_create_profile(src_ip)
        profile.record_packet(meta)

        self.total_packets += 1
        if ip_type == "EXTERNAL":
            self.external_packets += 1

        # Pure loopback: keep packets in store; skip threat / ML / fingerprint noise
        if ip_type == "LOOPBACK":
            return
        
        # ─── DNS Analysis (Decoding offloaded to worker) ───
        now = time.time()
        dns_query = None
        if meta.get("has_dns"):
            # If we had the raw packet we would decode here, 
            # but for now we'll assume the capture meta might have it or we skip if too expensive.
            # In our current scapy implementation, we'll try to get it if possible.
            dns_query = meta.get("dns_query")

        # ─── Attacker Fingerprinting (throttled — runs on every packet by default) ───
        try:
            last_fp = self._fp_last_ts.get(src_ip, 0.0)
            if now - last_fp >= _FP_THROTTLE_SEC:
                self._fp_last_ts[src_ip] = now
                fingerprint_engine.process_network_event(
                    src_ip, meta.get("dst_port", 0), meta.get("timestamp", now)
                )
        except Exception:
            pass

        alerts = []

        # ─── DNS Monitoring ── throttled: analyze domain but log only every 8s ───
        if dns_query:
            dns_query_clean = dns_query.lower().strip().rstrip(".")
            # Drop pure noise (reverse DNS, mDNS, etc.) but do NOT exit early —
            # fall through to behavioural analysis for non-DNS packets.
            if not is_noise_domain(dns_query_clean):
                if dns_query_clean in self._domain_cache:
                    threat_score, reasons = self._domain_cache[dns_query_clean]
                else:
                    threat_score, reasons = self.website_analyzer.analyze_domain(dns_query_clean)
                    if len(self._domain_cache) > 2000:
                        self._domain_cache.clear()
                    self._domain_cache[dns_query_clean] = (threat_score, reasons)

                # Throttle: only write to DB once per domain per 8s
                last_logged = _DNS_LOG_THROTTLE.get(dns_query_clean, 0)
                if now - last_logged >= _DNS_THROTTLE_SEC:
                    _DNS_LOG_THROTTLE[dns_query_clean] = now
                    proc_name = meta.get("process", "UNKNOWN")
                    # Log ALL domains — not just suspicious ones — for full DNS history
                    log_dns_query(dns_query_clean, src_ip, threat_score, proc_name)
                    if threat_score >= 1:
                        log_event(
                            src_ip=src_ip,
                            dest_ip="DNS_SERVER",
                            dst_port=53,
                            protocol="DNS",
                            severity="INFO",
                            anomaly_score=threat_score / 10.0,
                            active_window="NETWORK_DNS",
                            details={"domain": dns_query_clean, "threat_score": threat_score},
                            threat_score=int(threat_score)
                        )
                    # Prune throttle table periodically
                    if len(_DNS_LOG_THROTTLE) > 3000:
                        old = [k for k, v in _DNS_LOG_THROTTLE.items() if now - v > 120]
                        for k in old:
                            del _DNS_LOG_THROTTLE[k]

                if threat_score >= 4:
                    alerts.append({
                        "type": "DNS_THREAT",
                        "severity": "MEDIUM" if threat_score < 7 else "HIGH",
                        "score": threat_score,
                        "detail": f"Suspicious DNS: {dns_query_clean} ({', '.join(reasons)})",
                        "domain": dns_query_clean,
                        "timestamp": now,
                    })

        # ─── Behavioral Sampling & Stats Caching ───
        # For very high volume IPs, we don't need to re-run full behavioral analysis on every single packet.
        # This 10x speedup comes from skipping redundant behavior checks.
        
        should_analyze = True
        stats_cache_key = src_ip
        
        # Check mini-cache for recent stats and decision
        cached_info = self._stats_cache.get(src_ip)
        if cached_info:
            last_analysis, packet_rate, port_count, pkt_count = cached_info
            # If we analyzed this IP very recently (< 50ms) and it's not a DNS packet,
            # we can skip heavy analysis for most packets while still sampling regularly.
            if now - last_analysis < _STATS_SKIP_SEC and not meta.get("has_dns"):
                should_analyze = False
                self._stats_cache[src_ip] = (last_analysis, packet_rate, port_count, pkt_count + 1)
                if (pkt_count + 1) % FAST_SAMPLE_N == 0:
                    should_analyze = True
                if pkt_count > 50:
                    should_analyze = True

        if not should_analyze:
            return

        # ─── Real-time behavioral stats (once per analysis cycle) ───
        packet_rate_10s = profile.get_packet_rate(window_sec=10)
        port_count_60s = profile.get_recent_port_count(window_sec=60)
        
        # Update cache
        self._stats_cache[src_ip] = (now, packet_rate_10s, port_count_60s, 0)
        if len(self._stats_cache) > 5000: self._stats_cache.clear()

        # ─── ML Anomaly Detection ── throttled and sampled ────
        last_ml = _ML_CALL_THROTTLE.get(src_ip, 0)
        # Only run ML if enough time has passed AND we sample 1 in 5 packets to hit 10x throughput
        if now - last_ml >= _ML_THROTTLE_SEC:
            _ML_CALL_THROTTLE[src_ip] = now
            anomaly_score = self.ml_detector.predict_anomaly(profile, meta)
            # Increase threshold from 1.0 to 2.5 to avoid noise on minor traffic variations
            if anomaly_score >= 2.5:
                alerts.append({
                    "type": "ML_ANOMALY",
                    "severity": "MEDIUM" if anomaly_score < 6 else "HIGH",
                    "score": int(anomaly_score),
                    "detail": f"Behavioral Anomaly: Traffic pattern deviates from learned baseline (Score: {anomaly_score:.2f})",
                    "reason": f"Anomalous traffic profile detected. The packet sequence and timing match high-risk behavioral patterns associated with automated scanning or data exfiltration (Confidence: {min(anomaly_score/10, 0.99):.2f})",
                    "timestamp": now,
                })

        # ─── Detection Methods (Using optimized stats) ───
        detected_alerts = []
        detected_alerts += self._detect_port_scan(src_ip, profile, port_count_60s)
        detected_alerts += self._detect_connection_burst(src_ip, profile, packet_rate_10s, alerts)
        detected_alerts += self._detect_brute_force(src_ip, profile, meta)
        detected_alerts += self._detect_high_risk_port(src_ip, profile, meta)
        detected_alerts += self._detect_traffic_spike(src_ip, profile, meta)
        
        alerts += detected_alerts

        # --- Only log if there were actual alerts or anomalies ---
        if not alerts:
            return

        # Forward alerts to threat engine
        if alerts:
            ip_type = meta.get("ip_type", "UNKNOWN")
            for alert in alerts:
                alert["src_ip"] = src_ip
                alert["dst_ip"] = meta.get("dst_ip", "0.0.0.0")
                alert["dst_port"] = meta.get("dst_port", 0)
                alert["protocol"] = meta.get("protocol", "OTHER")
                alert["timestamp"] = now
                alert["ip"] = src_ip
                alert["ip_type"] = ip_type
                alert["process"] = meta.get("process") or "unknown process"
                
                self.alert_queue.append(alert)
                try:
                    self.threat_engine.process_alert(alert, profile)
                except Exception as e:
                    print(f"[TrafficAnalyzer] Error in process_alert: {e}")

    # ── Detection: Port Scan ──────────────────────────────────────────────────

    def _detect_port_scan(self, ip, profile, port_count):
        """
        Port scan detection:
        - Sequential or random port probing in short time window
        - Threshold: > 15 distinct ports in 60 seconds = port scan
        """
        alerts = []

        MIN_PORTS_THRESHOLD = 20   # unique ports
        WINDOW_SEC = 5             # short time window
        
        # We need to check if the 20 ports were hit within 5 seconds.
        # profile.get_distinct_ports(window_sec=5) should work.
        recent_ports_5s = profile.get_distinct_ports(window_sec=WINDOW_SEC)
        port_count_5s = len(recent_ports_5s)

        if port_count_5s >= MIN_PORTS_THRESHOLD and not profile.is_scanning:
            profile.is_scanning = True
            if "PORT_SCAN" not in profile.threat_tags:
                profile.threat_tags.append("PORT_SCAN")

            sorted_ports = sorted(recent_ports_5s)
            is_sequential = self._is_sequential(sorted_ports)
            scan_type = "SEQUENTIAL" if is_sequential else "RANDOM"

            alerts.append({
                "type": "PORT_SCAN",
                "subtype": scan_type,
                "severity": "HIGH",
                "score": 10,
                "detail": f"Port scan detected: {port_count_5s} ports accessed in {WINDOW_SEC} seconds",
                "reason": f"Port scan detected: {port_count_5s} ports accessed in {WINDOW_SEC} seconds",
                "ports_sample": sorted_ports[:10],
                "timestamp": time.time(),
            })

        elif port_count >= SUSPICIOUS_THRESHOLD and "SUSPICIOUS_PORTSCAN" not in profile.threat_tags:
            profile.threat_tags.append("SUSPICIOUS_PORTSCAN")
            alerts.append({
                "type": "SUSPICIOUS_PORTSCAN",
                "severity": "MEDIUM",
                "score": 2,
                "detail": f"Suspicious port probing: {port_count} distinct ports",
                "reason": f"IP has contacted {port_count} unique ports, exceeding the suspicious threshold (15). Possible reconnaissance.",
                "timestamp": time.time(),
            })

        # Reset scan flag if activity stops
        elif port_count < 5:
            profile.is_scanning = False

        return alerts

    def _is_sequential(self, sorted_ports):
        """Check if port list is sequential (e.g., 80, 81, 82...)."""
        if len(sorted_ports) < 5:
            return False
        sequential_runs = 0
        for i in range(1, len(sorted_ports)):
            if sorted_ports[i] - sorted_ports[i-1] <= 2:
                sequential_runs += 1
        return sequential_runs >= len(sorted_ports) * 0.6

    # ── Detection: Connection Burst ───────────────────────────────────────────

    def _corroborating_signals(self, prior_alerts):
        """Non-burst signals that justify higher severity (not spike alone)."""
        for a in prior_alerts or []:
            t = (a.get("type") or "").upper()
            if t in ("ML_ANOMALY", "PORT_SCAN", "SUSPICIOUS_PORTSCAN", "BRUTE_FORCE", "DNS_THREAT", "HIGH_RISK_PORT"):
                return True
        return False

    def _detect_connection_burst(self, ip, profile, rate, prior_alerts):
        """
        Connection burst / spike: high packet rate in 10s window.
        Spike alone is not treated as highly malicious; pair with corroboration or repetition.
        """
        alerts = []

        BURST_THRESHOLD = 100   # packets/sec as requested
        
        if rate >= BURST_THRESHOLD and not profile.is_bursting:
            profile.is_bursting = True
            if "CONNECTION_BURST" not in profile.threat_tags:
                profile.threat_tags.append("CONNECTION_BURST")
            
            alerts.append({
                "type": "CONNECTION_BURST",
                "severity": "HIGH",
                "score": 8,
                "detail": f"Traffic spike detected: {rate:.1f} packets/sec",
                "reason": f"Traffic spike detected: {rate:.1f} packets/sec",
                "rate": rate,
                "timestamp": time.time(),
                "spike_only": False,
            })

        elif rate < 10:
            profile.is_bursting = False

        elif rate < 2:
            profile.is_bursting = False  # Reset when calmed

        return alerts

    # ── Detection: Brute Force ────────────────────────────────────────────────

    def _detect_brute_force(self, ip, profile, meta):
        """
        Brute force detection: repeated connections to SSH/RDP/FTP/DB ports.
        Threshold: > 10 attempts to brute-force ports within 30 seconds.
        """
        alerts = []
        dst_port = meta.get("dst_port", 0)

        if dst_port not in BRUTE_FORCE_PORTS:
            return alerts

        now = time.time()
        # Use deque for O(1) popleft instead of list comprehension on every packet
        attempts = self.connection_attempts[ip]
        attempts.append(now)
        while attempts and now - attempts[0] > 30:
            attempts.popleft()
        recent_count = len(attempts)

        BRUTE_THRESHOLD = 10

        if recent_count >= BRUTE_THRESHOLD and not profile.is_brute_forcing:
            profile.is_brute_forcing = True
            if "BRUTE_FORCE" not in profile.threat_tags:
                profile.threat_tags.append("BRUTE_FORCE")
            alerts.append({
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "score": 8,
                "detail": f"Repeated connection attempts: {recent_count} requests in 30 seconds",
                "reason": f"Repeated connection attempts: {recent_count} requests in 30 seconds",
                "target_port": dst_port,
                "attempts": recent_count,
                "timestamp": time.time(),
            })

        return alerts

    # ── Detection: High-Risk Port ─────────────────────────────────────────────

    def _detect_high_risk_port(self, ip, profile, meta):
        """Detect connections to known malware/C2/exploit ports."""
        alerts = []
        dst_port = meta.get("dst_port", 0)

        if dst_port in HIGH_RISK_PORTS:
            tag = f"HIGH_RISK_PORT_{dst_port}"
            if tag not in profile.threat_tags:
                profile.threat_tags.append(tag)
                alerts.append({
                    "type": "HIGH_RISK_PORT",
                    "severity": "HIGH",
                    "score": 4,
                    "detail": f"High-risk port connection: {dst_port}",
                    "reason": f"Connection attempt to a known sensitive/malware port ({dst_port}).",
                    "target_port": dst_port,
                    "timestamp": time.time(),
                })

        return alerts

    # ── Detection: Traffic Spike ──────────────────────────────────────────────

    def _detect_traffic_spike(self, ip, profile, meta):
        """Detect abnormal data transfer (bandwidth spike)."""
        alerts = []
        total_bytes = profile.get_total_bytes() if hasattr(profile, 'get_total_bytes') else profile.total_bytes

        SPIKE_BYTES = 10 * 1024 * 1024  # 10 MB threshold

        if total_bytes > SPIKE_BYTES:
            tag = "TRAFFIC_SPIKE"
            if tag not in profile.threat_tags:
                profile.threat_tags.append(tag)
                alerts.append({
                    "type": "TRAFFIC_SPIKE",
                    "severity": "MEDIUM",
                    "score": 2,
                    "detail": f"High data transfer: {total_bytes // 1024 // 1024}MB",
                    "reason": f"Abnormal traffic burst: {total_bytes // 1024 // 1024}MB of data transferred from this IP.",
                    "bytes": total_bytes,
                    "timestamp": time.time(),
                })

        return alerts

    # ── Public API ────────────────────────────────────────────────────────────

    def get_profile(self, ip):
        with self._lock:
            return self.profiles.get(ip)

    def get_all_profiles(self):
        with self._lock:
            return {ip: p.to_dict() for ip, p in self.profiles.items() if p is not None}

    def get_external_profiles(self):
        with self._lock:
            return {
                ip: p.to_dict()
                for ip, p in self.profiles.items()
                if p is not None and p.ip_type == "EXTERNAL"
            }

    def get_recent_alerts(self, n=50):
        return list(self.alert_queue)[-n:]

    def get_stats(self):
        with self._lock:
            profiles = [p for p in self.profiles.values() if p]
            external = [p for p in profiles if p.ip_type == "EXTERNAL"]
            internal = [p for p in profiles if p.ip_type == "INTERNAL"]
            flagged = [p for p in profiles if p.threat_score >= 4]
            return {
                "total_packets": self.total_packets,
                "external_packets": self.external_packets,
                "unique_ips": len(profiles),
                "external_ips": len(external),
                "internal_ips": len(internal),
                "flagged_ips": len(flagged),
                "recent_alerts": len(self.alert_queue),
            }

    def get_top_threats(self, n=10):
        with self._lock:
            profiles = [p for p in self.profiles.values() if p and p.threat_score > 0]
            sorted_profiles = sorted(profiles, key=lambda p: p.threat_score, reverse=True)
            return [p.to_dict() for p in sorted_profiles[:n]]


# Global singleton
traffic_analyzer = TrafficAnalyzer()
