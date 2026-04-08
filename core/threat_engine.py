"""
Threat Scoring Engine
- Receives alerts from the Traffic Analyzer
- Applies weighted scoring to build a threat profile per IP
- Enforces decisions based on accumulated scores
- Smart blocking: accumulate evidence before acting
- Auto-unblock after safe cooldown window
"""

import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta

# ─── Behavior + Pattern Intelligence (Lightweight) ─────────────────────────────

class IPBehaviorProfile:
    """
    Lightweight per-IP behavior baseline + pattern memory.
    Kept intentionally simple to avoid false positives and keep CPU low.
    """

    def __init__(self, ip: str):
        self.ip = ip
        self._lock = threading.Lock()

        # Tracking
        self.request_count = 0
        self.last_seen = 0.0
        self.ports = set()
        self.connection_count = 0

        # Baselines (simple moving averages)
        self.avg_rate_10s = 0.0
        self.avg_port_count_60s = 0.0

        # Recent activity timing
        self._seen_times = deque(maxlen=50)  # timestamps for burstiness

        # Repetition memory (recent alert types, rolling window)
        self._recent_alerts = deque(maxlen=30)  # (ts, alert_type)

        # ML memory
        self.last_ml_score = 0.0
        self.last_ml_ts = 0.0

    def update_from_profile(self, profile):
        """Update behavior snapshot using TrafficAnalyzer IPProfile (if available)."""
        now = time.time()
        with self._lock:
            self.request_count += 1
            self.last_seen = now
            self._seen_times.append(now)

            if profile is None:
                return

            # Pull stats from existing profile (already optimized there)
            try:
                rate_10s = float(profile.get_packet_rate(window_sec=10))
            except Exception:
                rate_10s = 0.0
            try:
                port_count_60s = float(profile.get_recent_port_count(window_sec=60))
            except Exception:
                port_count_60s = 0.0

            # Simple moving averages (lightweight baseline learning)
            self.avg_rate_10s = (self.avg_rate_10s + rate_10s) / 2.0 if self.avg_rate_10s else rate_10s
            self.avg_port_count_60s = (self.avg_port_count_60s + port_count_60s) / 2.0 if self.avg_port_count_60s else port_count_60s

            # Best-effort ports/connection count (not required for decision)
            try:
                self.connection_count = int(getattr(profile, "connection_count", self.connection_count))
            except Exception:
                pass
            try:
                ports = profile.get_distinct_ports(window_sec=60)
                if ports:
                    # Keep only a small rolling set (avoid unbounded growth)
                    if len(self.ports) > 2000:
                        self.ports.clear()
                    self.ports.update(set(list(ports)[:200]))
            except Exception:
                pass

    def record_alert(self, alert_type: str, alert: dict):
        now = float(alert.get("timestamp", time.time()))
        with self._lock:
            self._recent_alerts.append((now, alert_type))
            if alert_type == "ML_ANOMALY":
                # In your pipeline, alert["score"] is an int derived from MLDetector threat_delta.
                try:
                    self.last_ml_score = float(alert.get("score", 0.0))
                except Exception:
                    self.last_ml_score = 0.0
                self.last_ml_ts = now

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "request_count": self.request_count,
                "last_seen": self.last_seen,
                "ports_count": len(self.ports),
                "connection_count": self.connection_count,
                "avg_rate_10s": self.avg_rate_10s,
                "avg_port_count_60s": self.avg_port_count_60s,
                "last_ml_score": self.last_ml_score,
                "last_ml_ts": self.last_ml_ts,
                "seen_times": list(self._seen_times),
                "recent_alerts": list(self._recent_alerts),
            }


def _clamp01(x: float) -> float:
    try:
        return max(0.0, min(1.0, float(x)))
    except Exception:
        return 0.0

# ─── Score Weights ─────────────────────────────────────────────────────────────

SCORE_WEIGHTS = {
    "PORT_SCAN":          5,   # Port scanning
    "CONNECTION_BURST":   4,   # Rapid burst
    "BRUTE_FORCE":        6,   # Brute force login
    "HIGH_RISK_PORT":     4,   # C2/malware ports
    "MALICIOUS_PROCESS":  6,   # Malicious process detect (Abnormal process spawn)
    "DNS_THREAT":         4,   # Phishing/C2 domain (Suspicious domain)
    "HONEYPOT_HIT":       10,  # Honeypot interaction
}

# ─── Threat Levels ─────────────────────────────────────────────────────────────

def get_threat_level(score):
    if score <= 3:
        return "NORMAL"
    elif score <= 6:
        return "SUSPICIOUS"
    elif score <= 9:
        return "MALICIOUS"
    else:
        return "CRITICAL"

def get_threat_severity(score):
    level = get_threat_level(score)
    return {
        "NORMAL": "LOW",
        "SUSPICIOUS": "MEDIUM",
        "MALICIOUS": "HIGH",
        "CRITICAL": "HIGH",
    }.get(level, "LOW")

# ─── Per-IP Threat State ───────────────────────────────────────────────────────

class IPThreatState:
    """Maintains threat scoring state for one IP."""

    SCORE_DECAY_PERIOD = 300   # 5 minutes: score decays after inactivity
    BLOCK_COOLDOWN = 1800      # 30 minutes: auto-unblock after this

    def __init__(self, ip):
        self.ip = ip
        self.score = 0
        self.evidence = deque(maxlen=50)   # Recorded alert history
        self.last_updated = time.time()
        self.action = "MONITOR"            # MONITOR, LOG, TEMP_BLOCK, BLOCK
        self.blocked_at = None
        self.is_blocked = False
        self.block_reason = ""
        self.last_confidence = 0.0
        self.last_reasoning = ""
        self.last_reasoning_list = []
        self.last_risk_score = 0
        self.last_repeat_strong = 0
        self.last_process_name = "unknown process"
        self._lock = threading.Lock()

    def add_score(self, points, reason, alert_type):
        with self._lock:
            self.score = min(self.score + points, 50)   # cap at 50
            self.last_updated = time.time()
            self.evidence.append({
                "type": alert_type,
                "score_added": points,
                "reason": reason,
                "timestamp": datetime.now().isoformat(),
            })

    def decay_score(self):
        """Gradually reduce score over time if no new activity."""
        with self._lock:
            elapsed = time.time() - self.last_updated
            if elapsed > self.SCORE_DECAY_PERIOD:
                decrement = int(elapsed / self.SCORE_DECAY_PERIOD)
                self.score = max(0, self.score - decrement)

    def should_auto_unblock(self):
        """Check if enough time has passed to auto-unblock."""
        if not self.is_blocked or self.blocked_at is None:
            return False
        return (time.time() - self.blocked_at) >= self.BLOCK_COOLDOWN

    def get_threat_level(self):
        return get_threat_level(self.score)

    def get_severity(self):
        return get_threat_severity(self.score)

    def to_dict(self):
        with self._lock:
            return {
                "ip": self.ip,
                "score": self.score,
                "threat_level": self.get_threat_level(),
                "action": self.action,
                "is_blocked": self.is_blocked,
                "confidence": round(self.last_confidence, 2),
                "risk_score": self.last_risk_score,
                "repeat_strong": self.last_repeat_strong,
                "reasoning": self.last_reasoning[:400],
                "evidence_count": len(self.evidence),
                "evidence": list(self.evidence)[-5:],  # Last 5 pieces
                "last_updated": datetime.fromtimestamp(self.last_updated).isoformat(),
            }


# ─── Threat Scoring Engine ───────────────────────────────────────────────────

class ThreatScoringEngine:
    """
    Central threat scoring and decision engine.

    Scoring:  Alerts → weighted scores per IP
    Decision: Score threshold → action (monitor/log/temp_block/block)
    Smart:    Never block on single event — accumulate evidence first
    """

    def __init__(self):
        self._states = {}     # ip -> IPThreatState
        self._lock = threading.Lock()
        self._blocked_ips = set()
        self._event_timeline = deque(maxlen=1000)  # Forensic timeline
        self._action_log = deque(maxlen=500)
        self._behavior = {}   # ip -> IPBehaviorProfile
        self._domain_repeats = defaultdict(lambda: deque(maxlen=50))  # domain -> [timestamps]
        self._process_cache = {}  # ip -> {"process": str, "ts": float}
        self._process_cache_lock = threading.Lock()
        self._process_cache_ttl_sec = 25.0

        # Optional source intelligence caches (async, best-effort; never block).
        self._domain_cache = {}  # ip -> {"domain": str, "ts": float}
        self._isp_cache = {}     # ip -> {"isp_org": str, "ts": float}
        self._intel_cache_lock = threading.Lock()
        self._domain_inflight = set()
        self._isp_inflight = set()
        self._domain_ttl_sec = 6 * 3600
        self._isp_ttl_sec = 1 * 3600

        # Start auto-unblock monitor
        t = threading.Thread(target=self._unblock_monitor, daemon=True)
        t.start()

    def _get_state(self, ip):
        with self._lock:
            if ip not in self._states:
                self._states[ip] = IPThreatState(ip)
            return self._states[ip]

    def _get_behavior(self, ip: str) -> IPBehaviorProfile:
        with self._lock:
            b = self._behavior.get(ip)
            if b is None:
                b = IPBehaviorProfile(ip)
                self._behavior[ip] = b
            return b

    def _source_type_from_ip(self, ip: str) -> str:
        """Backend-only label (never shown as INTERNAL/EXTERNAL)."""
        try:
            if ip.startswith(("10.", "192.168.")):
                return "Local Device"
            if ip.startswith("172."):
                parts = ip.split(".")
                if len(parts) >= 2:
                    sec = int(parts[1])
                    if 16 <= sec <= 31:
                        return "Local Device"
        except Exception:
            pass
        return "External Source"

    def _get_process_for_ip_cached(self, ip: str) -> str:
        """Best-effort process mapping from in-memory packet store (cached)."""
        now = time.time()
        with self._process_cache_lock:
            ent = self._process_cache.get(ip)
            if ent and (now - ent.get("ts", 0)) <= self._process_cache_ttl_sec:
                return ent.get("process") or "unknown process"

        process_name = "unknown process"
        try:
            from monitoring.packet_capture import packet_store
            recent_packets = packet_store.get_recent(n=250) or []
            for p in reversed(recent_packets):
                if p.get("src_ip") == ip and p.get("process"):
                    process_name = p.get("process") or process_name
                    break
        except Exception:
            pass

        with self._process_cache_lock:
            self._process_cache[ip] = {"process": process_name, "ts": now}
        return process_name

    def _get_cached_domain_and_isp(self, ip: str) -> tuple:
        """Return cached (domain, isp_org) without triggering blocking calls."""
        now = time.time()
        with self._intel_cache_lock:
            d_ent = self._domain_cache.get(ip)
            i_ent = self._isp_cache.get(ip)

            domain = d_ent.get("domain") if d_ent and (now - d_ent.get("ts", 0)) <= self._domain_ttl_sec else None
            isp_org = i_ent.get("isp_org") if i_ent and (now - i_ent.get("ts", 0)) <= self._isp_ttl_sec else None
        return (domain or "unknown", isp_org or "unresolved")

    def _schedule_reverse_dns_async(self, ip: str) -> None:
        """Async reverse DNS lookup with safe fallback."""
        now = time.time()
        with self._intel_cache_lock:
            d_ent = self._domain_cache.get(ip)
            if d_ent and (now - d_ent.get("ts", 0)) <= self._domain_ttl_sec:
                return
            if ip in self._domain_inflight:
                return
            self._domain_inflight.add(ip)

        def _worker():
            try:
                import socket as _socket
                # Prevent hanging: short timeout during lookup
                orig_timeout = None
                try:
                    orig_timeout = _socket.getdefaulttimeout()
                except Exception:
                    orig_timeout = None
                try:
                    _socket.setdefaulttimeout(2.0)
                    domain = _socket.gethostbyaddr(ip)[0]
                finally:
                    try:
                        _socket.setdefaulttimeout(orig_timeout)
                    except Exception:
                        pass
            except Exception:
                domain = "unknown"

            with self._intel_cache_lock:
                self._domain_cache[ip] = {"domain": domain, "ts": time.time()}
                self._domain_inflight.discard(ip)

        threading.Thread(target=_worker, daemon=True).start()

    def _schedule_isp_org_async(self, ip: str) -> None:
        """Async ISP/org enrichment via ip-api.com (best-effort)."""
        now = time.time()
        with self._intel_cache_lock:
            i_ent = self._isp_cache.get(ip)
            if i_ent and (now - i_ent.get("ts", 0)) <= self._isp_ttl_sec:
                return
            if ip in self._isp_inflight:
                return
            self._isp_inflight.add(ip)

        def _worker():
            isp_org = "unresolved"
            try:
                import urllib.request as _urllib_request
                import json as _json
                url = f"http://ip-api.com/json/{ip}?fields=status,isp,org"
                req = _urllib_request.Request(url, headers={"User-Agent": "AutonomousCyberDefence/1.0"})
                with _urllib_request.urlopen(req, timeout=2.5) as resp:
                    raw = resp.read().decode("utf-8", errors="ignore")
                data = _json.loads(raw) if raw else {}
                if data.get("status") == "success":
                    isp = data.get("isp") or ""
                    org = data.get("org") or ""
                    val = (isp if isp else org).strip()
                    isp_org = val if val else "unresolved"
            except Exception:
                isp_org = "unresolved"

            with self._intel_cache_lock:
                self._isp_cache[ip] = {"isp_org": isp_org, "ts": time.time()}
                self._isp_inflight.discard(ip)

        threading.Thread(target=_worker, daemon=True).start()

    def _detect_patterns(self, ip: str, behavior_snap: dict, profile, alert: dict) -> list:
        """
        Pattern detection using behavior snapshot + current TrafficAnalyzer profile.
        Returns a list of human-readable pattern strings.
        """
        patterns = []
        now = time.time()

        # Current observed stats (best-effort)
        cur_rate = 0.0
        cur_ports = 0.0
        try:
            if profile is not None:
                cur_rate = float(profile.get_packet_rate(window_sec=10))
                cur_ports = float(profile.get_recent_port_count(window_sec=60))
        except Exception:
            pass

        avg_rate = float(behavior_snap.get("avg_rate_10s") or 0.0)
        avg_ports = float(behavior_snap.get("avg_port_count_60s") or 0.0)

        # 1) Sudden spike in requests (avoid blocking on a single spike)
        # Trigger pattern only when rate is meaningfully above baseline and above a floor.
        if avg_rate > 0.0:
            if cur_rate >= max(6.0, avg_rate * 3.0):
                patterns.append(f"abnormal spike: {cur_rate:.1f} pkt/s vs baseline {avg_rate:.1f} pkt/s")
        else:
            if cur_rate >= 25.0:
                patterns.append(f"abnormal spike: {cur_rate:.1f} pkt/s (no baseline yet)")

        # 2) Multiple ports rapidly (port-scan-like behavior)
        if avg_ports > 0.0:
            if cur_ports >= max(10.0, avg_ports * 3.0):
                patterns.append(f"rapid multi-port access: {int(cur_ports)} ports/60s vs baseline {avg_ports:.1f}")
        else:
            if cur_ports >= 15.0:
                patterns.append(f"rapid multi-port access: {int(cur_ports)} ports/60s (no baseline yet)")

        # 3) Repeated login attempts (brute force)
        # TrafficAnalyzer already emits BRUTE_FORCE; we also detect repetition from evidence here.
        alert_type = alert.get("type", "UNKNOWN")
        if alert_type == "BRUTE_FORCE":
            patterns.append("repeated login attempts (brute force signal)")

        # 4) Unusual activity timing (burst vs normal)
        seen = behavior_snap.get("seen_times") or []
        if len(seen) >= 8:
            # If many packets arrive in a very tight window, mark bursty
            try:
                window = float(seen[-1]) - float(seen[-8])
                if window >= 0.0 and window <= 1.0:
                    patterns.append("bursty timing: 8+ events within ~1s")
            except Exception:
                pass

        return patterns

    def _count_repeats(self, behavior_snap: dict, alert_types: set, window_sec: float = 60.0) -> int:
        """Count how often any of alert_types occurred in recent window."""
        now = time.time()
        recent = behavior_snap.get("recent_alerts") or []
        c = 0
        for ts, t in recent:
            try:
                if now - float(ts) <= window_sec and t in alert_types:
                    c += 1
            except Exception:
                continue
        return c

    def _compute_confidence(self, *, ml_score: float, rate_deviation: float, repetition: int) -> float:
        """
        Confidence in maliciousness: combine ML + deviation + repetition.
        Returned value in [0,1].
        Safety-biased: repetition is required to get high confidence.
        """
        # Normalize ML score: in your pipeline it is int-ish (0..~10+)
        ml_norm = _clamp01(ml_score / 10.0)
        dev_norm = _clamp01(rate_deviation)  # already a 0..1 measure
        rep_norm = _clamp01(repetition / 5.0)

        # Weight repetition heavily to avoid blocking on one-off anomalies/spikes
        confidence = (0.35 * ml_norm) + (0.25 * dev_norm) + (0.40 * rep_norm)
        return _clamp01(confidence)

    # ─── Production Decision Model (Safety-biased, explainable) ───────────────
    def compute_risk(self, threat: dict, state: "IPThreatState") -> tuple[int, list[str]]:
        """
        Compute a risk score (0-100) and explain why.

        Inputs used (as requested):
        - process
        - source_type
        - confidence (state.last_confidence)
        - behavior score (state.score)
        """
        ip = state.ip
        confidence = float(getattr(state, "last_confidence", 0.0) or 0.0)
        behavior_score = int(getattr(state, "score", 0) or 0)

        process_name = threat.get("process") or getattr(state, "last_process_name", None) or self._get_process_for_ip_cached(ip)
        process_lower = (process_name or "unknown process").lower()
        unknown_process = ("unknown" in process_lower) or not process_lower.strip()

        source_type = self._source_type_from_ip(ip)  # Local Device / External Source

        risk = 0
        reasons: list[str] = []

        # Positive signals (weights as requested)
        if confidence > 0.75:
            risk += 40
            reasons.append(f"ML confidence high ({confidence:.2f} > 0.75): +40")
        if behavior_score >= 50:  # behavior_score is capped at 50 in this system
            risk += 20
            reasons.append(f"Behavior score high ({behavior_score} >= 50): +20")
        if source_type == "External Source":
            risk += 10
            reasons.append("External source: +10")
        if unknown_process:
            risk += 20
            reasons.append("Unknown process: +20")

        # Protection (as requested)
        trusted_processes = {
            "chrome.exe", "msedge.exe", "edge.exe", "explorer.exe",
            "whatsapp.exe", "teams.exe", "outlook.exe",
            "svchost.exe", "system", "winlogon.exe", "services.exe"
        }
        is_trusted_process = process_lower in trusted_processes

        if is_trusted_process:
            risk -= 30
            reasons.append(f"Trusted process ({process_name}): -30")
        if source_type == "Local Device":
            risk -= 20
            reasons.append("Local traffic: -20")

        risk = max(0, min(100, int(risk)))
        return risk, reasons

    def decide(self, risk: int, state: "IPThreatState") -> str:
        """
        Decide action based on risk + repetition + confidence.

        Returns one of: ALLOW, MONITOR, ALERT, BLOCK
        """
        repeat_strong = int(getattr(state, "last_repeat_strong", 0) or 0)
        confidence = float(getattr(state, "last_confidence", 0.0) or 0.0)

        # Safety rule: no blocking on low repetition
        if repeat_strong < 2:
            return "MONITOR"

        if risk < 30:
            return "ALLOW"
        if risk < 60:
            return "MONITOR"
        if risk < 80:
            return "ALERT"

        # risk >= 80: only block if repeated + high confidence
        if repeat_strong >= 3 and confidence > 0.8:
            return "BLOCK"
        return "ALERT"

    def process_alert(self, alert, profile=None):
        """
        Process an alert from the traffic analyzer.
        Updates the IP's threat score and decides action.
        """
        ip = alert.get("ip", "")
        if not ip:
            return

        alert_type = alert.get("type", "UNKNOWN")
        score_delta = alert.get("score", SCORE_WEIGHTS.get(alert_type, 1))
        detail = alert.get("detail", "")
        severity = alert.get("severity", "LOW")

        state = self._get_state(ip)
        state.add_score(score_delta, detail, alert_type)

        # Update per-IP behavior profile (baseline learning)
        behavior = self._get_behavior(ip)
        behavior.update_from_profile(profile)
        behavior.record_alert(alert_type, alert)

        # Trigger Active Recon Logic - (Currently Disabled to Reduce Complexity/Remove Unnecessary Files)
        # To enable, create nmap_integration.py and uncomment below
        # if state.score >= 5 and ip != "GLOBAL_NETWORK":
        #     pass

        # Record in forensic timeline
        self._event_timeline.append({
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "ip_type": alert.get("ip_type", "UNKNOWN"),
            "event_type": alert_type,
            "score_delta": score_delta,
            "cumulative_score": state.score,
            "severity": severity,
            "detail": detail,
        })

        # ─── Correlation Logic ───────────────────────────────────────────────
        from core.correlation_engine import correlation_engine
        attack_chain = correlation_engine.correlate(alert)
        
        if attack_chain and attack_chain["confidence"] in ["MEDIUM", "HIGH"]:
            correlation_boost = 3 if attack_chain["confidence"] == "MEDIUM" else 5
            state.add_score(correlation_boost, f"Correlation Boost: {attack_chain['confidence']} confidence attack chain ({', '.join(attack_chain['event_types'])})", "CORRELATION")
            
            # Record in forensic timeline
            self._event_timeline.append({
                "timestamp": datetime.now().isoformat(),
                "ip": ip,
                "event_type": "CORRELATION_BOOST",
                "score_delta": correlation_boost,
                "cumulative_score": state.score,
                "severity": "HIGH",
                "detail": f"Correlated alerts: {', '.join(attack_chain['event_types'])}",
                "chain": attack_chain
            })

        # Determine action based on accumulated score
        action = self._decide_action(ip, state, alert, profile=profile, behavior=behavior)

        # Log to database
        try:
            from data.database import log_event, log_action, block_entity_db
            process_name = getattr(state, "last_process_name", None) or alert.get("process") or "unknown process"
            reasoning_str = getattr(state, "last_reasoning", "") or ""
            reasoning_list = getattr(state, "last_reasoning_list", []) or []
            repeat_count = int(getattr(state, "last_repeat_strong", 0) or 0)
            risk_score = int(getattr(state, "last_risk_score", state.score) or 0)
            log_event(
                src_ip=ip,
                dest_ip=alert.get("dst_ip", "LOCAL"),
                src_port=alert.get("src_port", 0),
                dst_port=alert.get("dst_port", 0),
                protocol=alert.get("protocol", "OTHER"),
                payload_size=alert.get("payload_size", 0),
                severity=severity,
                anomaly_score=min(state.score / 10.0, 1.0),
                active_window=alert.get("ip_type", "NETWORK"),
                details={
                    "threat_level": state.get_threat_level(),
                    "alert_type": alert_type,
                    "action": action,
                    "process": process_name,
                    "event": alert_type,
                    "risk_score": risk_score,
                    "confidence": state.last_confidence,
                    "repeat_count": repeat_count,
                    "reasoning": reasoning_list,
                    "detail": f"{detail} | WHY: {reasoning_str}" if reasoning_str else detail
                },
                threat_score=state.score
            )
        except Exception:
            pass

        # ─── New: Domain-Specific Blocking for DNS Intelligence ───────────
        if alert_type == "DNS_THREAT":
            # Detail format: f"Suspicious Domain: {query} ({', '.join(reasons)})"
            domain = detail.split(": ")[1].split(" (")[0] if ": " in detail else ""

            # Safety upgrade: NEVER block domain on a single hit.
            # Only block when the domain repeats over time and score is high.
            if domain:
                now = time.time()
                self._domain_repeats[domain].append(now)
                # prune older than 10 minutes
                while self._domain_repeats[domain] and now - self._domain_repeats[domain][0] > 600:
                    self._domain_repeats[domain].popleft()

            repeat_hits = len(self._domain_repeats.get(domain, [])) if domain else 0
            should_block_domain = bool(domain and score_delta >= 7 and repeat_hits >= 3)

            if should_block_domain:
                try:
                    from defense.firewall import block_domain
                    block_domain(domain)
                    from data.database import block_entity_db, log_action
                    block_entity_db("DOMAIN", domain, f"High-confidence suspicious domain (repeat_hits={repeat_hits}): {detail}")
                    log_action("DOMAIN", domain, "BLOCK", f"DNS score={score_delta}, repeat_hits={repeat_hits}")
                except:
                    pass

        return action

    def _decide_action(self, ip, state, alert, profile=None, behavior=None):
        """
        Smart decision engine:
        - score 0–3: MONITOR
        - score 4–6: LOG (suspicious, watching)
        - score 7–10: TEMP_BLOCK (30-minute block)
        - score 11+:  BLOCK (permanent until manual review)

        Never block on a single alert — requires pattern evidence.
        """
        score = state.score
        evidence_count = len(state.evidence)

        if state.is_blocked:
            return "BLOCKED"

        action = "MONITOR"

        # ─── Behavior + pattern based intelligence (safety-biased) ───
        behavior_snap = behavior.snapshot() if behavior is not None else {}
        patterns = self._detect_patterns(ip, behavior_snap, profile, alert)

        # "Repeated malicious pattern" requirement: count repeats of strong signals in last 60s
        repeat_strong = self._count_repeats(
            behavior_snap,
            alert_types={"PORT_SCAN", "CONNECTION_BURST", "BRUTE_FORCE", "HIGH_RISK_PORT", "ML_ANOMALY", "HONEYPOT_HIT"},
            window_sec=60.0
        )

        # Recent ML anomaly requirement (single anomaly alone must NOT block)
        now = time.time()
        last_ml_ts = float(behavior_snap.get("last_ml_ts") or 0.0)
        last_ml_score = float(behavior_snap.get("last_ml_score") or 0.0)
        has_recent_ml = (now - last_ml_ts) <= 45.0 and last_ml_score >= 1.0

        # Frequency deviation (0..1)
        cur_rate = 0.0
        try:
            if profile is not None:
                cur_rate = float(profile.get_packet_rate(window_sec=10))
        except Exception:
            pass
        avg_rate = float(behavior_snap.get("avg_rate_10s") or 0.0)
        if avg_rate > 0.0 and cur_rate > avg_rate:
            freq_dev = _clamp01((cur_rate - avg_rate) / max(avg_rate, 1e-6))
        else:
            freq_dev = 0.0

        confidence = self._compute_confidence(
            ml_score=last_ml_score if has_recent_ml else 0.0,
            rate_deviation=freq_dev,
            repetition=repeat_strong
        )

        # Explainable reasoning (MANDATORY)
        reasoning_lines = []
        if has_recent_ml:
            reasoning_lines.append(f"ML anomaly present: score={last_ml_score:.1f} (recent)")
        if patterns:
            reasoning_lines.extend([f"Pattern: {p}" for p in patterns])
        if repeat_strong:
            reasoning_lines.append(f"Repeated strong signals: {repeat_strong} events/60s")
        reasoning_lines.append(f"Confidence={confidence:.2f} (safety-biased)")

        # Persist last reasoning to state (for dashboard/API visibility)
        try:
            state.last_confidence = float(confidence)
            state.last_reasoning = " | ".join(reasoning_lines)
        except Exception:
            pass

        # Hard safety rules:
        # - single anomaly => never block
        # - temporary spike => monitor/alert first (require repetition)
        # - require ML + abnormal pattern + repetition + not whitelisted (whitelist enforced in _execute_block)
        # Persist repetition count for the decision model.
        try:
            state.last_repeat_strong = int(repeat_strong)
        except Exception:
            state.last_repeat_strong = 0

        # Resolve process and persist it for explainable logging.
        process_name = alert.get("process") or self._get_process_for_ip_cached(ip)
        state.last_process_name = process_name or "unknown process"

        # Risk + decision (production-level, safety-biased).
        risk, risk_reasons = self.compute_risk(alert, state)
        decision = self.decide(risk, state)

        # Combine explainability (baseline patterns + risk factors + final decision).
        final_reasoning_list = list(reasoning_lines)
        final_reasoning_list.extend(risk_reasons)
        final_reasoning_list.append(
            f"Decision={decision} (risk={risk}, repeat_strong={repeat_strong}, confidence={confidence:.2f})"
        )

        # Persist explainable outputs for log_event() in process_alert().
        state.last_risk_score = int(risk)
        state.last_reasoning_list = final_reasoning_list
        state.last_reasoning = " | ".join(final_reasoning_list)

        # Map decision to existing action semantics.
        if decision == "ALLOW" or decision == "MONITOR":
            action = "MONITOR"
            state.action = action
            return action

        if decision == "ALERT":
            action = "LOG"
            state.action = action
            self._action_log.append({
                "timestamp": datetime.now().isoformat(),
                "ip": ip,
                "action": action,
                "score": score,
                "reason": "ALERT: " + " | ".join(final_reasoning_list[:6]),
            })
            return action

        # decision == "BLOCK": Safe blocking (TEMP_BLOCK only, repetition-confirmed by decide()).
        if decision == "BLOCK":
            action = "TEMP_BLOCK"
            reason = "Blocked because:\n- " + "\n- ".join(final_reasoning_list)
            self._execute_block(ip, state, reason, permanent=False)
            return "TEMP_BLOCK"

        # Defensive fallback (should never happen).
        state.action = "MONITOR"
        return "MONITOR"

    def _execute_block(self, ip, state, reason, permanent=False):
        """Execute firewall block and update state."""
        from monitoring.packet_capture import get_ip_type
        try:
            from data.database import is_whitelisted
            if is_whitelisted("IP", ip):
                print(f"[ThreatEngine] Safety: IP {ip} is whitelisted, skipping block.")
                return
        except Exception:
            pass

        # Safety: never block local/protected interface IPs
        from monitoring.packet_capture import PROTECTED_IPS
        if ip in PROTECTED_IPS:
            return

        if state.is_blocked:
            return  # Already blocked

        state.is_blocked = True
        state.blocked_at = time.time()
        state.action = "BLOCK" if permanent else "TEMP_BLOCK"
        state.block_reason = reason

        with self._lock:
            self._blocked_ips.add(ip)

        block_type = "PERMANENT BLOCK" if permanent else "TEMP BLOCK (30min)"
        print(f"[ThreatEngine] {block_type}: {ip} - {reason}")

        # Record action timeline
        self._action_log.append({
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "action": state.action,
            "score": state.score,
            "reason": reason,
        })

        # Log to database
        try:
            from data.database import log_action, block_entity_db
            from defense.firewall import block_ip
            # Also log a structured event so the dashboard "Events Feed" updates.
            from monitoring.packet_capture import packet_store
            process_name = "unknown process"
            try:
                recent_packets = packet_store.get_recent(n=300) or []
                for p in reversed(recent_packets):
                    if p.get("src_ip") == ip and p.get("process"):
                        process_name = p.get("process") or process_name
                        break
            except Exception:
                pass

            block_entity_db("IP", ip, reason[:200])
            log_action("IP", ip, state.action, reason[:200])
            block_ip(ip)

            # Critical: blocking must always trigger an events-table write.
            from data.database import log_event
            log_event(
                src_ip=ip,
                dest_ip="LOCAL",
                src_port=0,
                dst_port=0,
                protocol="DEFENSE",
                payload_size=0,
                severity=state.get_severity(),
                anomaly_score=min(state.score / 10.0, 1.0),
                active_window="BLOCK",
                details={
                    "event": "BLOCK",
                    "action": state.action,
                    "risk_score": int(getattr(state, "last_risk_score", state.score) or state.score),
                    "confidence": float(getattr(state, "last_confidence", 0.0) or 0.0),
                    "repeat_count": int(getattr(state, "last_repeat_strong", 0) or 0),
                    "reasoning": getattr(state, "last_reasoning_list", []) or [],
                    "process": process_name,
                    "detail": reason
                },
                threat_score=state.score
            )
        except Exception as e:
            print(f"[ThreatEngine] Block error: {e}")

    def _unblock_monitor(self):
        """Background thread: auto-unblock IPs after cooldown."""
        while True:
            try:
                with self._lock:
                    states = list(self._states.items())

                for ip, state in states:
                    if state.should_auto_unblock():
                        print(f"[ThreatEngine] Auto-unblocking {ip} (cooldown expired)")
                        state.is_blocked = False
                        state.blocked_at = None
                        state.score = max(0, state.score - 5)  # Reduce score
                        with self._lock:
                            self._blocked_ips.discard(ip)

                        # Remove firewall rule
                        try:
                            from defense.firewall import unblock_ip
                            unblock_ip(ip)
                        except Exception:
                            pass

                        # Log unblock
                        try:
                            from data.database import log_action
                            log_action("IP", ip, "UNBLOCK", "Auto-unblocked after 30min cooldown")
                        except Exception:
                            pass

                    # Also do score decay
                    state.decay_score()

            except Exception as e:
                pass

            time.sleep(60)  # Check every minute

    # ── Public API ────────────────────────────────────────────────────────────

    def get_state(self, ip):
        return self._get_state(ip).to_dict()

    def get_all_states(self):
        with self._lock:
            return {ip: s.to_dict() for ip, s in self._states.items()}

    def get_blocked_ips(self):
        with self._lock:
            return list(self._blocked_ips)

    def get_high_threat_ips(self, min_score=4):
        with self._lock:
            return [
                s.to_dict()
                for s in self._states.values()
                if s.score >= min_score
            ]

    def get_event_timeline(self, n=100):
        return list(self._event_timeline)[-n:]

    def get_action_log(self, n=50):
        return list(self._action_log)[-n:]

    def get_stats(self):
        with self._lock:
            all_states = list(self._states.values())
            return {
                "total_ips_tracked": len(all_states),
                "blocked_ips": len(self._blocked_ips),
                "high_threat_ips": len([s for s in all_states if s.score >= 7]),
                "suspicious_ips": len([s for s in all_states if 4 <= s.score < 7]),
                "events_processed": len(self._event_timeline),
            }

    def manual_unblock(self, ip):
        """Manually unblock an IP."""
        state = self._get_state(ip)
        state.is_blocked = False
        state.score = 0
        state.action = "MONITOR"
        with self._lock:
            self._blocked_ips.discard(ip)
        try:
            from defense.firewall import unblock_ip
            from data.database import log_action
            unblock_ip(ip)
            log_action("IP", ip, "MANUAL_UNBLOCK", "Manually unblocked by operator")
        except Exception:
            pass
        return True


# Global singleton
threat_engine = ThreatScoringEngine()
