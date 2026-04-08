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


def _is_noise_domain(d: str) -> bool:
    try:
        from monitoring.website_analyzer import is_noise_domain
        return bool(is_noise_domain(d))
    except Exception:
        return False


def _clamp01(x: float) -> float:
    try:
        return max(0.0, min(1.0, float(x)))
    except Exception:
        return 0.0


def classify_source(ip: str) -> str:
    """
    Context classification for interpretation (does not suppress detection).
    Returns: SYSTEM | LOCAL_DEVICE | EXTERNAL_SOURCE
    """
    try:
        if ip.startswith("127."):
            return "SYSTEM"
        if ip.startswith("192.168.") or ip.startswith("10."):
            return "LOCAL_DEVICE"
        if ip.startswith("172."):
            parts = ip.split(".")
            if len(parts) >= 2:
                sec = int(parts[1])
                if 16 <= sec <= 31:
                    return "LOCAL_DEVICE"
    except Exception:
        pass
    return "EXTERNAL_SOURCE"


def _downgrade_severity_for_source(severity: str, source_type: str) -> str:
    """
    Context-aware severity interpretation:
    - SYSTEM: downgrade by 2 levels
    - LOCAL_DEVICE: downgrade by 1 level
    - EXTERNAL_SOURCE: unchanged
    """
    levels = ["LOW", "MEDIUM", "HIGH"]
    sev = (severity or "LOW").upper()
    try:
        idx = levels.index(sev)
    except ValueError:
        idx = 0

    if source_type == "SYSTEM":
        idx = max(0, idx - 2)
    elif source_type == "LOCAL_DEVICE":
        idx = max(0, idx - 1)

    return levels[idx]

# ─── Score Weights ─────────────────────────────────────────────────────────────

SCORE_WEIGHTS = {
    "PORT_SCAN":          5,   # Port scanning
    "CONNECTION_BURST":   2,   # Rapid burst (severity comes from alert score + corroboration)
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
        self.last_attack_type = ""
        self.last_domain = "unknown"
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
        """Gradually reduce risk over time if no new activity (self-healing)."""
        with self._lock:
            elapsed = time.time() - self.last_updated
            if elapsed > self.SCORE_DECAY_PERIOD:
                steps = int(elapsed / self.SCORE_DECAY_PERIOD)
                # Exponential decay: each period reduces score by ~10%
                factor = 0.9 ** steps
                self.score = max(0, int(self.score * factor))

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
            src = classify_source(self.ip)
            risk = int(self.last_risk_score or 0)
            tl = self.get_threat_level()
            if risk >= 90:
                tl = "CRITICAL"
            try:
                from core.cloud_intel import is_likely_cloud_or_cdn

                if is_likely_cloud_or_cdn(self.ip) and risk < 80 and tl in ("MALICIOUS", "CRITICAL"):
                    tl = "SUSPICIOUS"
            except Exception:
                pass
            return {
                "ip": self.ip,
                "score": self.score,
                "threat_level": tl,
                "action": self.action,
                "is_blocked": self.is_blocked,
                "confidence": round(self.last_confidence, 2),
                "risk_score": risk,
                "risk": risk,
                "repeat_strong": self.last_repeat_strong,
                "attack_type": self.last_attack_type or "SUSPICIOUS_BEHAVIOR",
                "source_type": src,
                "domain": self.last_domain or "unknown",
                "process": self.last_process_name or "unknown process",
                "reason": (self.last_reasoning[:400] if self.last_reasoning else "No reasoning available"),
                "timestamp": datetime.fromtimestamp(self.last_updated).isoformat(),
                "reasoning": self.last_reasoning[:400],
                "evidence_count": len(self.evidence),
                "evidence": list(self.evidence)[-5:],
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
        self.blocked_registry = {}  # ip -> {"blocked_at": float, "duration": int, "reason": str}
        self._event_timeline = deque(maxlen=1000)  # Forensic timeline
        self._action_log = deque(maxlen=500)
        self._behavior = {}   # ip -> IPBehaviorProfile
        self._domain_repeats = defaultdict(lambda: deque(maxlen=50))  # domain -> [timestamps]
        self._process_cache = {}  # ip -> {"process": str, "ts": float, "lookup_done": bool}
        self._process_cache_lock = threading.Lock()
        self._process_cache_ttl_sec = 25.0

        # Threat log dedup: same IP within window updates count instead of flooding DB/UI.
        self.ip_last_seen_cache = {}  # ip -> {"ts": float, "event_count": int, "last_detail": str}
        self._threat_dedup_lock = threading.Lock()
        self.THREAT_DEDUP_SEC = 60.0
        self.THREAT_LOG_COOLDOWN_SEC = 45.0

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

        # ─── Persistent IP memory (hybrid RAM primary) ─────────────────────
        # Load persistent memory on startup (read once).
        self.ip_memory = {}  # ip -> {"total_flags": int, "past_blocks": int, "last_seen": float}
        self._ip_memory_lock = threading.Lock()
        self._ip_memory_dirty = set()
        self._ip_memory_max = 1000

        # ─── Dynamic environment profiles (weights only) ─────────────────────
        # IMPORTANT: profiles only affect risk computation (no direct decision override).
        self.base_weights = {
            "ml_confidence": 40,
            "behavior_score": 20,
            "external_source": 10,
            "unknown_process": 20,
            "trusted_process": -30,
            "local_traffic": -20,
        }

        self.profiles = {
            "default": {},
            "developer": {
                "unknown_process": 10,
                "external_source": 5,
            },
            "gaming": {
                "behavior_score": 10,
                "external_source": 5,
            },
            "strict": {
                "unknown_process": 25,
                "external_source": 15,
            },
        }

        self.current_profile = "default"

        # Progressive scoring engine (continuous risk accumulation).
        # Cached singleton to avoid per-alert import overhead.
        try:
            from core.risk_engine import risk_engine as _risk_engine

            self._risk_engine = _risk_engine
        except Exception:
            self._risk_engine = None

        try:
            from data.database import load_ip_memory
            loaded = load_ip_memory() or {}
            # Optional cap on load to keep RAM bounded.
            if len(loaded) > self._ip_memory_max:
                # Keep most recently seen entries.
                loaded = dict(sorted(loaded.items(), key=lambda kv: kv[1].get("last_seen", 0.0), reverse=True)[: self._ip_memory_max])
            self.ip_memory = loaded
        except Exception:
            self.ip_memory = {}

        # Periodic sync (write periodically, never query DB during detection).
        t2 = threading.Thread(target=self._ip_memory_sync_loop, daemon=True)
        t2.start()

    def get_active_weights(self) -> dict:
        """Merge base weights with the active environment profile overrides."""
        weights = dict(self.base_weights)
        overrides = self.profiles.get(self.current_profile, {}) or {}
        for k, v in overrides.items():
            weights[k] = v
        return weights

    def _get_state(self, ip):
        with self._lock:
            if ip not in self._states:
                self._states[ip] = IPThreatState(ip)
            return self._states[ip]

    def _normalize_threat_object(self, *, ip: str, alert: dict, state: IPThreatState, action: str, reason: str, source_type: str | None = None) -> dict:
        """Single canonical threat object used across decision -> response -> DB -> API. No None values."""
        src_type = str(source_type or self._source_type_from_ip(ip) or "EXTERNAL_SOURCE")
        domain = "unknown"
        try:
            if alert.get("domain"):
                domain = str(alert.get("domain") or "unknown").strip() or "unknown"
            else:
                d = str(alert.get("detail") or "")
                if "Suspicious Domain:" in d:
                    domain = d.split("Suspicious Domain:", 1)[1].split("(", 1)[0].strip() or "unknown"
                elif "Suspicious DNS:" in d:
                    domain = d.split("Suspicious DNS:", 1)[1].split("(", 1)[0].strip() or "unknown"
        except Exception:
            domain = "unknown"
        if _is_noise_domain(domain):
            domain = "unknown"
        risk = int(getattr(state, "last_risk_score", 0) or 0)
        tl = str(state.get_threat_level() or "SUSPICIOUS")
        if risk >= 90:
            tl = "CRITICAL"
        proc = str(getattr(state, "last_process_name", "") or alert.get("process") or "external traffic").strip() or "external traffic"
        if proc.lower() == "unknown process":
            proc = "external traffic"
        atk = str(getattr(state, "last_attack_type", "") or alert.get("type") or "SUSPICIOUS_BEHAVIOR")
        act = str(action or "MONITOR").upper()
        try:
            from core.cloud_intel import is_likely_cloud_or_cdn

            if is_likely_cloud_or_cdn(str(ip or "")) and risk < 80 and tl in ("MALICIOUS", "CRITICAL"):
                tl = "SUSPICIOUS"
        except Exception:
            pass
        if risk >= 90 or tl == "CRITICAL":
            act = "BLOCK"
        return {
            "ip": str(ip or "unknown"),
            "domain": str(domain or "unknown"),
            "process": proc,
            "source_type": src_type,
            "risk": risk,
            "threat_level": tl,
            "attack_type": atk,
            "action": act,
            "reason": str(reason or "No reason provided"),
            "timestamp": datetime.now().isoformat(),
        }

    # ─── Hybrid persistence helpers (RAM primary) ───────────────────────────

    def _touch_ip_memory(self, ip: str, *, flags_delta: int = 0, block_inc: int = 0):
        """
        Update in-memory ip_memory without querying DB.
        marks the IP as dirty for periodic sync.
        """
        if not ip:
            return
        now = time.time()
        with self._ip_memory_lock:
            mem = self.ip_memory.get(ip)
            if mem is None:
                mem = {"total_flags": 0, "past_blocks": 0, "last_seen": now}
                self.ip_memory[ip] = mem
            mem["total_flags"] = int(mem.get("total_flags", 0) or 0) + int(flags_delta or 0)
            mem["past_blocks"] = int(mem.get("past_blocks", 0) or 0) + int(block_inc or 0)
            mem["last_seen"] = now

            self._ip_memory_dirty.add(ip)

            # Cap memory size (optional enhancement)
            if len(self.ip_memory) > self._ip_memory_max * 1.2:
                # Evict least-recently-seen entries to bound RAM.
                items = sorted(self.ip_memory.items(), key=lambda kv: kv[1].get("last_seen", 0.0))
                keep = dict(items[-self._ip_memory_max:])
                self.ip_memory = keep
                # Dirty set should be trimmed too
                self._ip_memory_dirty = {k for k in self._ip_memory_dirty if k in self.ip_memory}

    def _ip_memory_sync_loop(self):
        """Background periodic persistence sync: RAM -> DB (non-blocking for detection)."""
        import time as _time
        while True:
            try:
                _time.sleep(60)
                with self._ip_memory_lock:
                    dirty_ips = list(self._ip_memory_dirty)
                    snapshot = {ip: dict(self.ip_memory[ip]) for ip in dirty_ips if ip in self.ip_memory}
                    # Clear dirty set early; subsequent updates will re-add.
                    self._ip_memory_dirty.clear()

                if snapshot:
                    from data.database import save_ip_memory
                    for ip, data in snapshot.items():
                        save_ip_memory(ip, data)
            except Exception:
                # Never break core detection pipeline
                pass

    def _should_emit_threat_log(self, ip: str, detail: str) -> bool:
        """
        Dedup + cooldown: avoid duplicate DB rows / timeline flood for the same IP.
        Within 60s: merge into cache (count++), no new emit.
        Otherwise respect cooldown between emits (45s default).
        """
        if not ip:
            return True
        now = time.time()
        with self._threat_dedup_lock:
            ent = self.ip_last_seen_cache.get(ip)
            if ent is None:
                self.ip_last_seen_cache[ip] = {
                    "window_start": now,
                    "last_emit": now,
                    "event_count": 1,
                    "last_detail": detail[:300],
                }
                return True
            if now - float(ent.get("window_start", 0)) < self.THREAT_DEDUP_SEC:
                ent["event_count"] = int(ent.get("event_count", 0) or 0) + 1
                ent["last_detail"] = detail[:300]
                return False
            if now - float(ent.get("last_emit", 0)) < self.THREAT_LOG_COOLDOWN_SEC:
                ent["event_count"] = int(ent.get("event_count", 0) or 0) + 1
                ent["last_detail"] = detail[:300]
                ent["window_start"] = now
                return False
            ent["window_start"] = now
            ent["last_emit"] = now
            ent["event_count"] = int(ent.get("event_count", 0) or 0) + 1
            ent["last_detail"] = detail[:300]
            return True

    def _get_behavior(self, ip: str) -> IPBehaviorProfile:
        with self._lock:
            b = self._behavior.get(ip)
            if b is None:
                b = IPBehaviorProfile(ip)
                self._behavior[ip] = b
            return b

    def _source_type_from_ip(self, ip: str) -> str:
        """Normalized context class used by decision/risk logic."""
        return classify_source(ip)

    def _get_process_for_ip_cached(self, ip: str) -> str:
        """Best-effort process mapping from in-memory packet store (cached). One lookup round; else benign label."""
        now = time.time()
        with self._process_cache_lock:
            ent = self._process_cache.get(ip)
            if ent and (now - ent.get("ts", 0)) <= self._process_cache_ttl_sec:
                return ent.get("process") or "external traffic"

        process_name = ""
        try:
            from monitoring.packet_capture import packet_store
            recent_packets = packet_store.get_recent(n=250) or []
            for p in reversed(recent_packets):
                if p.get("src_ip") == ip and p.get("process"):
                    raw = (p.get("process") or "").strip()
                    if raw and raw.lower() != "none":
                        process_name = raw
                        break
        except Exception:
            pass

        if not process_name:
            process_name = "external traffic"

        with self._process_cache_lock:
            self._process_cache[ip] = {"process": process_name, "ts": now, "lookup_done": True}
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
        unknown_process = (
            (("unknown" in process_lower) or not process_lower.strip())
            and "external traffic" not in process_lower
        )

        source_type = self._source_type_from_ip(ip)  # SYSTEM | LOCAL_DEVICE | EXTERNAL_SOURCE

        # ─── Optional auto profile detection (safe + conservative) ──────────
        # Profiles only modify risk weights; decision thresholds remain unchanged.
        # Keep it conservative to avoid amplifying false positives.
        try:
            threat_type = (threat.get("type") or "").upper()
            detail = (threat.get("detail") or "").upper()

            dev_procs = {
                "code.exe", "cursor.exe", "vscode.exe", "pycharm64.exe", "idea64.exe",
                "sublime_text.exe", "notepad++.exe", "node.exe", "npm",
                "python.exe",
            }
            game_procs = {
                "steam.exe", "epicgameslauncher.exe", "leagueoflegends.exe", "dota2.exe",
                "fortnite.exe", "minecraftlauncher.exe", "robloxplayerbeta.exe",
                "csgo.exe", "valorant.exe",
            }

            is_dev_proc = any(p in process_lower for p in dev_procs)
            is_game_proc = any(p in process_lower for p in game_procs)

            has_many_ports = threat_type in {"PORT_SCAN", "SUSPICIOUS_PORTSCAN"} or ("PORTS" in detail and "60" in detail)
            udp_alert = (threat.get("protocol") == "UDP") or ("UDP" in detail)

            if has_many_ports and is_dev_proc:
                self.current_profile = "developer"
            elif udp_alert and is_game_proc:
                self.current_profile = "gaming"
            else:
                self.current_profile = "default"
        except Exception:
            # Safety: never crash risk computation due to profile logic.
            self.current_profile = getattr(self, "current_profile", "default") or "default"

        weights = self.get_active_weights()

        risk = 0
        reasons: list[str] = []

        # Positive signals (weights as requested)
        if confidence > 0.75:
            risk += weights.get("ml_confidence", 40)
            reasons.append(f"ML confidence high ({confidence:.2f} > 0.75): +{weights.get('ml_confidence', 40)}")
        # behavior_score is capped at 50 in this system; use >= to allow the weight to activate.
        if behavior_score >= 50:
            risk += weights.get("behavior_score", 20)
            reasons.append(f"Behavior score high ({behavior_score} >= 50): +{weights.get('behavior_score', 20)}")
        if source_type == "EXTERNAL_SOURCE":
            risk += weights.get("external_source", 10)
            reasons.append(f"External source: +{weights.get('external_source', 10)}")
        if unknown_process:
            risk += weights.get("unknown_process", 20)
            reasons.append(f"Unknown process: +{weights.get('unknown_process', 20)}")

        # Protection (as requested)
        trusted_processes = {
            "chrome.exe", "msedge.exe", "edge.exe", "explorer.exe",
            "whatsapp.exe", "teams.exe", "outlook.exe",
            "svchost.exe", "system", "winlogon.exe", "services.exe"
        }
        is_trusted_process = process_lower in trusted_processes

        if is_trusted_process:
            risk += weights.get("trusted_process", -30)
            reasons.append(f"Trusted process ({process_name}): {weights.get('trusted_process', -30)}")
        if source_type in ("SYSTEM", "LOCAL_DEVICE"):
            risk += weights.get("local_traffic", -20)
            reasons.append(f"Local traffic: {weights.get('local_traffic', -20)}")

        # Process context improvement:
        # known user/system processes reduce risk slightly to cut false positives.
        known_processes = {"chrome.exe", "msedge.exe", "whatsapp.exe", "system"}
        if process_lower in known_processes:
            risk -= 10
            reasons.append(f"Known process ({process_name}): -10")

        # ─── Persistent memory reinforcement (repeat attackers) ──────────
        # Uses RAM-loaded DB memory only (no real-time DB queries).
        try:
            mem = self.ip_memory.get(ip, {}) or {}
            past_blocks = int(mem.get("past_blocks", 0) or 0)
            total_flags = int(mem.get("total_flags", 0) or 0)

            # Small additive bias; final BLOCK still requires repetition + high confidence.
            if past_blocks >= 1:
                add = min(15, 5 * past_blocks)
                risk += add
                reasons.append(f"Repeat attacker: past_blocks={past_blocks} (+{add})")
            if total_flags >= 50:
                risk += 10
                reasons.append(f"Known noisy source: total_flags={total_flags} (+10)")
        except Exception:
            pass

        risk = max(0, min(100, int(risk)))
        reasons.append(f"Active profile: {self.current_profile}")
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
        source_type = classify_source(ip)

        # DNS false-positive reduction:
        # reverse DNS lookups (in-addr.arpa) should not increase threat score.
        if alert_type == "DNS_THREAT" and "in-addr.arpa" in detail.lower():
            score_delta = 0
            detail = f"{detail} [context: reverse DNS lookup ignored for scoring]"

        state = self._get_state(ip)
        state.add_score(score_delta, detail, alert_type)

        # Update persistent IP memory in RAM (no DB I/O here).
        # Treat each alert as a "flag" event.
        self._touch_ip_memory(ip, flags_delta=1)

        # "Save when total_flags increases significantly" requirement:
        # enqueue a DB upsert when total_flags hits coarse milestones.
        try:
            with self._ip_memory_lock:
                mem = self.ip_memory.get(ip, {})
                total_flags = int(mem.get("total_flags", 0) or 0)
            if total_flags > 0 and total_flags % 25 == 0:
                from data.database import save_ip_memory
                self._touch_ip_memory(ip, flags_delta=0)  # ensures last_seen updated
                with self._ip_memory_lock:
                    data = dict(self.ip_memory.get(ip, {}))
                save_ip_memory(ip, data)
        except Exception:
            pass

        # Update per-IP behavior profile (baseline learning)
        behavior = self._get_behavior(ip)
        behavior.update_from_profile(profile)
        behavior.record_alert(alert_type, alert)

        # Trigger Active Recon Logic - (Currently Disabled to Reduce Complexity/Remove Unnecessary Files)
        # To enable, create nmap_integration.py and uncomment below
        # if state.score >= 5 and ip != "GLOBAL_NETWORK":
        #     pass

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

        # Log to database + timeline (dedup/cooldown per IP — avoids duplicate cards / event flood)
        try:
            from data.database import log_event, log_action, block_entity_db
            process_name = getattr(state, "last_process_name", None) or alert.get("process") or "external traffic"
            if (process_name or "").strip().lower() in ("", "unknown process"):
                process_name = "external traffic"
            reasoning_str = getattr(state, "last_reasoning", "") or ""
            reasoning_list = getattr(state, "last_reasoning_list", []) or []
            repeat_count = int(getattr(state, "last_repeat_strong", 0) or 0)
            risk_score = int(getattr(state, "last_risk_score", state.score) or 0)
            merged_detail = f"{detail} | WHY: {reasoning_str}" if reasoning_str else detail
            emit_log = self._should_emit_threat_log(ip, merged_detail)
            if emit_log:
                self._event_timeline.append({
                    "timestamp": datetime.now().isoformat(),
                    "ip": ip,
                    "ip_type": source_type,
                    "event_type": alert_type,
                    "score_delta": score_delta,
                    "cumulative_score": state.score,
                    "severity": _downgrade_severity_for_source(severity, source_type),
                    "detail": merged_detail[:500],
                })
                log_event(
                    src_ip=ip,
                    dest_ip=alert.get("dst_ip", "LOCAL"),
                    src_port=alert.get("src_port", 0),
                    dst_port=alert.get("dst_port", 0),
                    protocol=alert.get("protocol", "OTHER"),
                    payload_size=alert.get("payload_size", 0),
                    severity=_downgrade_severity_for_source(severity, source_type),
                    anomaly_score=min(state.score / 10.0, 1.0),
                    active_window=source_type,
                    details={
                        "threat_level": state.get_threat_level(),
                        "alert_type": alert_type,
                        "action": action,
                        "source_type": source_type,
                        "process": process_name,
                        "event": alert_type,
                        "risk_score": risk_score,
                        "risk": risk_score,
                        "confidence": state.last_confidence,
                        "repeat_count": repeat_count,
                        "attack_type": getattr(state, "last_attack_type", "") or "",
                        "reasoning": reasoning_list,
                        "detail": merged_detail,
                        "reason": reasoning_str or detail,
                        "timestamp": datetime.now().isoformat(),
                    },
                    threat_score=state.score
                )
        except Exception:
            pass

        # ─── New: Domain-Specific Blocking for DNS Intelligence ───────────
        if alert_type == "DNS_THREAT":
            # Detail format: f"Suspicious Domain: {query} ({', '.join(reasons)})"
            domain = detail.split(": ")[1].split(" (")[0] if ": " in detail else ""
            if domain.lower().endswith(".in-addr.arpa"):
                return action

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
                    from data.database import block_entity_db_sync, log_action
                    ok_dom = block_domain(domain)
                    domain_threat = self._normalize_threat_object(
                        ip=ip,
                        alert={**alert, "domain": domain},
                        state=state,
                        action="BLOCK",
                        reason=f"High-confidence suspicious domain (repeat_hits={repeat_hits}): {detail}",
                        source_type=source_type,
                    )
                    domain_threat["domain"] = domain or "unknown"
                    if ok_dom:
                        block_entity_db_sync("DOMAIN", domain, f"High-confidence suspicious domain (repeat_hits={repeat_hits}): {detail}", threat_object=domain_threat)
                        log_action("DOMAIN", domain, "BLOCK", f"DNS score={score_delta}, repeat_hits={repeat_hits}")
                        print(f"[Executed] DOMAIN_BLOCK {domain} for ip={ip}")
                    else:
                        log_action("DOMAIN", domain, "BLOCK_FAILED", f"hosts/policy failed score={score_delta}")
                        print(f"[Executed] DOMAIN_BLOCK_FAILED {domain}")
                except Exception as e:
                    print(f"[Executed] DOMAIN_BLOCK_FAILED {domain} ({e})")

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
        signal_name_map = {
            "PORT_SCAN": "PORT_SCAN (reconnaissance)",
            "SUSPICIOUS_PORTSCAN": "SUSPICIOUS_PORTSCAN (reconnaissance)",
            "BRUTE_FORCE": "BRUTE_FORCE",
            "CONNECTION_BURST": "CONNECTION_SPIKE",
            "ML_ANOMALY": "ML_ANOMALY",
            "DNS_THREAT": "DNS_THREAT",
            "HIGH_RISK_PORT": "HIGH_RISK_PORT",
            "HONEYPOT_HIT": "HONEYPOT_HIT",
        }
        alert_type_u = str(alert.get("type") or "UNKNOWN").upper()
        reasoning_lines.append(f"Detected signal: {signal_name_map.get(alert_type_u, alert_type_u)}")
        if detail:
            reasoning_lines.append(f"Event detail: {str(detail)[:180]}")
        if has_recent_ml:
            reasoning_lines.append(f"ML anomaly present: score={last_ml_score:.1f} (recent)")
        if patterns:
            reasoning_lines.extend([f"Pattern: {p}" for p in patterns])
        if repeat_strong >= 3:
            reasoning_lines.append(f"Repeated strong signals: {repeat_strong} events/60s")
        elif repeat_strong > 0:
            reasoning_lines.append(f"Single event detected: {repeat_strong} events/60s")
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

        # Connection spike alone must not reach CRITICAL without ML/repeat corroboration.
        try:
            if (alert.get("type") or "") == "CONNECTION_BURST" and alert.get("spike_only"):
                if repeat_strong < 2 and not has_recent_ml:
                    if state.score > 8:
                        state.score = 8
            from core.cloud_intel import is_likely_cloud_or_cdn

            if is_likely_cloud_or_cdn(ip) and alert.get("spike_only") and repeat_strong < 2 and not has_recent_ml:
                if state.score > 6:
                    state.score = 6
        except Exception:
            pass

        # Resolve process and persist it for explainable logging.
        process_name = alert.get("process") or self._get_process_for_ip_cached(ip)
        state.last_process_name = process_name or "external traffic"

        # Progressive risk scoring (continuous accumulation + explainability).
        risk_engine = getattr(self, "_risk_engine", None)
        if risk_engine is None:
            # Defensive fallback: keep conservative behavior if risk engine fails.
            state.last_risk_score = int(getattr(state, "score", 0) or 0)
            state.action = "MONITOR"
            return "MONITOR"

        source_type = self._source_type_from_ip(ip)
        process_name = alert.get("process") or self._get_process_for_ip_cached(ip) or "unknown process"

        anomaly_ratio = 0.0
        try:
            # last_ml_score is already from MLDetector threat_delta; normalize to 0..~1 range.
            last_ml = float(behavior_snap.get("last_ml_score") or 0.0)
            anomaly_ratio = last_ml / 10.0
        except Exception:
            anomaly_ratio = 0.0

        risk, risk_reasons, attack_type = risk_engine.score_event(
            ip=ip,
            state=state,
            alert={**alert, "ip": ip},
            patterns=patterns,
            behavior_snap=behavior_snap,
            repeat_strong=repeat_strong,
            confidence=confidence,
            source_type=source_type,
            anomaly_ratio=anomaly_ratio,
            process_name=process_name,
            ip_memory=self.ip_memory,
        )

        # Confidence-based risk cap: prevent weak, low-confidence signals from exceeding MEDIUM risk.
        ml_anomaly = has_recent_ml or anomaly_ratio > 0.9
        multi_signal = repeat_strong >= 2
        if confidence < 0.3 and repeat_strong < 3 and not ml_anomaly and not multi_signal:
            risk = min(risk, 60)

        # Combine explainability (baseline patterns + progressive risk + attack intent).
        final_reasoning_list = list(reasoning_lines)
        final_reasoning_list.extend(risk_reasons)
        final_reasoning_list.append(
            f"attack_type={attack_type} | risk={risk} | repeat_strong={repeat_strong} | confidence={confidence:.2f}"
        )

        # Persist explainable outputs for log_event() in process_alert().
        state.last_risk_score = int(risk)
        state.last_attack_type = attack_type
        state.last_reasoning_list = final_reasoning_list
        state.last_reasoning = " | ".join(final_reasoning_list)

        # Progressive response behavior (centralized + explainable).
        from core.decision_engine import progressive_decide_action

        action = progressive_decide_action(
            risk=int(risk),
            repeat_strong=int(repeat_strong),
            confidence=float(confidence),
            source_type=source_type,
            attack_type=attack_type,
            threat_level=state.get_threat_level(),
        )

        # Tighten BLOCK condition: require at least one strong corroborating signal.
        # HONEYPOT_HIT is always treated as a strong signal regardless of repeat count.
        if action == "BLOCK":
            honeypot_hit = (
                (alert.get("type") or "") == "HONEYPOT_HIT"
                or (alert.get("attack_type") or "") == "HONEYPOT_HIT"
                or (attack_type or "") == "HONEYPOT_HIT"
            )
            has_strong = repeat_strong >= 3 or ml_anomaly or multi_signal or honeypot_hit
            if not has_strong:
                action = "LOG"

        if alert.get("domain"):
            try:
                state.last_domain = str(alert.get("domain") or "unknown").strip() or "unknown"
            except Exception:
                state.last_domain = "unknown"

        threat_object = self._normalize_threat_object(
            ip=ip, alert=alert, state=state, action=action, reason=" | ".join(final_reasoning_list[:6]), source_type=source_type
        )

        try:
            print(f"[Decision] {ip} | risk: {int(risk)} | action: {threat_object.get('action', action)}")
        except Exception:
            pass

        if action == "MONITOR":
            state.action = "MONITOR"
            return "MONITOR"

        if action == "LOG":
            state.action = "LOG"
            self._action_log.append({
                "timestamp": datetime.now().isoformat(),
                "ip": ip,
                "action": "LOG",
                "score": score,
                "reason": "LOG: " + " | ".join(final_reasoning_list[:6]),
            })
            return "LOG"

        # action == "BLOCK": execute blocking path and log status.
        reason = "Blocked because:\n- " + "\n- ".join(final_reasoning_list)
        blocked_ok = self._execute_block(ip, state, reason, permanent=False, alert=alert, source_type=source_type)
        try:
            print(f"[Executed] {'BLOCK' if blocked_ok else 'BLOCK_FAILED'} for {ip}")
        except Exception:
            pass
        return "BLOCK" if blocked_ok else "LOG"

    def _execute_block(self, ip, state, reason, permanent=False, alert=None, source_type=None):
        """Execute firewall block and update state."""
        from monitoring.packet_capture import get_ip_type
        try:
            from data.database import is_whitelisted
            if is_whitelisted("IP", ip):
                print(f"[Decision] {ip} | whitelist skip | action: BLOCK refused")
                return False
        except Exception:
            pass

        # Safety: never block local/protected interface IPs
        from monitoring.packet_capture import PROTECTED_IPS
        if ip in PROTECTED_IPS:
            return False

        if state.is_blocked:
            return True  # Already blocked (prior successful path)

        threat_object = self._normalize_threat_object(
            ip=ip,
            alert=alert or {},
            state=state,
            action="BLOCK",
            reason=reason,
            source_type=source_type or self._source_type_from_ip(ip),
        )

        # Persist to DB and firewall first; only then set is_blocked so the dashboard
        # cannot show BLOCK/BLOCKED while the blocked list has no matching row.
        try:
            from data.database import block_entity_db_sync, unblock_entity_db, log_action
            from defense.firewall import block_ip

            block_entity_db_sync("IP", ip, reason[:200], threat_object=threat_object)
            ok = block_ip(ip)
            if ok is False:
                try:
                    unblock_entity_db("IP", ip)
                except Exception:
                    pass
                print(f"[Executed] BLOCK_FAILED for {ip} (firewall)")
                try:
                    log_action("IP", ip, "BLOCK_FAILED", f"Firewall failed for {ip}")
                except Exception:
                    pass
                return False
        except Exception as e:
            print(f"[Executed] BLOCK_FAILED for {ip} (error: {e})")
            try:
                from data.database import log_action, unblock_entity_db
                try:
                    unblock_entity_db("IP", ip)
                except Exception:
                    pass
                log_action("IP", ip, "BLOCK_FAILED", f"{reason[:140]} | error={e}")
            except Exception:
                pass
            return False

        state.is_blocked = True
        state.blocked_at = time.time()
        state.action = "BLOCK"
        state.block_reason = reason

        with self._lock:
            self._blocked_ips.add(ip)
            self.blocked_registry[ip] = {
                "blocked_at": state.blocked_at,
                "duration": 120,
                "reason": reason,
            }

        self._touch_ip_memory(ip, block_inc=1)
        try:
            from data.database import save_ip_memory
            with self._ip_memory_lock:
                data = dict(self.ip_memory.get(ip, {"total_flags": 0, "past_blocks": 0, "last_seen": time.time()}))
            save_ip_memory(ip, data)
        except Exception:
            pass

        print(f"[Executed] BLOCK for {ip} (firewall+db ok)")

        self._action_log.append({
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "action": state.action,
            "score": state.score,
            "reason": reason,
        })

        try:
            from data.database import log_action, log_event
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

            log_action("IP", ip, "BLOCK", reason[:200])
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
                    "action": "BLOCK",
                    "threat_level": state.get_threat_level(),
                    "risk_score": int(getattr(state, "last_risk_score", state.score) or state.score),
                    "confidence": float(getattr(state, "last_confidence", 0.0) or 0.0),
                    "repeat_count": int(getattr(state, "last_repeat_strong", 0) or 0),
                    "reasoning": getattr(state, "last_reasoning_list", []) or [],
                    "attack_type": getattr(state, "last_attack_type", "") or "",
                    "process": process_name,
                    "detail": reason
                },
                threat_score=state.score
            )
        except Exception as e:
            print(f"[Executed] BLOCK for {ip} (post-log warning: {e})")

        return True

    def _unblock_monitor(self):
        """Background thread: auto-unblock + risk decay (self-healing)."""
        while True:
            try:
                self.check_auto_unblock()
            except Exception:
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

    # ─── Self-Healing: auto-unblock + decay ────────────────────────────────────

    def _remove_block(self, ip: str, state: IPThreatState, reason_suffix: str = "Auto-unblock after timeout"):
        """Centralized unblock logic with safe firewall + logging."""
        if not state.is_blocked:
            return

        state.is_blocked = False
        state.blocked_at = None
        # Extra safety: small risk decay on unblock.
        state.score = max(0, int(state.score * 0.9))

        with self._lock:
            self._blocked_ips.discard(ip)
            self.blocked_registry.pop(ip, None)

        print(f"[ThreatEngine] UNBLOCK: {ip} - {reason_suffix}")

        # Reverse firewall rule (best-effort, non-fatal on error).
        try:
            from defense.firewall import unblock_ip
            unblock_ip(ip)
        except Exception:
            pass

        try:
            from data.database import unblock_entity_db
            unblock_entity_db("IP", ip)
        except Exception:
            pass

        # Log unblock in actions + events for dashboard visibility.
        try:
            from data.database import log_action, log_event
            log_action("IP", ip, "UNBLOCK", reason_suffix)

            log_event(
                src_ip=ip,
                dest_ip="LOCAL",
                src_port=0,
                dst_port=0,
                protocol="DEFENSE",
                payload_size=0,
                severity=state.get_severity(),
                anomaly_score=min(state.score / 10.0, 1.0),
                active_window="UNBLOCK",
                details={
                    "event": "UNBLOCK",
                    "action": "UNBLOCK",
                    "reason": reason_suffix,
                    "risk_score": int(getattr(state, "last_risk_score", state.score) or state.score),
                    "confidence": float(getattr(state, "last_confidence", 0.0) or 0.0),
                    "repeat_count": int(getattr(state, "last_repeat_strong", 0) or 0),
                    "reasoning": getattr(state, "last_reasoning_list", []) or [],
                },
                threat_score=state.score,
            )
        except Exception:
            pass

    def check_auto_unblock(self):
        """
        Periodic self-healing:
        - Automatically unblocks IPs after their duration, if risk is low.
        - Extends block duration if risk remains high.
        - Applies global risk decay across all states.
        """
        now = time.time()

        # Snapshot for thread-safety
        with self._lock:
            registry_items = list(self.blocked_registry.items())
            states_snapshot = list(self._states.items())

        # Registry-driven auto-unblock with safe re-evaluation
        for ip, entry in registry_items:
            state = next((s for k, s in states_snapshot if k == ip), None)
            if not state or not state.is_blocked:
                with self._lock:
                    self.blocked_registry.pop(ip, None)
                continue

            blocked_at = entry.get("blocked_at", state.blocked_at or now)
            duration = int(entry.get("duration", 120) or 120)

            if now - blocked_at >= duration:
                # Safe re-evaluation before unblock
                if state.score < 30:
                    self._remove_block(ip, state, "Auto-unblock after timeout")
                else:
                    # Extend block duration for higher-risk IPs (no unblock yet)
                    entry["blocked_at"] = now
                    entry["duration"] = min(duration * 2, 1800)  # cap at 30 min

        # Legacy cooldown-based auto-unblock as a safety net
        for ip, state in states_snapshot:
            if state.should_auto_unblock():
                self._remove_block(ip, state, "Auto-unblock after cooldown")

        # Global risk decay (self-healing) for all tracked IPs
        for _, state in states_snapshot:
            state.decay_score()

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
            from data.database import log_action, unblock_entity_db
            unblock_ip(ip)
            unblock_entity_db("IP", ip)
            log_action("IP", ip, "MANUAL_UNBLOCK", "Manually unblocked by operator")
        except Exception:
            pass
        return True


# Global singleton
threat_engine = ThreatScoringEngine()
