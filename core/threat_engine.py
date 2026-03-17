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

        # Start auto-unblock monitor
        t = threading.Thread(target=self._unblock_monitor, daemon=True)
        t.start()

    def _get_state(self, ip):
        with self._lock:
            if ip not in self._states:
                self._states[ip] = IPThreatState(ip)
            return self._states[ip]

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

        # Trigger Active Recon if score is becoming significant
        if state.score >= 5 and ip != "GLOBAL_NETWORK":
            try:
                from nmap_integration import nmap_recon
                nmap_recon.trigger_scan(ip)
            except:
                pass

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
        action = self._decide_action(ip, state, alert)

        # Log to database
        try:
            from data.database import log_event, log_action, block_entity_db
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
                    "detail": detail
                },
                threat_score=state.score
            )
        except Exception:
            pass

        # ─── New: Domain-Specific Blocking for DNS Intelligence ───────────
        if alert_type == "DNS_THREAT":
            # Detail format: f"Suspicious Domain: {query} ({', '.join(reasons)})"
            domain = detail.split(": ")[1].split(" (")[0] if ": " in detail else ""
            if domain and score_delta >= 6:
                try:
                    from defense.firewall import block_domain
                    block_domain(domain)
                    from data.database import block_entity_db, log_action
                    block_entity_db("DOMAIN", domain, f"Suspicious domain detected: {detail}")
                    log_action("DOMAIN", domain, "BLOCK", f"Heuristic Score {score_delta}")
                except:
                    pass

        return action

    def _decide_action(self, ip, state, alert):
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

        if score >= 11 and evidence_count >= 3:
            action = "BLOCK"
            self._execute_block(ip, state, f"Score {score} - {state.evidence[-1]['type'] if state.evidence else 'multiple alerts'}", permanent=True)

        elif score >= 7 and evidence_count >= 2:
            action = "TEMP_BLOCK"
            self._execute_block(ip, state, f"Score {score} - Suspicious pattern detected", permanent=False)

        elif score >= 4:
            action = "LOG"
            state.action = action
            self._action_log.append({
                "timestamp": datetime.now().isoformat(),
                "ip": ip,
                "action": action,
                "score": score,
                "reason": f"Suspicious activity (score={score})"
            })

        elif score == 0:
            action = "MONITOR"
            state.action = action

        return action

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

        # Safety: never block localhost
        if ip in {"127.0.0.1", "::1", "localhost"}:
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
            block_entity_db("IP", ip, reason[:200])
            log_action("IP", ip, state.action, reason[:200])
            block_ip(ip)
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
