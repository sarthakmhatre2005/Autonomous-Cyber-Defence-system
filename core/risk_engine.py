"""
Progressive, context-aware risk engine.

Design goals:
- Continuous accumulation (no single threshold dependency)
- Early escalation on rapid activity
- Strong-signal override (ML anomaly + honeypot)
- Conditional correlation boosts
- Lightweight distributed attack detection (global, port-scoped)
- Explainability: returns reasons + attack_type

This module does NOT make blocking decisions by itself; it returns
risk + suggested action/intent for ThreatScoringEngine to enforce safety rules.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any


class RiskEngine:
    def __init__(self):
        # port -> deque[(ts, ip, alert_type, confidence)]
        self._port_hits: dict[int, deque[tuple[float, str, str, float]]] = defaultdict(
            lambda: deque(maxlen=300)
        )
        self._coordinated_window_sec = 30.0
        self._coordinated_min_ips = 2
        self._coordinated_min_strong_hits = 1

    def _count_recent_seen(self, seen_times: list[float], now: float, window_sec: float) -> int:
        cnt = 0
        cutoff = now - window_sec
        for t in seen_times[-50:]:
            try:
                if float(t) >= cutoff:
                    cnt += 1
            except Exception:
                continue
        return cnt

    def _is_port_scan_pattern(self, patterns: list[str]) -> bool:
        return any("rapid multi-port access" in p for p in patterns)

    def _is_burst_pattern(self, patterns: list[str]) -> bool:
        return any("bursty timing" in p for p in patterns) or any("abnormal spike" in p for p in patterns)

    def _detect_coordinated_attack(
        self,
        *,
        now: float,
        alert: dict,
        confidence: float,
    ) -> tuple[bool, int]:
        """
        Lightweight distributed attack: multiple IPs hitting same port in a short time window.
        """
        # Best-effort port extraction.
        port = alert.get("target_port") or alert.get("dst_port") or alert.get("src_port") or 0
        try:
            port = int(port or 0)
        except Exception:
            port = 0
        if port <= 0:
            return False, 0

        ip = str(alert.get("ip") or "")
        alert_type = str(alert.get("type") or "UNKNOWN")
        if not ip:
            return False, 0

        dq = self._port_hits[port]
        dq.append((now, ip, alert_type, float(confidence or 0.0)))

        cutoff = now - self._coordinated_window_sec
        ips = set()
        strong_hits = 0
        for ts, hit_ip, hit_type, hit_conf in list(dq):
            if ts < cutoff:
                continue
            ips.add(hit_ip)
            if hit_conf >= 0.75:
                strong_hits += 1

        is_coordinated = (
            len(ips) >= self._coordinated_min_ips
            and strong_hits >= self._coordinated_min_strong_hits
        )
        return is_coordinated, len(ips)

    def score_event(
        self,
        *,
        ip: str,
        state: Any,
        alert: dict,
        patterns: list[str],
        behavior_snap: dict,
        repeat_strong: int,
        confidence: float,
        source_type: str,
        anomaly_ratio: float,
        process_name: str,
        ip_memory: dict,
    ) -> tuple[int, list[str], str]:
        """
        Returns:
        - risk: 0..100 (int)
        - reasons: explainability list[str]
        - attack_type: simple intent mapping for logging/UI
        """
        now = time.time()
        risk_prev = int(getattr(state, "last_risk_score", 0) or 0)

        seen_times = behavior_snap.get("seen_times") or []
        attempts_in_5s = self._count_recent_seen(seen_times, now, window_sec=5.0)

        port_scan = self._is_port_scan_pattern(patterns)
        burst = self._is_burst_pattern(patterns)
        ml_anomaly_strong = anomaly_ratio > 0.9
        honeypot_hit = str(alert.get("type") or "") == "HONEYPOT_HIT"

        alert_type_u = str(alert.get("type") or "").upper()
        spike_only = bool(alert.get("spike_only")) and alert_type_u == "CONNECTION_BURST"

        # Isolated connection spike: small risk bump only (no +40/+50 style escalation).
        if spike_only:
            bump = 7
            if repeat_strong >= 2:
                bump = min(18, 10 + repeat_strong * 2)
            if ml_anomaly_strong:
                bump = min(25, bump + 10)
            risk = risk_prev + bump
            reasons = [
                f"connection_spike_only=+{bump} (capped; corroboration={'yes' if (repeat_strong >= 2 or ml_anomaly_strong) else 'no'})",
            ]
            # Still apply memory for repeat offenders, lightly
            mem = ip_memory.get(ip, {}) or {}
            past_blocks = int(mem.get("past_blocks", 0) or 0)
            if past_blocks >= 1:
                mem_add = min(12, 4 * past_blocks)
                risk += mem_add
                reasons.append(f"memory_add=+{mem_add} (past_blocks={past_blocks})")
            proc_lower = (process_name or "").lower()
            trusted_processes = {"chrome.exe", "msedge.exe", "whatsapp.exe", "system"}
            if proc_lower in trusted_processes:
                risk -= 8
                reasons.append("process_trust_penalty=-8")
            try:
                from core.cloud_intel import is_likely_cloud_or_cdn

                if is_likely_cloud_or_cdn(ip) and repeat_strong < 2 and not ml_anomaly_strong:
                    risk -= 15
                    reasons.append("cloud_cdn_benign_hint=-15")
            except Exception:
                pass
            risk = max(0, min(100, int(risk)))
            attack_type = "CONNECTION_SPIKE"
            return risk, reasons, attack_type

        # --- Base increment (continuous accumulation) ---
        base_increment = 5
        if source_type == "SYSTEM":
            base_increment = 1
        elif source_type == "LOCAL_DEVICE":
            base_increment = 3

        risk = risk_prev + base_increment
        reasons = [f"base_increment=+{base_increment} (source={source_type})"]

        # --- Early escalation: rapid first attempts ---
        if attempts_in_5s >= 3:
            early_boost = 20
            risk += early_boost
            reasons.append(f"early_boost=+{early_boost} (>=3 events/5s: {attempts_in_5s})")

        # --- Strong signal override ---
        if ml_anomaly_strong:
            large_boost = 25
            risk += large_boost
            reasons.append(f"strong_ml_boost=+{large_boost} (anomaly_ratio={anomaly_ratio:.2f})")
        if honeypot_hit:
            large_boost = 35
            risk += large_boost
            reasons.append(f"honeypot_boost=+{large_boost}")

        # --- Repetition: multiply when repeated pattern appears ---
        # This is intentionally multiplicative to avoid hard thresholds.
        if repeat_strong >= 2 and (port_scan or burst or honeypot_hit):
            risk = int(risk * 1.2)
            reasons.append("repeat_multiplier=×1.2 (repeat_strong>=2 and suspicious pattern)")
        if repeat_strong >= 3:
            risk = int(risk * 1.2)
            reasons.append("repeat_multiplier=×1.2 (repeat_strong>=3)")

        # --- Conditional correlation boosts ---
        if port_scan and burst:
            high_boost = 15
            risk += high_boost
            reasons.append(f"conditional_correlation=+{high_boost} (port_scan AND burst)")

        proc_l = (process_name or "").lower()
        unknown_process = (not process_name) or (
            "unknown" in proc_l and "external traffic" not in proc_l
        )
        if (ml_anomaly_strong or confidence >= 0.75) and unknown_process:
            high_boost = 15
            risk += high_boost
            reasons.append(f"conditional_correlation=+{high_boost} (anomaly AND unknown_process)")

        # --- Memory-based persistence ---
        mem = ip_memory.get(ip, {}) or {}
        past_blocks = int(mem.get("past_blocks", 0) or 0)
        total_flags = int(mem.get("total_flags", 0) or 0)
        if past_blocks >= 1:
            mem_add = min(20, 5 * past_blocks)
            risk += mem_add
            reasons.append(f"memory_add=+{mem_add} (past_blocks={past_blocks})")

        # Escalate faster for repeat offenders by adding fraction of previous risk.
        if risk_prev > 0:
            mem_factor = 0.10 + min(0.20, past_blocks * 0.05)
            mem_risk = int(risk_prev * mem_factor)
            risk += mem_risk
            reasons.append(f"memory_prev_risk_add=+{mem_risk} (factor={mem_factor:.2f})")

        if total_flags >= 100:
            risk += 10
            reasons.append("memory_total_flags_boost=+10 (total_flags>=100)")

        # --- Local trust override (never blindly trust) ---
        if source_type in ("SYSTEM", "LOCAL_DEVICE"):
            # Default reduction is already reflected in base_increment,
            # but we remove additional reductions if behavior is repeated/suspicious.
            if repeat_strong >= 2:
                reasons.append("local_reduction_removed (repeat_strong>=2)")

        # Process trust refinement (do not fully eliminate trust)
        trusted_processes = {"chrome.exe", "msedge.exe", "whatsapp.exe", "system"}
        proc_lower = (process_name or "").lower()
        if proc_lower in trusted_processes:
            # Reduce penalty if anomaly is strong.
            penalty = -10
            if ml_anomaly_strong or confidence >= 0.8:
                penalty = -5
            risk += penalty
            reasons.append(f"process_trust_penalty={penalty} (process={process_name})")

        # --- Lightweight distributed attack detection ---
        is_coord, n_ips = self._detect_coordinated_attack(
            now=now, alert={**alert, "ip": ip}, confidence=confidence
        )
        if is_coord:
            global_boost = 10
            risk += global_boost
            reasons.append(f"coordinated_global_boost=+{global_boost} (same_port_ips={n_ips})")

        # --- Attack intent mapping for explainability ---
        attack_type = "SUSPICIOUS_BEHAVIOR"
        alert_type = str(alert.get("type") or "")
        if alert_type in ("PORT_SCAN", "SUSPICIOUS_PORTSCAN"):
            attack_type = "RECONNAISSANCE"
        elif alert_type == "BRUTE_FORCE":
            attack_type = "ACCESS_ATTEMPT"
        elif honeypot_hit:
            attack_type = "HONEYPOT_HIT"
        elif ml_anomaly_strong or alert_type == "ML_ANOMALY":
            attack_type = "SUSPICIOUS_BEHAVIOR"

        # --- Clamp ---
        risk = max(0, min(100, int(risk)))
        return risk, reasons, attack_type


# Global singleton (lightweight)
risk_engine = RiskEngine()

