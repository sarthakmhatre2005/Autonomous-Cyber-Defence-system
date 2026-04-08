"""
Offline dataset builder for ML training.

Core rule: use only high-confidence labels.
- honeypot hits => label=1 (malicious)
- blocked IP entities (active=1, entity_type='IP') => label=1 (malicious)
- whitelisted IPs => label=0 (benign)
- everything else => label=-1 (unknown/unsure; excluded from training)

This module does NOT affect runtime detection/blocking logic.
"""

from __future__ import annotations

import csv
import json
import math
import os
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

import ipaddress

from data.database import DB_FILE


def _iso_to_epoch(ts: str) -> float | None:
    try:
        return datetime.fromisoformat(ts).timestamp()
    except Exception:
        return None


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default


def _source_type_from_ip(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version != 4:
            return "External Source"
        if ip.startswith("10."):
            return "Local Device"
        if ip.startswith("192.168."):
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


def load_events() -> list[dict]:
    """
    Load event rows from DB.

    SQL (efficient bulk fetch):
    SELECT src_ip, timestamp, protocol, src_port, dst_port, payload_size, severity,
           anomaly_score, threat_score, active_window, details
    FROM events
    """
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        """
        SELECT src_ip, timestamp, protocol, src_port, dst_port, payload_size, severity,
               anomaly_score, threat_score, active_window, details
        FROM events
        """
    )
    rows = cur.fetchall()
    conn.close()

    out: list[dict] = []
    for r in rows:
        out.append(
            {
                "src_ip": r["src_ip"],
                "timestamp": r["timestamp"],
                "protocol": r["protocol"],
                "src_port": r["src_port"],
                "dst_port": r["dst_port"],
                "payload_size": r["payload_size"],
                "severity": r["severity"],
                "anomaly_score": r["anomaly_score"],
                "threat_score": r["threat_score"],
                "active_window": r["active_window"],
                "details": r["details"],
            }
        )
    return out


def load_actions() -> list[dict]:
    """
    Load action rows from DB.

    SQL:
    SELECT entity_type, entity_value, timestamp, action_type, reason
    FROM actions
    """
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT entity_type, entity_value, timestamp, action_type, reason FROM actions")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def load_blocks() -> list[dict]:
    """
    Load high-confidence blocked IPs from DB.

    We only label malicious when:
    - active=1
    - entity_type='IP'

    SQL:
    SELECT entity_value, timestamp
    FROM blocked_entities
    WHERE active=1 AND entity_type='IP'
    """
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        """
        SELECT entity_value, timestamp, reason
        FROM blocked_entities
        WHERE active=1 AND entity_type='IP'
        """
    )
    rows = cur.fetchall()
    conn.close()

    out: list[dict] = []
    for r in rows:
        out.append(
            {
                "ip": r["entity_value"],
                "timestamp": r["timestamp"],
                "reason": r["reason"],
            }
        )
    return out


def load_honeypot() -> list[dict]:
    """
    Load honeypot hits from DB.

    SQL:
    SELECT source_ip, timestamp, honeypot_port, data
    FROM honeypot_events
    """
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    # Table may exist; if not, just return [].
    try:
        cur.execute("SELECT source_ip, timestamp, honeypot_port, data FROM honeypot_events")
    except sqlite3.Error:
        conn.close()
        return []

    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def is_high_confidence_block(ip: str, block_record: dict, ip_memory: dict, event_context: dict) -> bool:
    """
    Tier-1 malicious block:
    - IP has been blocked multiple times historically (past_blocks >= 2)
    - Current window threat_score is high (>= 11)
    - Current window risk_score is high (>= 80)

    Note: event_context is per-window, derived from behavior, not DB decisions.
    """
    mem = ip_memory.get(ip, {}) or {}
    past_blocks = int(mem.get("past_blocks", 0) or 0)
    threat_score = float(event_context.get("threat_score", 0.0) or 0.0)
    risk_score = float(event_context.get("risk_score", 0.0) or 0.0)
    return past_blocks >= 2 and threat_score >= 11.0 and risk_score >= 80.0


def is_strong_benign(ip: str, ip_history: dict) -> bool:
    """
    Strong benign definition:
    - never blocked (past_blocks == 0)
    - almost no flags (total_flags < 5)
    - very low average threat score (avg_threat_score < 3)
    - no high severity events (high_severity_count == 0)
    """
    return (
        ip_history.get("past_blocks", 0) == 0
        and ip_history.get("total_flags", 0) < 5
        and ip_history.get("avg_threat_score", 0.0) < 3.0
        and ip_history.get("high_severity_count", 0) == 0
    )


def _load_whitelist_ips() -> set[str]:
    """Whitelist IPs are treated as benign label=0."""
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT entity_value
            FROM whitelist
            WHERE entity_type='IP'
            """
        )
        rows = cur.fetchall()
    except sqlite3.Error:
        conn.close()
        return set()
    conn.close()
    return {str(r["entity_value"]) for r in rows if r["entity_value"]}


def _entropy_from_counts(counts: dict[int, int]) -> float:
    """Normalized Shannon entropy in [0,1]."""
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    n = len([c for c in counts.values() if c > 0])
    if n <= 1:
        return 0.0

    ent = 0.0
    for c in counts.values():
        if c <= 0:
            continue
        p = c / total
        ent -= p * math.log(p + 1e-12)

    # Normalize by log(n)
    return float(ent / math.log(n + 1e-12))


@dataclass(frozen=True)
class DatasetRow:
    # identifiers
    ip: str
    window_start: float
    label: int

    # features (strings / categoricals)
    protocol_mode: str
    process_name_mode: str
    source_type: str

    # numeric features
    anomaly_score_mean: float
    anomaly_score_max: float
    threat_score_mean: float
    event_count_60: int
    request_rate_60: float
    unique_ports_60: int
    port_entropy_60: float
    event_count_10: int
    request_rate_10: float
    burst_score_10: float
    interarrival_variance_10: float
    repeat_count_max: int
    time_since_prev_seen: float
    total_flags: int
    past_blocks: int
    last_seen_age: float


def build_training_dataset(
    output_csv: str | None = None,
    window_sec: int = 60,
    subwindow_sec: int = 10,
    label_delta_sec: int = 300,
    limit_windows: int | None = None,
) -> tuple[list[dict], list[int]]:
    """
    Build dataset from existing DB telemetry.

    Output:
    - writes CSV to `data/training_dataset.csv` by default
    - returns (X_rows, y_labels)
    """
    if output_csv is None:
        output_csv = os.path.join(os.path.dirname(__file__), "training_dataset.csv")

    events = load_events()
    blocks = load_blocks()
    honeypot_hits = load_honeypot()
    whitelist_ips = _load_whitelist_ips()

    # Load ip_memory to provide persistent features (optional but helpful).
    try:
        from data.database import load_ip_memory
        ip_memory = load_ip_memory() or {}
    except Exception:
        ip_memory = {}

    # Index honeypot + blocks timestamps by IP for label matching.
    honeypot_ts_by_ip: dict[str, list[float]] = defaultdict(list)
    for h in honeypot_hits:
        ip = str(h.get("source_ip", "")).strip()
        if not ip:
            continue
        ts = _iso_to_epoch(h.get("timestamp", ""))
        if ts is None:
            continue
        honeypot_ts_by_ip[ip].append(ts)

    blocked_ts_by_ip: dict[str, list[float]] = defaultdict(list)
    for b in blocks:
        ip = str(b.get("ip", "")).strip()
        if not ip:
            continue
        ts = _iso_to_epoch(b.get("timestamp", ""))
        if ts is None:
            continue
        blocked_ts_by_ip[ip].append(ts)

    # Parse and group events by (ip, window_start).
    grouped: dict[tuple[str, float], list[dict]] = defaultdict(list)
    for ev in events:
        ip = str(ev.get("src_ip", "")).strip()
        if not ip:
            continue
        ts = _iso_to_epoch(ev.get("timestamp", ""))
        if ts is None:
            continue

        # Build a window from event timestamps.
        window_start = float(int(ts // window_sec) * window_sec)
        grouped[(ip, window_start)].append(ev)

    # For each IP, compute previous window's last timestamp (time_since_prev_seen).
    last_ts_by_ip_window: dict[str, list[tuple[float, float]]] = defaultdict(list)
    for (ip, wstart), evs in grouped.items():
        last_ts = max(_iso_to_epoch(e.get("timestamp", "")) or 0.0 for e in evs)
        first_ts = min(_iso_to_epoch(e.get("timestamp", "")) or 0.0 for e in evs)
        last_ts_by_ip_window[ip].append((wstart, last_ts if last_ts > 0 else first_ts))

    prev_seen_delta: dict[tuple[str, float], float] = {}
    for ip, lst in last_ts_by_ip_window.items():
        lst.sort(key=lambda x: x[0])
        prev_last = None
        prev_last_ts = None
        for idx, (wstart, last_ts) in enumerate(lst):
            if idx == 0:
                prev_seen_delta[(ip, wstart)] = 0.0
            else:
                # delta between previous window last timestamp and current window start
                prev_seen_delta[(ip, wstart)] = max(0.0, (wstart - (prev_last_ts or wstart)))
            prev_last_ts = last_ts
            prev_last = last_ts

    # For strong-benign detection we also need per-IP aggregates.
    ip_threat_sum: dict[str, float] = defaultdict(float)
    ip_window_count: dict[str, int] = defaultdict(int)
    ip_high_sev_count: dict[str, int] = defaultdict(int)

    # Build dataset rows.
    now = datetime.now().timestamp()
    rows: list[DatasetRow] = []

    # Optional cap on number of windows (useful for quick smoke tests).
    window_count = 0

    for (ip, wstart), evs in grouped.items():
        if limit_windows is not None and window_count >= limit_windows:
            break
        window_count += 1

        # Sort events by timestamp.
        evs_sorted = sorted(evs, key=lambda e: _iso_to_epoch(e.get("timestamp", "")) or 0.0)

        # Split into last subwindow [wstart+window_sec-subwindow_sec, wstart+window_sec)
        sub_start = wstart + (window_sec - subwindow_sec)
        ts_sub: list[float] = []
        dst_ports_60: list[int] = []
        port_counts: dict[int, int] = defaultdict(int)
        protocol_counts: Counter[str] = Counter()
        process_counts: Counter[str] = Counter()

        anomaly_vals: list[float] = []
        threat_vals: list[float] = []
        repeat_counts: list[int] = []

        any_high_sev = False
        for e in evs_sorted:
            ts = _iso_to_epoch(e.get("timestamp", "")) or 0.0
            if ts < wstart:
                continue
            if ts >= wstart + window_sec:
                continue

            protocol_counts[str(e.get("protocol", "OTHER") or "OTHER")] += 1

            anomaly_vals.append(_safe_float(e.get("anomaly_score", 0.0)))
            threat_vals.append(_safe_float(e.get("threat_score", 0.0)))

            # Parse details JSON for process/repeat_count (if present)
            details_raw = e.get("details") or "{}"
            try:
                details = json.loads(details_raw) if isinstance(details_raw, str) else (details_raw or {})
            except Exception:
                details = {}
            proc = str(details.get("process") or "unknown process")
            process_counts[proc] += 1

            repeat_counts.append(_safe_int(details.get("repeat_count", 0), 0))

            dst_port = _safe_int(e.get("dst_port", 0), 0)
            if dst_port and dst_port > 0:
                dst_ports_60.append(dst_port)
                port_counts[dst_port] += 1

            if sub_start <= ts < (wstart + window_sec):
                ts_sub.append(ts)

            sev = str(e.get("severity", "") or "").upper()
            if sev == "HIGH":
                any_high_sev = True

        protocol_mode = protocol_counts.most_common(1)[0][0] if protocol_counts else "OTHER"
        process_name_mode = process_counts.most_common(1)[0][0] if process_counts else "unknown process"

        # Burst score: variance of inter-arrival within last subwindow.
        ts_sub_sorted = sorted(ts_sub)
        if len(ts_sub_sorted) >= 2:
            intervals = [ts_sub_sorted[i] - ts_sub_sorted[i - 1] for i in range(1, len(ts_sub_sorted))]
            interarrival_variance = float(statistics_variance(intervals))
            burst_score = interarrival_variance
        else:
            interarrival_variance = 0.0
            burst_score = 0.0

        anomaly_mean = float(sum(anomaly_vals) / len(anomaly_vals)) if anomaly_vals else 0.0
        anomaly_max = float(max(anomaly_vals)) if anomaly_vals else 0.0
        threat_mean = float(sum(threat_vals) / len(threat_vals)) if threat_vals else 0.0

        event_count_60 = len([e for e in evs_sorted if (_iso_to_epoch(e.get("timestamp", "")) or 0.0) < wstart + window_sec])
        request_rate_60 = float(event_count_60 / float(window_sec))

        ports_unique = len(set(dst_ports_60))
        port_entropy_60 = _entropy_from_counts(port_counts)

        # subwindow metrics
        event_count_10 = len(ts_sub_sorted)
        request_rate_10 = float(event_count_10 / float(subwindow_sec))

        repeat_count_max = max(repeat_counts) if repeat_counts else 0

        time_since_prev = float(prev_seen_delta.get((ip, wstart), 0.0))

        mem = ip_memory.get(ip, {}) or {}
        total_flags = int(mem.get("total_flags", 0) or 0)
        past_blocks = int(mem.get("past_blocks", 0) or 0)
        last_seen = float(mem.get("last_seen", 0.0) or 0.0)
        last_seen_age = float(now - last_seen) if last_seen > 0 else 0.0

        # Accumulate per-IP history for strong-benign logic.
        ip_threat_sum[ip] += threat_mean
        ip_window_count[ip] += 1
        if any_high_sev:
            ip_high_sev_count[ip] += 1

        # Label assignment using strict high-confidence rules (Tier-1).
        w_end = wstart + window_sec
        malicious = False
        for t in honeypot_ts_by_ip.get(ip, []):
            if (wstart - label_delta_sec) <= t <= (w_end + label_delta_sec):
                malicious = True
                break
        if not malicious:
            for t in blocked_ts_by_ip.get(ip, []):
                if (wstart - label_delta_sec) <= t <= (w_end + label_delta_sec):
                    # Build minimal context from this window and persistent memory
                    ctx = {
                        "threat_score": threat_mean,
                        # risk approx: reuse threat_mean scale (0-10) -> 0-100
                        "risk_score": threat_mean * 10.0,
                    }
                    block_rec = {"ip": ip, "timestamp": t}
                    if is_high_confidence_block(ip, block_rec, ip_memory, ctx):
                        malicious = True
                        break

        if malicious:
            label = 1
        else:
            label = -1

        rows.append(
            DatasetRow(
                ip=ip,
                window_start=wstart,
                label=label,
                protocol_mode=protocol_mode,
                process_name_mode=process_name_mode,
                source_type=_source_type_from_ip(ip),
                anomaly_score_mean=anomaly_mean,
                anomaly_score_max=anomaly_max,
                threat_score_mean=threat_mean,
                event_count_60=int(event_count_60),
                request_rate_60=request_rate_60,
                unique_ports_60=int(ports_unique),
                port_entropy_60=port_entropy_60,
                event_count_10=int(event_count_10),
                request_rate_10=request_rate_10,
                burst_score_10=float(burst_score),
                interarrival_variance_10=float(interarrival_variance),
                repeat_count_max=int(repeat_count_max),
                time_since_prev_seen=time_since_prev,
                total_flags=int(total_flags),
                past_blocks=int(past_blocks),
                last_seen_age=float(last_seen_age),
            )
        )

    # Build per-IP history for strong-benign labeling
    ip_history: dict[str, dict] = {}
    for ip, cnt in ip_window_count.items():
        if cnt <= 0:
            continue
        avg_threat = float(ip_threat_sum[ip] / cnt)
        ip_mem = ip_memory.get(ip, {}) or {}
        ip_history[ip] = {
            "past_blocks": int(ip_mem.get("past_blocks", 0) or 0),
            "total_flags": int(ip_mem.get("total_flags", 0) or 0),
            "avg_threat_score": avg_threat,
            "high_severity_count": int(ip_high_sev_count.get(ip, 0) or 0),
        }

    # Apply strong-benign labeling (conservative; only upgrade -1 -> 0)
    for idx, r in enumerate(rows):
        if r.label != -1:
            continue
        hist = ip_history.get(r.ip)
        if hist and is_strong_benign(r.ip, hist):
            rows[idx] = replace(r, label=0)

    # Write CSV
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    fieldnames = [
        "ip",
        "window_start",
        "protocol_mode",
        "process_name_mode",
        "source_type",
        "anomaly_score_mean",
        "anomaly_score_max",
        "threat_score_mean",
        "event_count_60",
        "request_rate_60",
        "unique_ports_60",
        "port_entropy_60",
        "event_count_10",
        "request_rate_10",
        "burst_score_10",
        "interarrival_variance_10",
        "repeat_count_max",
        "time_since_prev_seen",
        "total_flags",
        "past_blocks",
        "last_seen_age",
        "label",
    ]

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(
                {
                    "ip": r.ip,
                    "window_start": r.window_start,
                    "protocol_mode": r.protocol_mode,
                    "process_name_mode": r.process_name_mode,
                    "source_type": r.source_type,
                    "anomaly_score_mean": r.anomaly_score_mean,
                    "anomaly_score_max": r.anomaly_score_max,
                    "threat_score_mean": r.threat_score_mean,
                    "event_count_60": r.event_count_60,
                    "request_rate_60": r.request_rate_60,
                    "unique_ports_60": r.unique_ports_60,
                    "port_entropy_60": r.port_entropy_60,
                    "event_count_10": r.event_count_10,
                    "request_rate_10": r.request_rate_10,
                    "burst_score_10": r.burst_score_10,
                    "interarrival_variance_10": r.interarrival_variance_10,
                    "repeat_count_max": r.repeat_count_max,
                    "time_since_prev_seen": r.time_since_prev_seen,
                    "total_flags": r.total_flags,
                    "past_blocks": r.past_blocks,
                    "last_seen_age": r.last_seen_age,
                    "label": r.label,
                }
            )

    # Return X/y for convenience (training script can read CSV too)
    X_rows: list[dict] = []
    y: list[int] = []
    for r in rows:
        X_rows.append(
            {
                "ip": r.ip,
                "window_start": r.window_start,
                "protocol_mode": r.protocol_mode,
                "process_name_mode": r.process_name_mode,
                "source_type": r.source_type,
                "anomaly_score_mean": r.anomaly_score_mean,
                "anomaly_score_max": r.anomaly_score_max,
                "threat_score_mean": r.threat_score_mean,
                "event_count_60": r.event_count_60,
                "request_rate_60": r.request_rate_60,
                "unique_ports_60": r.unique_ports_60,
                "port_entropy_60": r.port_entropy_60,
                "event_count_10": r.event_count_10,
                "request_rate_10": r.request_rate_10,
                "burst_score_10": r.burst_score_10,
                "interarrival_variance_10": r.interarrival_variance_10,
                "repeat_count_max": r.repeat_count_max,
                "time_since_prev_seen": r.time_since_prev_seen,
                "total_flags": r.total_flags,
                "past_blocks": r.past_blocks,
                "last_seen_age": r.last_seen_age,
            }
        )
        y.append(r.label)

    return X_rows, y


def statistics_variance(values: list[float]) -> float:
    """Small helper: population variance to avoid importing statistics module overhead."""
    n = len(values)
    if n <= 1:
        return 0.0
    mean = sum(values) / n
    return float(sum((v - mean) ** 2 for v in values) / n)


if __name__ == "__main__":
    # Reproducible offline dataset generation.
    # Usage: python data/dataset_builder.py
    build_training_dataset()
