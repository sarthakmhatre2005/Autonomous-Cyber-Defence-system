import json
import os
from datetime import datetime

LOG_FILE = "events.log"

def export_event(event):
    """
    Exports real threat events to a SIEM-compatible log file (Splunk Optimized).
    Format: JSON Lines (one event per line).
    """
    try:
        # Standardize fields for Splunk ingestion
        score = event.get("score", 0)
        
        payload = {
            "timestamp": event.get("timestamp") or datetime.utcnow().isoformat(),
            "export_time": datetime.utcnow().isoformat(),
            "ip": event.get("ip", "0.0.0.0"),
            "event_type": event.get("reason", "UNKNOWN"),
            "score": score,
            "severity": "HIGH" if score > 70 else "MEDIUM",
            "action": event.get("action", "MONITOR"),
            "sigma_rule": event.get("sigma_rule", "UNKNOWN_ANOMALY"),
            "raw_alert_type": event.get("type", "UNKNOWN")
        }

        # Ensure directory exists if needed (current directory is fine)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(payload) + "\n")

    except Exception as e:
        print("[SIEM EXPORT ERROR]", e)
