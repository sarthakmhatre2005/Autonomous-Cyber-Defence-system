import os
import psutil
from data.database import log_action, block_entity_db, get_recent_actions
from defense.firewall import block_ip, block_domain

def enforce_response(target_type, target_value, reason, severity="HIGH"):
    """
    Orchestrates autonomous defense responses.
    """
    print(f"[DecisionEngine] Enforcing {target_type} protection on {target_value} - Reason: {reason}")
    
    if target_type == "IP":
        block_ip(target_value)
        block_entity_db("IP", target_value, reason)
        log_action("IP", target_value, "BLOCK", reason)
        
    elif target_type == "DOMAIN":
        block_domain(target_value)
        block_entity_db("DOMAIN", target_value, reason)
        log_action("DOMAIN", target_value, "BLOCK", reason)
        
    elif target_type == "PROCESS":
        # Process termination is usually handled in process_monitor, 
        # but we centralize here for consistency
        try:
            for proc in psutil.process_iter(['name', 'pid']):
                if proc.info['name'] == target_value:
                    print(f"[DecisionEngine] Terminating malicious process: {target_value} (PID: {proc.info['pid']})")
                    proc.terminate()
            block_entity_db("PROCESS", target_value, reason)
            log_action("PROCESS", target_value, "TERMINATE", reason)
        except Exception as e:
            print(f"[DecisionEngine] Error terminating process {target_value}: {e}")

def evaluate_threat_action(ip, score, evidence_count):
    """
    Determines the appropriate action level based on threat score.
    0-3: MONITOR
    4-6: LOG/SUSPICIOUS
    7-9: TEMP_BLOCK
    10+: BLOCK
    """
    if score >= 10 and evidence_count >= 3:
        return "BLOCK"
    elif score >= 7 and evidence_count >= 2:
        return "TEMP_BLOCK"
    elif score >= 4:
        return "LOG"
    return "MONITOR"


def progressive_decide_action(
    *,
    risk: int,
    repeat_strong: int,
    confidence: float,
    source_type: str,
    attack_type: str,
    threat_level: str = "",
) -> str:
    """
    Safety-biased progressive escalation.

    Returns one of: MONITOR | LOG | BLOCK
    Mandatory BLOCK when risk >= 90 or threat_level is CRITICAL (unless whitelisted at execution).
    """
    source_type = (source_type or "").upper().strip()

    thr = (threat_level or "").upper().strip()

    # Critical override (except whitelist checks in execution layer).
    if risk >= 90 or thr == "CRITICAL":
        return "BLOCK"

    # Internal safety rule: do not block internal unless extremely high risk.
    if source_type in ("SYSTEM", "LOCAL_DEVICE") and risk < 80:
        return "MONITOR"

    # Single strong signals should be visible early.
    if risk < 60:
        if (attack_type or "") == "HONEYPOT_HIT":
            return "LOG"
        # Single strong ML anomalies should be visible immediately.
        if (attack_type or "") == "SUSPICIOUS_BEHAVIOR":
            return "LOG"
        return "MONITOR"

    # Moderate-high risk: log / monitor.
    if risk < 80:
        return "LOG"

    # Very high risk: require strong confirmation.
    if repeat_strong >= 3 and confidence > 0.8:
        return "BLOCK"

    return "LOG"

def evaluate_event(event):
    """
    Decides validation based on severity and history.
    Event dict: {timestamp, source_ip, path, severity, anomaly_score, ...}
    """
    severity = event['severity']
    ip = event['source_ip']
    
    action = "DO_NOTHING"
    
    if severity == "LOW":
        action = "DO_NOTHING"
        if ip not in {"127.0.0.1", "::1", "localhost"}:
            log_action("IP", ip, action, "Severity is LOW.")
        
    elif severity == "MEDIUM":
        # Check if we should escalate to BLOCK
        # If this IP has had a MEDIUM alert recently, escalate?
        # For this logic, we'll keep it simple per requirements: "Escalate ONLY after previous action fails"
        # We'll determine 'fails' by checking if we recently RATE_LIMITED this IP.
        
        recent_actions = get_recent_actions(limit=10)
        previous_action = next((a for a in recent_actions if a['entity_value'] == ip and a['action_type'] == 'RATE_LIMIT'), None)
        
        if previous_action:
             action = "BLOCK"
             block_ip(ip)
             block_entity_db("IP", ip, "Escalated from RATE_LIMIT due to repeated offense.")
             log_action("IP", ip, action, "Escalated from RATE_LIMIT.")
        else:
             action = "RATE_LIMIT"
             # In a real app, we'd add this IP to a token bucket or similar.
             # Here we just log the decision.
             log_action("IP", ip, action, "Severity is MEDIUM. Rate limiting applied.")

    elif severity == "HIGH":
        action = "BLOCK"
        block_ip(ip)
        block_entity_db("IP", ip, "Severity is HIGH.")
        log_action("IP", ip, action, "Severity is HIGH. Immediate Block.")

    return action
