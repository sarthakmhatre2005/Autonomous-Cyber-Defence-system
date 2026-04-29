"""
Test: CRITICAL threat level must always produce BLOCK action.
Run: python tests/test_critical_blocks.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.decision_engine import progressive_decide_action
from core.threat_engine import threat_engine, IPThreatState

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
results = []

def chk(label, got, expected):
    ok = got == expected
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}: got={got!r} expected={expected!r}")
    return ok

# ── 1. decision_engine: CRITICAL always → BLOCK ───────────────────────────────
print("=== 1. progressive_decide_action ===")
cases = [
    (95, 0, 0.0, "EXTERNAL_SOURCE", "PORT_SCAN",    "CRITICAL",  "BLOCK"),
    (75, 0, 0.0, "EXTERNAL_SOURCE", "PORT_SCAN",    "MALICIOUS", "BLOCK"),
    (63, 0, 0.0, "EXTERNAL_SOURCE", "PORT_SCAN",    "HIGH",      "BLOCK"),
    (50, 0, 0.0, "EXTERNAL_SOURCE", "PORT_SCAN",    "SUSPICIOUS","BLOCK"),
    (30, 0, 0.0, "EXTERNAL_SOURCE", "PORT_SCAN",    "SUSPICIOUS","LOG"),
    (10, 0, 0.0, "EXTERNAL_SOURCE", "PORT_SCAN",    "NORMAL",    "MONITOR"),
    (10, 0, 0.0, "EXTERNAL_SOURCE", "HONEYPOT_HIT", "NORMAL",    "BLOCK"),
    (95, 0, 0.0, "LOCAL_DEVICE",    "PORT_SCAN",    "CRITICAL",  "BLOCK"),
    (60, 0, 0.0, "LOCAL_DEVICE",    "PORT_SCAN",    "HIGH",      "LOG"),
]
for risk, rep, conf, src, atk, thr, expected in cases:
    got = progressive_decide_action(risk=risk, repeat_strong=rep, confidence=conf,
                                    source_type=src, attack_type=atk, threat_level=thr)
    chk(f"risk={risk} thr={thr} atk={atk[:12]}", got, expected)

# ── 2. to_dict: CRITICAL threat_level → action must be BLOCK ─────────────────
print("\n=== 2. IPThreatState.to_dict() consistency ===")
state = IPThreatState("8.8.8.8")
state.last_risk_score = 95   # → CRITICAL
state.action = "MONITOR"     # BUG: was set to MONITOR before fix
state.is_blocked = False
d = state.to_dict()
chk("CRITICAL risk=95 → action=BLOCK (not MONITOR)", d["action"], "BLOCK")
chk("threat_level=CRITICAL",                          d["threat_level"], "CRITICAL")

state2 = IPThreatState("1.1.1.1")
state2.last_risk_score = 75  # → MALICIOUS
state2.action = "MONITOR"    # BUG: was set to MONITOR before fix
d2 = state2.to_dict()
chk("MALICIOUS risk=75 → action=LOG (not MONITOR)", d2["action"] in ("LOG", "BLOCK"), True)

state3 = IPThreatState("2.2.2.2")
state3.last_risk_score = 20  # → SUSPICIOUS
state3.action = "MONITOR"
d3 = state3.to_dict()
chk("SUSPICIOUS risk=20 → action=MONITOR (correct)", d3["action"], "MONITOR")

# ── 3. Full pipeline: HONEYPOT_HIT → BLOCK ────────────────────────────────────
print("\n=== 3. Full pipeline: HONEYPOT_HIT ===")
threat_engine.process_alert({
    "ip": "45.33.32.156",
    "type": "HONEYPOT_HIT",
    "score": 90,
    "detail": "Honeypot hit on port 21 (FTP)",
    "severity": "HIGH",
    "ip_type": "EXTERNAL",
})
s = threat_engine._get_state("45.33.32.156").to_dict()
chk("HONEYPOT_HIT → action=BLOCK", s["action"], "BLOCK")
chk("HONEYPOT_HIT → risk > 0",     s["risk"] > 0, True)
print(f"  risk={s['risk']}  action={s['action']}  threat_level={s['threat_level']}")

# ── 4. Full pipeline: PORT_SCAN with high risk → BLOCK ────────────────────────
print("\n=== 4. Full pipeline: PORT_SCAN high risk ===")
threat_engine.process_alert({
    "ip": "5.5.5.5",
    "type": "PORT_SCAN",
    "score": 50,
    "detail": "20 ports in 10s (SEQUENTIAL)",
    "severity": "HIGH",
    "ip_type": "EXTERNAL",
})
s2 = threat_engine._get_state("5.5.5.5").to_dict()
print(f"  risk={s2['risk']}  action={s2['action']}  threat_level={s2['threat_level']}")
chk("PORT_SCAN risk>0",    s2["risk"] > 0, True)
chk("PORT_SCAN no MONITOR+CRITICAL mismatch",
    not (s2["threat_level"] == "CRITICAL" and s2["action"] == "MONITOR"), True)

# ── Summary ───────────────────────────────────────────────────────────────────
passed = sum(results)
total  = len(results)
print(f"\n{'='*45}")
print(f"Results: {passed}/{total} passed")
if passed == total:
    print("ALL TESTS PASSED")
else:
    print("SOME TESTS FAILED")
    sys.exit(1)
