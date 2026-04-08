"""
Bug condition exploration tests for the risk escalation fix.

Property 1: Bug Condition — Weak Signals Receive Proportional Risk
  Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6

These tests MUST FAIL on unfixed code — failure confirms the bug exists.
They encode the EXPECTED (correct) behavior and will pass once the fix is applied.

DO NOT attempt to fix the test or the code when it fails.
"""

import time
import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from core.threat_engine import ThreatScoringEngine, IPThreatState, IPBehaviorProfile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_engine() -> ThreatScoringEngine:
    """Create a fresh engine with no DB side-effects."""
    engine = ThreatScoringEngine()
    # Disable DB-backed ip_memory to keep tests hermetic
    engine.ip_memory = {}
    return engine


def _make_state(ip: str = "1.2.3.4") -> IPThreatState:
    """Fresh threat state with zero history."""
    return IPThreatState(ip)


def _make_behavior(ip: str = "1.2.3.4") -> IPBehaviorProfile:
    """Fresh behavior profile with no recorded alerts."""
    return IPBehaviorProfile(ip)


def _make_alert(alert_type: str = "CONNECTION_BURST", **kwargs) -> dict:
    base = {
        "type": alert_type,
        "ip": "1.2.3.4",
        "timestamp": time.time(),
        "score": 1,
    }
    base.update(kwargs)
    return base


def _call_decide(engine, ip="1.2.3.4", alert_type="CONNECTION_BURST", **alert_kwargs):
    """
    Call _decide_action with a fresh state/behavior and return (action, risk, reasoning).
    """
    state = _make_state(ip)
    behavior = _make_behavior(ip)
    alert = _make_alert(alert_type, **alert_kwargs)
    action = engine._decide_action(ip, state, alert, profile=None, behavior=behavior)
    risk = int(state.last_risk_score or 0)
    reasoning = str(state.last_reasoning or "")
    return action, risk, reasoning


# ---------------------------------------------------------------------------
# Test 1 — Single event: repeat_strong=1, confidence=0.1, no ML, no multi-signal
# Expected (correct): action != "BLOCK" and risk < 85
# ---------------------------------------------------------------------------

def test_single_event_no_block():
    """
    A single event with low confidence must NOT result in a BLOCK or risk >= 85.

    Bug condition: repeat_strong=1, confidence=0.1, no ML anomaly, no multi-signal.
    Expected (fixed): action != "BLOCK" and risk < 85.
    WILL FAIL on unfixed code (risk=90, action=BLOCK).
    """
    engine = _make_engine()
    ip = "10.20.30.40"
    state = _make_state(ip)
    behavior = _make_behavior(ip)

    # Inject exactly one alert into behavior so repeat_strong will be 1
    alert = _make_alert("CONNECTION_BURST", ip=ip)
    behavior.record_alert("CONNECTION_BURST", alert)

    action = engine._decide_action(ip, state, alert=alert, profile=None, behavior=behavior)
    risk = int(state.last_risk_score or 0)

    assert action != "BLOCK", (
        f"BUG CONFIRMED: single event (repeat_strong≈1, confidence≈0.1) produced action=BLOCK "
        f"(risk={risk}). Expected action != BLOCK."
    )
    assert risk < 85, (
        f"BUG CONFIRMED: single event produced risk={risk} >= 85. "
        f"Expected risk < 85 for weak single-event signal."
    )


# ---------------------------------------------------------------------------
# Test 2 — Low confidence cap: confidence=0.2, repeat_strong=0, no strong signals
# Expected (correct): risk <= 60
# ---------------------------------------------------------------------------

def test_low_confidence_risk_cap():
    """
    Low-confidence input with no strong signals must be capped at risk <= 60.

    Bug condition: confidence=0.2, repeat_strong=0, no ML anomaly, no multi-signal.
    Expected (fixed): risk <= 60.
    WILL FAIL on unfixed code (risk=90).
    """
    engine = _make_engine()
    ip = "5.6.7.8"
    state = _make_state(ip)
    behavior = _make_behavior(ip)

    # No alerts recorded → repeat_strong=0, no ML, no patterns
    alert = _make_alert("CONNECTION_BURST", ip=ip)

    action = engine._decide_action(ip, state, alert=alert, profile=None, behavior=behavior)
    risk = int(state.last_risk_score or 0)

    assert risk <= 60, (
        f"BUG CONFIRMED: low-confidence input (confidence≈0, repeat_strong=0) produced risk={risk} > 60. "
        f"Expected risk <= 60 (capped for weak signals)."
    )


# ---------------------------------------------------------------------------
# Test 3 — Spike-only: CONNECTION_BURST with spike_only=True, repeat_strong=0
# Expected (correct): action == "MONITOR" and risk < 30
# ---------------------------------------------------------------------------

def test_spike_only_monitor():
    """
    A spike-only CONNECTION_BURST with no corroboration must result in MONITOR and risk < 30.

    Bug condition: spike_only=True, repeat_strong=0, no ML anomaly.
    Expected (fixed): action == "MONITOR" and risk < 30.
    WILL FAIL on unfixed code (action=BLOCK, risk=90).
    """
    engine = _make_engine()
    ip = "9.10.11.12"
    state = _make_state(ip)
    behavior = _make_behavior(ip)

    alert = _make_alert("CONNECTION_BURST", ip=ip, spike_only=True)

    action = engine._decide_action(ip, state, alert=alert, profile=None, behavior=behavior)
    risk = int(state.last_risk_score or 0)

    assert action == "MONITOR", (
        f"BUG CONFIRMED: spike-only CONNECTION_BURST (no corroboration) produced action={action}. "
        f"Expected action == MONITOR (risk={risk})."
    )
    assert risk < 30, (
        f"BUG CONFIRMED: spike-only CONNECTION_BURST produced risk={risk} >= 30. "
        f"Expected risk < 30 for isolated spike with no corroboration."
    )


# ---------------------------------------------------------------------------
# Test 4 — Reasoning text: repeat_strong=1 (event_count < 3)
# Expected (correct): reasoning contains "Single event detected" NOT "Repeated strong signals"
# ---------------------------------------------------------------------------

def test_reasoning_single_event_text():
    """
    When event_count < 3 (repeat_strong=1), reasoning must say "Single event detected",
    NOT "Repeated strong signals".

    Bug condition: repeat_strong=1, event_count < 3.
    Expected (fixed): "Single event detected" in reasoning, "Repeated strong signals" NOT in reasoning.
    WILL FAIL on unfixed code (shows "Repeated strong signals" for single events).
    """
    engine = _make_engine()
    ip = "13.14.15.16"
    state = _make_state(ip)
    behavior = _make_behavior(ip)

    # Inject exactly one alert so repeat_strong=1
    alert = _make_alert("CONNECTION_BURST", ip=ip)
    behavior.record_alert("CONNECTION_BURST", alert)

    engine._decide_action(ip, state, alert=alert, profile=None, behavior=behavior)
    reasoning = str(state.last_reasoning or "")

    assert "Repeated strong signals" not in reasoning, (
        f"BUG CONFIRMED: reasoning contains 'Repeated strong signals' for a single-event detection. "
        f"Reasoning: {reasoning!r}"
    )
    assert "Single event detected" in reasoning, (
        f"BUG CONFIRMED: reasoning does not contain 'Single event detected' for event_count < 3. "
        f"Reasoning: {reasoning!r}"
    )


# ---------------------------------------------------------------------------
# Property-based test — Bug Condition
# Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6
# ---------------------------------------------------------------------------

def _is_bug_condition(event_count: int, confidence: float, repeat_strong: int) -> bool:
    """
    Returns True when the input satisfies the bug condition:
    weak signal (event_count < 3) OR (low confidence AND no strong signals).
    """
    weak_signal = event_count < 3
    low_confidence = confidence < 0.3
    no_strong = repeat_strong == 0
    return weak_signal or (low_confidence and no_strong)


@given(
    event_count=st.integers(min_value=1, max_value=2),
    confidence=st.floats(min_value=0.0, max_value=0.29, allow_nan=False),
    repeat_strong_extra=st.integers(min_value=0, max_value=2),
)
@settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_bug_condition(event_count, confidence, repeat_strong_extra):
    """
    **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6**

    Property 1: Bug Condition — Weak Signals Receive Proportional Risk

    For any input where isBugCondition holds (event_count < 3, confidence < 0.3,
    repeat_strong in [0,2]), the system MUST NOT assign risk=90 and MUST NOT issue BLOCK.
    Additionally, when event_count < 3, reasoning MUST NOT say "Repeated strong signals".

    This test MUST FAIL on unfixed code — failure confirms the bug exists.
    """
    assert _is_bug_condition(event_count, confidence, repeat_strong_extra), (
        "Test setup error: inputs do not satisfy bug condition"
    )

    engine = _make_engine()
    ip = "192.0.2.1"  # TEST-NET, never a real IP
    state = _make_state(ip)
    behavior = _make_behavior(ip)

    # Inject `event_count` alerts to simulate repeat_strong
    alert = _make_alert("CONNECTION_BURST", ip=ip)
    for _ in range(event_count):
        behavior.record_alert("CONNECTION_BURST", alert)

    action = engine._decide_action(ip, state, alert=alert, profile=None, behavior=behavior)
    risk = int(state.last_risk_score or 0)
    reasoning = str(state.last_reasoning or "")

    assert risk != 90, (
        f"BUG CONFIRMED: event_count={event_count}, confidence≈{confidence:.2f}, "
        f"repeat_strong≈{repeat_strong_extra} → risk=90 (hardcoded override detected). "
        f"action={action}"
    )
    assert action != "BLOCK", (
        f"BUG CONFIRMED: event_count={event_count}, confidence≈{confidence:.2f}, "
        f"repeat_strong≈{repeat_strong_extra} → action=BLOCK. "
        f"Expected action != BLOCK for weak-signal inputs. risk={risk}"
    )
    # Bug 1.6: reasoning must NOT say "Repeated strong signals" for event_count < 3
    assert "Repeated strong signals" not in reasoning, (
        f"BUG CONFIRMED: event_count={event_count} (< 3) → reasoning contains "
        f"'Repeated strong signals'. Expected 'Single event detected'. "
        f"Reasoning: {reasoning!r}"
    )


# ===========================================================================
# Property 2: Preservation — Strong Threat Behavior Unchanged
# Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8
#
# These tests MUST PASS on unfixed code — they capture baseline behavior for
# genuinely strong-signal inputs (isBugCondition returns False).
# They must also pass after the fix is applied (regression prevention).
# ===========================================================================


# ---------------------------------------------------------------------------
# Observation helpers
# ---------------------------------------------------------------------------

def _make_strong_behavior(ip: str, *, repeat_count: int = 5, ml_score: float = 9.5) -> IPBehaviorProfile:
    """
    Build a behavior profile that represents a genuine repeat attacker:
    - Many recent events in a tight window (triggers early_boost)
    - High ML anomaly score
    - Multiple strong alert records
    """
    behavior = _make_behavior(ip)
    now = time.time()
    # Inject 10 recent seen_times within 0.5s (triggers early_boost: >=3 events/5s)
    for i in range(10):
        behavior._seen_times.append(now - i * 0.05)
    # Set high ML score (anomaly_ratio = ml_score/10.0 > 0.9 triggers strong_ml_boost)
    behavior.last_ml_score = ml_score
    behavior.last_ml_ts = now
    # Record strong alert types
    alert = _make_alert("PORT_SCAN", ip=ip)
    for _ in range(repeat_count):
        behavior.record_alert("PORT_SCAN", alert)
    return behavior


# ---------------------------------------------------------------------------
# Observed behavior on unfixed code (documented here for traceability):
#
# Observation 1: event_count=5, repeat_strong=5, ML score=9.5, past_blocks=5,
#   total_flags=200, many seen_times → risk=90, decision=BLOCK
#   (firewall fails in test env → _decide_action returns "LOG", but risk=90)
#
# Observation 2: HONEYPOT_HIT x1 → risk=40, action=LOG
#   HONEYPOT_HIT x5 + ML + past_blocks → risk=100, decision=BLOCK
#
# Observation 3: ML_ANOMALY, anomaly_ratio=0.95, repeat_strong=3 →
#   strong_ml_boost=+25 fires, risk increases significantly
#
# Observation 4: SYSTEM source type (127.0.0.1) → risk=1, action=MONITOR
#   (base_increment=1 for SYSTEM; progressive_decide_action returns MONITOR)
#
# Observation 5: Whitelisted IP → _execute_block returns False → action=LOG
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Test P2.1 — Genuine repeat attacker: risk reaches BLOCK threshold
# Validates: Requirement 3.1
# ---------------------------------------------------------------------------

def test_preservation_genuine_repeat():
    """
    **Validates: Requirements 3.1**

    Property 2: Preservation — Genuine Repeat Attacker Escalates to High Risk

    When an IP exhibits genuinely repeated malicious behavior (repeat_strong >= 3,
    high ML anomaly, many recent events, past_blocks), the system SHALL continue
    to escalate risk to >= 85 (the BLOCK threshold).

    Observed on unfixed code: risk=90 for this input combination.
    This behavior must be preserved after the fix.
    """
    engine = _make_engine()
    ip = "203.0.113.50"

    # Simulate a known repeat attacker with past blocks
    engine.ip_memory[ip] = {"past_blocks": 5, "total_flags": 200, "last_seen": time.time()}

    state = _make_state(ip)
    behavior = _make_strong_behavior(ip, repeat_count=5, ml_score=9.5)
    alert = _make_alert("PORT_SCAN", ip=ip)

    engine._decide_action(ip, state, alert=alert, profile=None, behavior=behavior)
    risk = int(state.last_risk_score or 0)
    repeat_strong = int(state.last_repeat_strong or 0)

    assert risk >= 85, (
        f"PRESERVATION BROKEN: genuine repeat attacker (repeat_strong={repeat_strong}, "
        f"ML anomaly, past_blocks=5) produced risk={risk} < 85. "
        f"Expected risk >= 85 (BLOCK threshold). Strong threats must still escalate."
    )
    assert repeat_strong >= 3, (
        f"PRESERVATION BROKEN: repeat_strong={repeat_strong} < 3 for an IP with "
        f"5 recorded PORT_SCAN alerts. Expected repeat_strong >= 3."
    )


# ---------------------------------------------------------------------------
# Test P2.2 — Honeypot hit: always produces high risk
# Validates: Requirement 3.3
# ---------------------------------------------------------------------------

def test_preservation_honeypot():
    """
    **Validates: Requirements 3.3**

    Property 2: Preservation — Honeypot Interaction Produces High Risk

    When a honeypot interaction is detected (HONEYPOT_HIT alert), the system
    SHALL continue to apply the honeypot boost (+35) and produce high risk.

    Observed on unfixed code: HONEYPOT_HIT x1 → risk=40 (honeypot_boost=+35 fires).
    This behavior must be preserved after the fix.
    """
    engine = _make_engine()
    ip = "203.0.113.51"
    state = _make_state(ip)
    behavior = _make_behavior(ip)

    alert = _make_alert("HONEYPOT_HIT", ip=ip)
    behavior.record_alert("HONEYPOT_HIT", alert)

    engine._decide_action(ip, state, alert=alert, profile=None, behavior=behavior)
    risk = int(state.last_risk_score or 0)
    reasoning = str(state.last_reasoning or "")

    assert risk >= 35, (
        f"PRESERVATION BROKEN: HONEYPOT_HIT produced risk={risk} < 35. "
        f"Expected risk >= 35 (honeypot_boost=+35 must always fire). "
        f"Reasoning: {reasoning!r}"
    )
    assert "honeypot_boost" in reasoning, (
        f"PRESERVATION BROKEN: honeypot_boost not found in reasoning for HONEYPOT_HIT. "
        f"Reasoning: {reasoning!r}"
    )


# ---------------------------------------------------------------------------
# Test P2.3 — ML anomaly: strong boost applies when anomaly_ratio > 0.9
# Validates: Requirement 3.2
# ---------------------------------------------------------------------------

def test_preservation_ml_anomaly():
    """
    **Validates: Requirements 3.2**

    Property 2: Preservation — Strong ML Boost Applies for High Anomaly Ratio

    When an ML anomaly with anomaly_ratio > 0.9 is detected alongside repeated
    signals, the system SHALL continue to apply the strong ML boost (+25) and
    escalate risk appropriately.

    Observed on unfixed code: anomaly_ratio=0.95, repeat_strong=3 →
    strong_ml_boost=+25 fires, risk increases by >= 25 over base.
    This behavior must be preserved after the fix.
    """
    engine = _make_engine()
    ip = "203.0.113.52"
    state = _make_state(ip)
    behavior = _make_behavior(ip)

    now = time.time()
    # Use score=10 so record_alert sets last_ml_score=10.0 → anomaly_ratio=1.0 > 0.9
    alert = _make_alert("ML_ANOMALY", ip=ip, score=10)
    for _ in range(3):
        behavior.record_alert("ML_ANOMALY", alert)
    # Ensure last_ml_ts is recent (within 45s window checked by _decide_action)
    behavior.last_ml_ts = now

    engine._decide_action(ip, state, alert=alert, profile=None, behavior=behavior)
    risk = int(state.last_risk_score or 0)
    reasoning = str(state.last_reasoning or "")
    repeat_strong = int(state.last_repeat_strong or 0)

    assert "strong_ml_boost" in reasoning, (
        f"PRESERVATION BROKEN: strong_ml_boost not found in reasoning for "
        f"anomaly_ratio=0.95. Expected strong_ml_boost=+25 to fire. "
        f"Reasoning: {reasoning!r}"
    )
    # Base increment is 5 (EXTERNAL_SOURCE); strong_ml_boost adds 25 → risk >= 30
    assert risk >= 30, (
        f"PRESERVATION BROKEN: ML anomaly (anomaly_ratio=0.95, repeat_strong={repeat_strong}) "
        f"produced risk={risk} < 30. Expected risk >= 30 (base+5 + ml_boost+25). "
        f"Reasoning: {reasoning!r}"
    )


# ---------------------------------------------------------------------------
# Test P2.4 — Whitelist: whitelisted IP is never blocked
# Validates: Requirement 3.5
# ---------------------------------------------------------------------------

def test_preservation_whitelist():
    """
    **Validates: Requirements 3.5**

    Property 2: Preservation — Whitelisted IP Is Never Blocked

    When an IP is on the whitelist, the system SHALL continue to refuse to
    block it regardless of risk score.

    Observed on unfixed code: whitelisted IP with high risk → _execute_block
    returns False → action != "BLOCK".
    This behavior must be preserved after the fix.
    """
    from data.database import add_to_whitelist, remove_from_whitelist

    engine = _make_engine()
    ip = "203.0.113.53"

    # Add to whitelist
    add_to_whitelist("IP", ip)
    try:
        state = _make_state(ip)
        # Give it a very high risk score via ip_memory to force BLOCK decision
        engine.ip_memory[ip] = {"past_blocks": 5, "total_flags": 200, "last_seen": time.time()}
        behavior = _make_strong_behavior(ip, repeat_count=5, ml_score=9.5)
        alert = _make_alert("PORT_SCAN", ip=ip)

        action = engine._decide_action(ip, state, alert=alert, profile=None, behavior=behavior)
        risk = int(state.last_risk_score or 0)

        assert action != "BLOCK", (
            f"PRESERVATION BROKEN: whitelisted IP {ip} was blocked (action=BLOCK). "
            f"Whitelisted IPs must never be blocked regardless of risk={risk}."
        )
    finally:
        # Always clean up whitelist entry
        remove_from_whitelist("IP", ip)


# ---------------------------------------------------------------------------
# Test P2.5 — Local device / SYSTEM source: not blocked for moderate risk
# Validates: Requirement 3.6
# ---------------------------------------------------------------------------

def test_preservation_local_device():
    """
    **Validates: Requirements 3.6**

    Property 2: Preservation — SYSTEM Source Type Avoids Blocking for Moderate Risk

    When a SYSTEM or LOCAL_DEVICE source type is identified, the system SHALL
    continue to apply reduced base increments and avoid blocking unless risk
    is extremely high.

    Observed on unfixed code: SYSTEM source (127.0.0.1) → risk=1, action=MONITOR.
    LOCAL_DEVICE (10.x.x.x) → risk=3, action=MONITOR.
    This behavior must be preserved after the fix.
    """
    engine = _make_engine()

    # Test SYSTEM source type (127.0.0.1)
    ip_system = "127.0.0.1"
    state_sys = _make_state(ip_system)
    behavior_sys = _make_behavior(ip_system)
    alert_sys = _make_alert("CONNECTION_BURST", ip=ip_system)
    behavior_sys.record_alert("CONNECTION_BURST", alert_sys)

    action_sys = engine._decide_action(ip_system, state_sys, alert=alert_sys, profile=None, behavior=behavior_sys)
    risk_sys = int(state_sys.last_risk_score or 0)

    assert action_sys != "BLOCK", (
        f"PRESERVATION BROKEN: SYSTEM source (127.0.0.1) with moderate risk={risk_sys} "
        f"produced action=BLOCK. SYSTEM sources must not be blocked for moderate risk."
    )
    # SYSTEM base_increment=1; risk should be very low for a single event
    assert risk_sys < 30, (
        f"PRESERVATION BROKEN: SYSTEM source (127.0.0.1) produced risk={risk_sys} >= 30. "
        f"Expected low risk (base_increment=1 for SYSTEM source)."
    )

    # Test LOCAL_DEVICE source type (10.x.x.x)
    ip_local = "10.0.0.100"
    state_local = _make_state(ip_local)
    behavior_local = _make_behavior(ip_local)
    alert_local = _make_alert("CONNECTION_BURST", ip=ip_local)
    behavior_local.record_alert("CONNECTION_BURST", alert_local)

    action_local = engine._decide_action(ip_local, state_local, alert=alert_local, profile=None, behavior=behavior_local)
    risk_local = int(state_local.last_risk_score or 0)

    assert action_local != "BLOCK", (
        f"PRESERVATION BROKEN: LOCAL_DEVICE source (10.0.0.100) with moderate risk={risk_local} "
        f"produced action=BLOCK. LOCAL_DEVICE sources must not be blocked for moderate risk."
    )


# ---------------------------------------------------------------------------
# Property-based test — Preservation
# Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8
# ---------------------------------------------------------------------------

@given(
    repeat_count=st.integers(min_value=3, max_value=10),
    ml_score=st.floats(min_value=9.1, max_value=10.0, allow_nan=False),
    past_blocks=st.integers(min_value=3, max_value=10),
)
@settings(max_examples=20, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_preservation_strong_signals(repeat_count, ml_score, past_blocks):
    """
    **Validates: Requirements 3.1, 3.2, 3.3, 3.4**

    Property 2: Preservation — Strong Signals Always Escalate Risk

    For any input where isBugCondition does NOT hold (repeat_count >= 3,
    ML anomaly with anomaly_ratio > 0.9, past_blocks >= 3), the system SHALL
    continue to escalate risk to >= 85 (the BLOCK threshold).

    This test MUST PASS on unfixed code — it confirms baseline behavior to preserve.
    It must also pass after the fix is applied (regression prevention).
    """
    engine = _make_engine()
    ip = "198.51.100.1"  # TEST-NET-2, never a real IP

    engine.ip_memory[ip] = {
        "past_blocks": past_blocks,
        "total_flags": 200,
        "last_seen": time.time(),
    }

    state = _make_state(ip)
    behavior = _make_strong_behavior(ip, repeat_count=repeat_count, ml_score=ml_score)
    alert = _make_alert("PORT_SCAN", ip=ip)

    engine._decide_action(ip, state, alert=alert, profile=None, behavior=behavior)
    risk = int(state.last_risk_score or 0)
    repeat_strong = int(state.last_repeat_strong or 0)
    reasoning = str(state.last_reasoning or "")

    assert risk >= 85, (
        f"PRESERVATION BROKEN: strong-signal input (repeat_count={repeat_count}, "
        f"ml_score={ml_score:.1f}, past_blocks={past_blocks}) produced risk={risk} < 85. "
        f"Expected risk >= 85 for genuinely strong threats. "
        f"repeat_strong={repeat_strong}. Reasoning: {reasoning[:200]!r}"
    )
    assert repeat_strong >= 3, (
        f"PRESERVATION BROKEN: repeat_strong={repeat_strong} < 3 for input with "
        f"repeat_count={repeat_count} recorded alerts. Expected repeat_strong >= 3."
    )
