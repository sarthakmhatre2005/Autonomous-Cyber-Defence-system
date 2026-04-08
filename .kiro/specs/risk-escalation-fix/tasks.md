# Implementation Plan

- [x] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - Weak Signals Receive Proportional Risk
  - **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior - it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the bug exists
  - **Scoped PBT Approach**: Scope the property to concrete failing cases — single-event inputs (event_count < 3) and low-confidence inputs (confidence < 0.3 with no strong signals)
  - Create `tests/test_risk_escalation_fix.py` with a property-based test using `hypothesis`
  - Test 1 — Single event: call `ThreatScoringEngine._decide_action` (or `process_alert`) with repeat_strong=1, confidence=0.1, no ML anomaly, no multi-signal; assert action != "BLOCK" and risk < 85
  - Test 2 — Low confidence cap: call with confidence=0.2, repeat_strong=0, no strong signals; assert risk <= 60
  - Test 3 — Spike-only: process a CONNECTION_BURST alert with spike_only=True, repeat_strong=0; assert action == "MONITOR" and risk < 30
  - Test 4 — Reasoning text: call with repeat_strong=1 (event_count < 3); assert reasoning contains "Single event detected" and NOT "Repeated strong signals"
  - Use `hypothesis.given` to generate random (event_count in [1,2], confidence in [0.0, 0.29], repeat_strong in [0,2]) tuples satisfying isBugCondition; assert risk != 90 and action != "BLOCK"
  - Run test on UNFIXED code: `pytest tests/test_risk_escalation_fix.py::test_bug_condition -v`
  - **EXPECTED OUTCOME**: Test FAILS (this is correct — it proves the bug exists)
  - Document counterexamples found (e.g., "repeat_strong=1, confidence=0.1 → risk=90, action=BLOCK")
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Strong Threat Behavior Unchanged
  - **IMPORTANT**: Follow observation-first methodology
  - Observe behavior on UNFIXED code for strong-signal inputs (isBugCondition returns False)
  - Observe: event_count=5, confidence=0.9, repeat_strong=4 → action on unfixed code
  - Observe: HONEYPOT_HIT alert → action on unfixed code
  - Observe: anomaly_ratio=0.95, repeat_strong=3 → action on unfixed code
  - Observe: SYSTEM source type with moderate risk → action on unfixed code
  - Write property-based tests in `tests/test_risk_escalation_fix.py` capturing observed behavior:
    - `test_preservation_genuine_repeat`: event_count >= 3, confidence >= 0.7, repeat_strong >= 3 → assert action == "BLOCK"
    - `test_preservation_honeypot`: HONEYPOT_HIT alert → assert high risk and action == "BLOCK"
    - `test_preservation_ml_anomaly`: anomaly_ratio=0.95, repeat_strong=3 → assert strong ML boost applies and risk reaches BLOCK threshold
    - `test_preservation_whitelist`: whitelisted IP with risk=95 → assert action != "BLOCK"
    - `test_preservation_local_device`: SYSTEM source type → assert action != "BLOCK" for moderate risk
  - Use `hypothesis.given` to generate random strong-signal inputs (event_count >= 3, confidence >= 0.7); verify action matches expected strong-threat behavior
  - Run tests on UNFIXED code: `pytest tests/test_risk_escalation_fix.py::test_preservation -v`
  - **EXPECTED OUTCOME**: Tests PASS (this confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8_

- [x] 3. Fix risk escalation bug in threat_engine.py and decision_engine.py

  - [x] 3.1 Fix repeated-signal threshold in `core/threat_engine.py`
    - Locate the condition in `ThreatScoringEngine._decide_action` that sets `repeated = True`
    - Change threshold from `repeat_strong >= 1` to `repeat_strong >= 3`
    - Ensures a single alert does not trigger the repeated-signal risk increment
    - _Bug_Condition: isBugCondition(input) where input.event_count < 3 (repeat_strong >= 1 fires on first event)_
    - _Expected_Behavior: repeated = True only when repeat_strong >= 3 (event_count >= 3)_
    - _Requirements: 2.1_

  - [x] 3.2 Remove hardcoded risk override in `core/threat_engine.py`
    - Locate and remove `risk = 90` or `risk = max(risk, 90)` in `ThreatScoringEngine._decide_action`
    - The additive engine (`risk_engine.score_event`) already handles escalation for strong signals
    - Do NOT remove the `progressive_decide_action` guard `if risk >= 90` — that guard is correct
    - _Bug_Condition: isBugCondition(input) — any input triggers risk=90 override_
    - _Expected_Behavior: risk = base_risk + sum(applicable_increments); no hardcoded override_
    - _Requirements: 2.2, 2.3_

  - [x] 3.3 Add confidence-based risk cap in `core/threat_engine.py`
    - After `risk_engine.score_event` returns, add guard in `_decide_action`:
      ```python
      if confidence < 0.3 and repeat_strong < 3 and not ml_anomaly and not multi_signal:
          risk = min(risk, 60)
      ```
    - Prevents weak, low-confidence signals from exceeding MEDIUM risk
    - _Bug_Condition: isBugCondition(input) where confidence < 0.3 AND no strong signals_
    - _Expected_Behavior: risk capped at 60 for low-confidence inputs with no strong corroboration_
    - _Requirements: 2.4_

  - [x] 3.4 Tighten BLOCK condition in `core/threat_engine.py`
    - After `progressive_decide_action` returns, add prerequisite check before allowing BLOCK:
      ```python
      if action == "BLOCK":
          has_strong = repeat_strong >= 3 or ml_anomaly or multi_signal
          if not has_strong:
              action = "LOG"
      ```
    - Ensures BLOCK requires risk >= 85 AND at least one strong corroborating signal
    - _Bug_Condition: isBugCondition(input) — BLOCK issued without strong signals_
    - _Expected_Behavior: BLOCK only when risk >= 85 AND (repeat_strong >= 3 OR ml_anomaly OR multi_signal)_
    - _Preservation: Genuine repeat attackers (repeat_strong >= 3) and honeypot hits still trigger BLOCK_
    - _Requirements: 2.5, 3.1, 3.2, 3.3_

  - [x] 3.5 Fix reasoning text in `core/threat_engine.py`
    - Locate the reasoning assembly in `_decide_action` that appends "Repeated strong signals"
    - Replace unconditional append with:
      ```python
      if repeat_strong >= 3:
          reasoning_lines.append(f"Repeated strong signals: {repeat_strong} events/60s")
      elif repeat_strong > 0:
          reasoning_lines.append(f"Single event detected: {repeat_strong} events/60s")
      ```
    - _Bug_Condition: isBugCondition(input) where event_count < 3 — shows "Repeated strong signals" incorrectly_
    - _Expected_Behavior: "Single event detected" shown when event_count < 3; "Repeated strong signals" only when event_count >= 3_
    - _Requirements: 2.6_

  - [x] 3.6 Verify `progressive_decide_action` guard in `core/decision_engine.py`
    - Confirm `if risk >= 90 or thr == "CRITICAL": return "BLOCK"` guard is still present and unchanged
    - This guard is correct in isolation — it only becomes a universal trigger due to the upstream risk=90 hardcode
    - No code change needed here; this is a verification step only
    - _Preservation: Guard continues to fire legitimately for genuinely high-risk threats after upstream fix_
    - _Requirements: 2.5, 3.1_

  - [x] 3.7 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** - Weak Signals Receive Proportional Risk
    - **IMPORTANT**: Re-run the SAME test from task 1 — do NOT write a new test
    - The test from task 1 encodes the expected behavior
    - When this test passes, it confirms the expected behavior is satisfied
    - Run: `pytest tests/test_risk_escalation_fix.py::test_bug_condition -v`
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed)
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

  - [x] 3.8 Verify preservation tests still pass
    - **Property 2: Preservation** - Strong Threat Behavior Unchanged
    - **IMPORTANT**: Re-run the SAME tests from task 2 — do NOT write new tests
    - Run: `pytest tests/test_risk_escalation_fix.py::test_preservation -v`
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirm all preservation tests still pass after fix (no regressions for genuine threats)

- [x] 4. Checkpoint - Ensure all tests pass
  - Run full test suite: `pytest tests/test_risk_escalation_fix.py -v`
  - Confirm Property 1 (bug condition) test passes — weak signals no longer get risk=90 or BLOCK
  - Confirm Property 2 (preservation) tests pass — strong threats still escalate and block correctly
  - Ensure all tests pass; ask the user if questions arise
