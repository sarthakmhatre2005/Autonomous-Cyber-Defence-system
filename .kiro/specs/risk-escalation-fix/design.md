# Risk Escalation Fix - Bugfix Design

## Overview

Every threat processed by the system is being assigned a risk score of 90, regardless of signal
strength, confidence, or repetition. This causes even weak, single-event, low-confidence signals
to be classified as CRITICAL and trigger IP blocks, resulting in widespread over-blocking of
normal traffic.

The fix restores proportional risk scoring by: correcting the repeated-signal threshold
(event_count >= 3, not >= 1), removing hardcoded `risk = 90` overrides, replacing them with
additive risk buildup from a base value, adding a confidence-based cap for weak signals, and
tightening the BLOCK condition to require both high risk and strong corroborating signals.

The affected code spans `core/threat_engine.py` (`_decide_action`, `ThreatScoringEngine`) and
`core/risk_engine.py` (`RiskEngine.score_event`), with the reasoning text fix in the
`_decide_action` reasoning assembly.

## Glossary

- **Bug_Condition (C)**: The condition that triggers the bug — a threat is processed with
  event_count < 3 (single/weak signal) and/or low confidence (< 0.3) yet receives risk = 90
  and a BLOCK action
- **Property (P)**: The desired behavior when the bug condition holds — risk is computed
  additively and proportionally; weak signals produce LOW/MEDIUM risk; BLOCK is only issued
  when risk >= 85 AND strong corroborating signals are present
- **Preservation**: Existing behavior for genuinely strong threats (event_count >= 3, high
  confidence, ML anomaly, honeypot) that must remain unchanged by the fix
- **repeat_strong**: Count of strong alert types (PORT_SCAN, CONNECTION_BURST, BRUTE_FORCE,
  ML_ANOMALY, HONEYPOT_HIT) observed for an IP within the last 60 seconds, computed in
  `ThreatScoringEngine._decide_action`
- **anomaly_ratio**: Normalized ML anomaly score (last_ml_score / 10.0), used in
  `RiskEngine.score_event` to determine if a strong ML boost applies (anomaly_ratio > 0.9)
- **spike_only**: Flag on CONNECTION_BURST alerts indicating no corroborating signals are
  present; triggers a capped risk bump path in `RiskEngine.score_event`
- **progressive_decide_action**: Function in `core/decision_engine.py` that maps risk +
  repeat_strong + confidence to MONITOR/LOG/BLOCK; currently contains a `risk >= 90` override
  that forces BLOCK

## Bug Details

### Bug Condition

The bug manifests when any threat is processed through `ThreatScoringEngine._decide_action`.
The function either sets `repeated = True` for a single event (event_count >= 1 instead of >= 3),
applies a hardcoded `risk = 90` override (or `risk = max(risk, 90)`), or both — causing the
`progressive_decide_action` CRITICAL override to fire unconditionally and issue a BLOCK.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input is a threat alert dict with fields:
         event_count (int), confidence (float 0..1),
         has_repeated_signals (bool), has_ml_anomaly (bool),
         has_multiple_signals (bool)
  OUTPUT: boolean

  weak_signal   := input.event_count < 3
  low_confidence := input.confidence < 0.3
  no_strong     := NOT input.has_repeated_signals
                   AND NOT input.has_ml_anomaly
                   AND NOT input.has_multiple_signals

  RETURN weak_signal OR (low_confidence AND no_strong)
END FUNCTION
```

### Examples

- **Single event, external IP**: event_count=1, confidence=0.1, no ML anomaly
  - Current (buggy): repeated=True → risk=90 → CRITICAL → BLOCK
  - Expected (fixed): repeated=False → risk ≈ base+5 (connection spike) → LOW → MONITOR

- **Low confidence, no strong signals**: confidence=0.2, event_count=2, no ML, no multi-signal
  - Current (buggy): risk=90 → CRITICAL → BLOCK
  - Expected (fixed): risk capped at 60 → MEDIUM → LOG

- **Moderate spike, no corroboration**: CONNECTION_BURST spike_only=True, repeat_strong=0
  - Current (buggy): risk=90 → BLOCK
  - Expected (fixed): risk = base + 7 (spike bump) ≈ 12–20 → LOW → MONITOR

- **Edge case — event_count=2, high confidence**: confidence=0.85, event_count=2, ML anomaly
  - Expected (fixed): repeated=False (count < 3), but ML anomaly boost applies; risk may reach
    LOG threshold but BLOCK requires event_count >= 3 or multiple signals

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- Genuine repeated malicious behavior (event_count >= 3, high confidence) SHALL continue to
  escalate risk and issue BLOCK when risk >= 85
- ML anomaly with anomaly_ratio > 0.9 alongside repeated signals SHALL continue to apply the
  strong ML boost (+25–40) and escalate risk appropriately
- Honeypot interactions SHALL continue to apply the honeypot boost (+35) and be treated as a
  strong signal for escalation
- Multiple correlated attack signals from the same IP SHALL continue to apply correlation boosts
- Whitelisted IPs SHALL continue to be refused blocking regardless of risk score
- SYSTEM and LOCAL_DEVICE source types SHALL continue to receive reduced base increments and
  avoid blocking unless risk is extremely high
- Risk decay over time (exponential decay in `IPThreatState.decay_score`) SHALL continue to
  reduce scores via the existing mechanism
- Auto-unblock after cooldown (`BLOCK_COOLDOWN = 1800s`) SHALL continue to work

**Scope:**
All inputs where isBugCondition returns False (event_count >= 3, or confidence >= 0.3 with
strong signals) should be completely unaffected by this fix. This includes:
- Genuine port scans (repeat_strong >= 3)
- Confirmed brute force attempts (>= 10 attempts in 30s)
- High-confidence ML anomalies paired with repeated signals
- Honeypot hits (always treated as strong signal regardless of count)

## Hypothesized Root Cause

Based on the bug description and code analysis, the most likely issues are:

1. **Incorrect repeated-signal threshold in `_decide_action`**: The `repeat_strong` counter
   (from `_count_repeats`) counts alert occurrences in the last 60s. The condition that sets
   `repeated = True` (or equivalent logic feeding into risk) uses `>= 1` instead of `>= 3`,
   meaning the very first alert for any IP immediately triggers the "repeated" path.

2. **Hardcoded `risk = 90` override in `_decide_action`**: After `risk_engine.score_event`
   returns a proportional risk, the code applies `risk = 90` or `risk = max(risk, 90)`,
   overwriting the carefully computed additive score. This is the primary cause of all threats
   reaching CRITICAL.

3. **`progressive_decide_action` CRITICAL override**: In `core/decision_engine.py`, the
   condition `if risk >= 90 or thr == "CRITICAL": return "BLOCK"` is correct in isolation, but
   becomes a universal BLOCK trigger once the hardcoded risk=90 is applied upstream. The fix
   to the risk computation will make this guard behave correctly again.

4. **Missing confidence cap**: No guard exists to cap risk at 60 when confidence < 0.3 and no
   strong signals are present. The additive engine can still accumulate past 60 for weak signals
   through memory boosts and base increments.

5. **Reasoning text not conditioned on event_count**: The line
   `reasoning_lines.append(f"Repeated strong signals: {repeat_strong} events/60s")` fires
   whenever `repeat_strong` is truthy (>= 1), producing misleading "Repeated strong signals"
   text even for single-event detections.

## Correctness Properties

Property 1: Bug Condition - Weak Signals Receive Proportional Risk

_For any_ input where the bug condition holds (isBugCondition returns true — event_count < 3
or confidence < 0.3 with no strong signals), the fixed `_decide_action` function SHALL compute
risk additively from base_risk with controlled increments only (connection_spike: +5–10,
repeated: +15–25 only when event_count >= 3, ML anomaly: +25–40, multiple signals: +20),
SHALL NOT assign risk = 90 or risk = max(risk, 90), and SHALL NOT issue a BLOCK action.

**Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5**

Property 2: Preservation - Strong Threat Behavior Unchanged

_For any_ input where the bug condition does NOT hold (isBugCondition returns false —
event_count >= 3 with high confidence, or ML anomaly with anomaly_ratio > 0.9, or honeypot
hit), the fixed `_decide_action` function SHALL produce the same risk escalation and action
decisions as the original function would produce if the hardcoded risk=90 were not present,
preserving all existing strong-threat detection and blocking behavior.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8**

## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct:

**File**: `core/threat_engine.py`

**Function**: `ThreatScoringEngine._decide_action`

**Specific Changes**:

1. **Fix repeated-signal threshold**: Change the condition that sets `repeated = True` (or
   feeds into the repeated-signal risk path) from `repeat_strong >= 1` to `repeat_strong >= 3`.
   This ensures a single alert does not trigger the repeated-signal risk increment.

2. **Remove hardcoded risk override**: Remove the line `risk = 90` or `risk = max(risk, 90)`
   that overwrites the output of `risk_engine.score_event`. The additive engine already handles
   escalation correctly for strong signals.

3. **Add confidence cap**: After `risk_engine.score_event` returns, add a guard:
   ```python
   if confidence < 0.3 and repeat_strong < 3 and not ml_anomaly and not multi_signal:
       risk = min(risk, 60)
   ```

4. **Tighten BLOCK condition**: In the action assignment after `progressive_decide_action`,
   add a prerequisite check before allowing BLOCK:
   ```python
   if action == "BLOCK":
       has_strong = repeat_strong >= 3 or ml_anomaly or multi_signal
       if not has_strong:
           action = "LOG"
   ```

5. **Fix reasoning text**: Change the reasoning line from unconditional
   `f"Repeated strong signals: {repeat_strong} events/60s"` to:
   ```python
   if repeat_strong >= 3:
       reasoning_lines.append(f"Repeated strong signals: {repeat_strong} events/60s")
   elif repeat_strong > 0:
       reasoning_lines.append(f"Single event detected: {repeat_strong} events/60s")
   ```

**File**: `core/decision_engine.py`

**Function**: `progressive_decide_action`

6. **Verify CRITICAL override**: The `if risk >= 90 or thr == "CRITICAL": return "BLOCK"` guard
   is correct but will only fire legitimately once the upstream risk=90 hardcode is removed.
   No change needed here if the upstream fix is applied, but confirm the guard remains.

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that
demonstrate the bug on unfixed code, then verify the fix works correctly and preserves
existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix.
Confirm or refute the root cause analysis. If we refute, we will need to re-hypothesize.

**Test Plan**: Write unit tests that call `ThreatScoringEngine._decide_action` (or the full
`process_alert` pipeline) with weak-signal inputs and assert that the returned action is NOT
BLOCK and risk is NOT 90. Run these tests on the UNFIXED code to observe failures and
understand the root cause.

**Test Cases**:
1. **Single event test**: Call `_decide_action` with repeat_strong=1, confidence=0.1,
   no ML anomaly — assert action != "BLOCK" and risk < 85 (will fail on unfixed code)
2. **Low confidence cap test**: Call with confidence=0.2, repeat_strong=0, no strong signals —
   assert risk <= 60 (will fail on unfixed code)
3. **Spike-only test**: Process a CONNECTION_BURST alert with spike_only=True, repeat_strong=0 —
   assert action == "MONITOR" and risk < 30 (will fail on unfixed code)
4. **Reasoning text test**: Call with repeat_strong=1 (event_count < 3) — assert reasoning
   contains "Single event detected" not "Repeated strong signals" (will fail on unfixed code)

**Expected Counterexamples**:
- `_decide_action` returns "BLOCK" for single-event inputs
- `state.last_risk_score` is 90 regardless of input signal strength
- Possible causes: hardcoded `risk = 90` override, `repeated = True` set at event_count >= 1

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces
the expected behavior.

**Pseudocode:**
```
FOR ALL input WHERE isBugCondition(input) DO
  risk, action, reasoning := _decide_action_fixed(input)
  ASSERT action != "BLOCK"
  ASSERT risk == base_risk + sum(applicable_increments_only)
  ASSERT risk != 90  -- unless legitimately reached by additive formula
  IF input.confidence < 0.3 AND no_strong_signals(input) THEN
    ASSERT risk <= 60
  END IF
  IF input.event_count < 3 THEN
    ASSERT "Single event detected" IN reasoning
    ASSERT "Repeated strong signals" NOT IN reasoning
  END IF
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed function
produces the same result as the original function.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  action_original := _decide_action_original(input)
  action_fixed    := _decide_action_fixed(input)
  ASSERT action_original == action_fixed
  -- Risk may differ slightly (hardcode removed) but action outcome must match
  -- for all genuinely strong-threat inputs
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many test cases automatically across the input domain
- It catches edge cases that manual unit tests might miss
- It provides strong guarantees that behavior is unchanged for all non-buggy inputs

**Test Plan**: Observe behavior on UNFIXED code first for strong-signal inputs (event_count >= 3,
high confidence, ML anomaly), then write property-based tests capturing that behavior.

**Test Cases**:
1. **Genuine repeat attacker preservation**: event_count=5, confidence=0.9, repeat_strong=4 —
   verify BLOCK is still issued after fix
2. **Honeypot preservation**: HONEYPOT_HIT alert — verify high risk and BLOCK still issued
3. **ML anomaly + repeat preservation**: anomaly_ratio=0.95, repeat_strong=3 — verify strong
   ML boost still applies and risk reaches BLOCK threshold
4. **Whitelist preservation**: Whitelisted IP with risk=95 — verify BLOCK is still refused
5. **Local device preservation**: SYSTEM source type — verify reduced base increment still
   applies and BLOCK is avoided for moderate risk

### Unit Tests

- Test `_decide_action` with event_count in [1, 2] — assert repeated=False and action != BLOCK
- Test `_decide_action` with confidence=0.2 and no strong signals — assert risk <= 60
- Test reasoning text for event_count < 3 — assert "Single event detected" in output
- Test BLOCK condition: risk=87, repeat_strong=0 — assert action == "LOG" not "BLOCK"
- Test BLOCK condition: risk=87, repeat_strong=3 — assert action == "BLOCK"

### Property-Based Tests

- Generate random (event_count, confidence, repeat_strong) tuples where isBugCondition is True;
  verify risk is never hardcoded to 90 and action is never BLOCK
- Generate random strong-signal inputs (event_count >= 3, confidence >= 0.7); verify action
  matches pre-fix behavior (preservation property)
- Generate random source_type values; verify SYSTEM/LOCAL_DEVICE always get lower base
  increments than EXTERNAL_SOURCE

### Integration Tests

- Full pipeline test: inject a single CONNECTION_BURST packet for a new IP; verify the IP is
  not blocked and risk is in LOW range
- Full pipeline test: inject 5 consecutive PORT_SCAN alerts for the same IP with high
  confidence; verify the IP is eventually blocked
- Full pipeline test: inject a HONEYPOT_HIT alert; verify high risk and BLOCK action
- Reasoning visibility test: verify the dashboard/API returns "Single event detected" for
  new IPs with one alert
