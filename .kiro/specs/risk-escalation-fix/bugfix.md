# Bugfix Requirements Document

## Introduction

The risk escalation pipeline in the cybersecurity system incorrectly assigns a risk score of 90 to nearly every threat, regardless of signal strength, confidence, or repetition. As a result, even weak, single-event, low-confidence signals are classified as CRITICAL and trigger IP blocks. This causes widespread over-blocking of normal traffic and degrades the system's credibility. The fix must restore proportional risk scoring so that only genuinely strong, repeated, or correlated threats reach CRITICAL and trigger blocking.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN a single event is observed for an IP (event_count = 1) THEN the system treats it as a repeated signal and sets `repeated = True`

1.2 WHEN any threat is processed THEN the system assigns `risk = 90` (or forces `risk = max(risk, 90)`), bypassing all proportional scoring logic

1.3 WHEN risk reaches 90 THEN the system classifies the threat as CRITICAL and issues a BLOCK action, even for low-confidence or single-event signals

1.4 WHEN a low-confidence signal (confidence < 0.3) with no strong corroborating signals is processed THEN the system allows risk to exceed 60, triggering false escalations

1.5 WHEN an IP is blocked THEN the system does not require repeated signals, ML anomaly, or multiple correlated signals as a prerequisite, allowing single-spike traffic to be blocked

1.6 WHEN the reasoning text is generated for a single-event detection THEN the system displays "Repeated strong signals" even though only one event was observed

### Expected Behavior (Correct)

2.1 WHEN a single event is observed for an IP (event_count < 3) THEN the system SHALL NOT set `repeated = True`; repeated signals SHALL only be flagged when event_count >= 3

2.2 WHEN a threat is processed THEN the system SHALL compute risk additively from a base value with controlled increments: connection spike adds 5–10, repeated signals add 15–25, ML anomaly adds 25–40, and multiple correlated signals add 20; no hardcoded `risk = 90` or `risk = max(risk, 90)` SHALL exist

2.3 WHEN risk is computed THEN the system SHALL use `risk = base_risk` as the starting point and apply only the increments above, so that weak signals produce LOW or MEDIUM risk scores

2.4 WHEN confidence < 0.3 AND no strong signals (no repeated signals, no ML anomaly, no multiple correlated signals) are present THEN the system SHALL cap risk at 60 and SHALL NOT escalate to CRITICAL

2.5 WHEN a BLOCK action is evaluated THEN the system SHALL only issue a BLOCK if risk >= 85 AND at least one of the following is true: repeated signals (event_count >= 3), ML anomaly detected, or multiple correlated signals present

2.6 WHEN the reasoning text is generated for a detection with event_count < 3 THEN the system SHALL display "Single event detected" instead of "Repeated strong signals"

### Unchanged Behavior (Regression Prevention)

3.1 WHEN an IP exhibits genuinely repeated malicious behavior (event_count >= 3) with high confidence THEN the system SHALL CONTINUE TO escalate risk and issue a BLOCK when risk >= 85

3.2 WHEN an ML anomaly with anomaly_ratio > 0.9 is detected alongside repeated signals THEN the system SHALL CONTINUE TO apply the strong ML boost and escalate risk appropriately

3.3 WHEN a honeypot interaction is detected THEN the system SHALL CONTINUE TO apply the honeypot boost and treat it as a strong signal for escalation

3.4 WHEN multiple correlated attack signals are detected from the same IP within the correlation window THEN the system SHALL CONTINUE TO apply correlation boosts to the risk score

3.5 WHEN an IP is on the whitelist THEN the system SHALL CONTINUE TO refuse to block it regardless of risk score

3.6 WHEN a SYSTEM or LOCAL_DEVICE source type is identified THEN the system SHALL CONTINUE TO apply reduced base increments and avoid blocking unless risk is extremely high

3.7 WHEN risk decays over time due to inactivity THEN the system SHALL CONTINUE TO reduce the risk score via the existing exponential decay mechanism

3.8 WHEN a previously blocked IP's risk drops below the threshold after the cooldown period THEN the system SHALL CONTINUE TO auto-unblock it
