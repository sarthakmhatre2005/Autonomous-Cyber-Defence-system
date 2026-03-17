# Autonomous Cyber Defence System - Error Fix TODO

## Approved Plan Steps:

### 1. Create TODO.md [✅ COMPLETE]

### 2. Fix log_event calls in monitoring/process_monitor.py [✅ COMPLETE]

- Fix active window tracking call
- Fix new process detection call
- Fix process kill event call
- Fix proactive track call

### 3. Fix log_event calls in monitoring/persistence_monitor.py [✅ COMPLETE]

- Update \_report_persistence log_event call with full keywords

### 4. Read and fix any issues in core/threat_engine.py log_event calls [✅ COMPLETE - no changes needed]

### 5. Fix DB schema: ALTER TABLE events ADD COLUMN dest_ip TEXT [✅ COMPLETE - column already present]

### 6. Verify fixes: Restart main.py, check no errors in logs [PENDING]

### 7. Test dashboard APIs, complete task [PENDING]
