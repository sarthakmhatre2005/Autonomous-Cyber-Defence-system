import sys
import os
import time
import json
import sqlite3

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.database import log_event, init_db, get_recent_events, DB_FILE

def test_logging():
    print("[*] Initializing test database...")
    init_db()
    
    print("[*] Testing log_event with full arguments...")
    log_event(
        src_ip="1.2.3.4",
        dest_ip="8.8.8.8",
        src_port=1234,
        dst_port=80,
        protocol="TCP",
        payload_size=500,
        severity="HIGH",
        anomaly_score=0.9,
        active_window="TEST_WINDOW",
        details={"test": "full_args"},
        threat_score=15
    )
    
    print("[*] Testing log_event with partial arguments (defaults check)...")
    log_event(src_ip="4.3.2.1", details={"test": "partial_args"})
    
    print("[*] Waiting for async logger...")
    time.sleep(2)
    
    print("[*] Verifying data in database...")
    events = get_recent_events(limit=5)
    
    if not events:
        print("[!] ERROR: No events found in database.")
        return False
        
    for ev in events:
        print(f"  - Event ID {ev['id']}: {ev['src_ip']} -> {ev['dest_ip']} (Threat: {ev.get('threat_score', 'N/A')})")
        
    # Check for specific columns
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("PRAGMA table_info(events)")
    cols = [row[1] for row in c.fetchall()]
    conn.close()
    
    required = ["src_ip", "dest_ip", "anomaly_score", "threat_score"]
    missing = [col for col in required if col not in cols]
    
    if missing:
        print(f"[!] ERROR: Missing columns: {missing}")
        return False
    
    print("[+] Verification SUCCESSFUL: Logging pipeline is stable and schema is correct.")
    return True

if __name__ == "__main__":
    if test_logging():
        sys.exit(0)
    else:
        sys.exit(1)
