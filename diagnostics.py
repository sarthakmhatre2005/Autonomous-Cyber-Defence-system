import json
import time
import os
from datetime import datetime

# Import the singletons
from core.threat_engine import threat_engine
from monitoring.traffic_analyzer import traffic_analyzer
from monitoring.packet_capture import packet_store

def generate_diagnostic_report():
    """Generates a detailed diagnostic report of the internal system state."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "threat_engine": {
            "states_count": len(threat_engine._states),
            "blocked_count": len(threat_engine._blocked_ips),
            "timeline_count": len(threat_engine._event_timeline),
            "ips_in_memory": list(threat_engine._states.keys())
        },
        "traffic_analyzer": {
            "alert_queue_count": len(traffic_analyzer.alert_queue),
            "total_packets": traffic_analyzer.total_packets,
            "external_packets": traffic_analyzer.external_packets,
            "profiles_count": len(traffic_analyzer._profiles)
        },
        "packet_store": {
            "total_captured": len(packet_store._packets)
        }
    }
    
    # Check for sample data
    if threat_engine._states:
        first_ip = next(iter(threat_engine._states))
        report["sample_state"] = threat_engine._states[first_ip].to_dict()
    
    return report

def dump_to_console():
    report = generate_diagnostic_report()
    print("\n" + "="*60)
    print("SOC SYSTEM DIAGNOSTIC REPORT")
    print("="*60)
    print(json.dumps(report, indent=2))
    print("="*60 + "\n")
    return report
