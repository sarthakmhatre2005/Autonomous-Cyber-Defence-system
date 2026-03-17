"""
Attack Correlation Engine
- Correlates events across different telemetry layers
- Builds "Attack Chains" based on source IP and temporal proximity
- Enhances threat scores when multiple vectors are involved
"""
import time
from collections import defaultdict, deque
from datetime import datetime

class CorrelationEngine:
    def __init__(self):
        # ip -> list of recent events
        self.ip_history = defaultdict(lambda: deque(maxlen=20))
        self.attack_chains = []
        self.CHAIN_TIMEOUT = 600  # 10 minutes

    def correlate(self, alert):
        ip = alert.get("ip")
        if not ip or ip == "LOCALHOST":
            return None

        now = time.time()
        history = self.ip_history[ip]
        history.append({
            "timestamp": now,
            "type": alert.get("type"),
            "severity": alert.get("severity"),
            "detail": alert.get("detail")
        })

        # Check for attack chains
        # Example: Port Scan -> DNS Query -> Suspicious Process
        types = {e["type"] for e in history if now - e["timestamp"] < self.CHAIN_TIMEOUT}
        
        if len(types) >= 2:
            chain = {
                "ip": ip,
                "start_time": datetime.fromtimestamp(min(e["timestamp"] for e in history)).isoformat(),
                "event_types": list(types),
                "confidence": "HIGH" if len(types) >= 3 else "MEDIUM",
                "events": list(history)
            }
            return chain
        
        return None

correlation_engine = CorrelationEngine()
