import queue
import threading
import subprocess
import time
import socket
from datetime import datetime
from collections import defaultdict

# --- SHARED STATE ---
class IDSLogic:
    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=10000)
        self.blocked_ips = set()
        self.threat_logs = []
        self.honeypot_hits = 0
        self.traffic_windows = defaultdict(lambda: {
            "packet_count": 0,
            "unique_ports": set(),
            "syn_count": 0,
            "threats": set()
        })
        self.dns_cache = {}
        self._lock = threading.Lock()

    def reset_state(self):
        with self._lock:
            self.blocked_ips.clear()
            self.threat_logs.clear()
            self.honeypot_hits = 0
            self.traffic_windows.clear()
            self.dns_cache.clear()
        print("[SYSTEM] State Reset.")

    def get_reverse_dns(self, ip):
        """Requirement: socket.gethostbyaddr(ip)"""
        if ip in self.dns_cache: return self.dns_cache[ip]
        try:
            # Short timeout to avoid blocking detection
            socket.setdefaulttimeout(0.8)
            domain = socket.gethostbyaddr(ip)[0]
        except:
            domain = "unknown"
        with self._lock:
            self.dns_cache[ip] = domain
        return domain

    def block_ip(self, ip):
        if ip in self.blocked_ips: return
        cmd = f'netsh advfirewall firewall add rule name="BLOCK_{ip}" dir=in action=block remoteip={ip}'
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True)
            if result.returncode == 0:
                print(f"[BLOCK SUCCESS] {ip}")
                with self._lock:
                    self.blocked_ips.add(ip)
        except: pass

    def log_forensics(self, ip, reason, score, action):
        """Log events with real reverse DNS."""
        entry = {
            "ip": ip,
            "domain": self.get_reverse_dns(ip),
            "timestamp": datetime.now().isoformat(),
            "reason": reason,
            "score": score,
            "action": action
        }
        with self._lock:
            self.threat_logs.append(entry)
        print(f"[THREAT] {action} {ip} ({entry['domain']}): {reason}")

    def feature_worker(self):
        print("[IDS LOGIC] Worker active.")
        while True:
            try:
                data = self.packet_queue.get()
                if data is None: break
                
                src_ip = data.get("src_ip", "0.0.0.0")
                
                # Special Requirement: Log DNS Activity
                if data.get("is_dns"):
                    domain = self.get_reverse_dns(src_ip)
                    self.log_forensics(src_ip, "DNS Activity detected", 5, "MONITOR")
                    self.packet_queue.task_done()
                    continue

                if src_ip in self.blocked_ips:
                    self.packet_queue.task_done()
                    continue
                    
                stats = self.traffic_windows[src_ip]
                stats["packet_count"] += 1
                if data.get("dst_port") is not None:
                    stats["unique_ports"].add(data["dst_port"])
                if data.get("protocol") == "TCP" and data.get("flags") == "S":
                    stats["syn_count"] += 1
                    
                # Detection rules
                port_count = len(stats["unique_ports"])
                syn_count = stats["syn_count"]
                
                if port_count > 10 and "PORT_SCAN" not in stats["threats"]:
                    self.log_forensics(src_ip, f"{port_count} ports scanned", port_count*5, "ALERT")
                    stats["threats"].add("PORT_SCAN")
                    
                if syn_count > 30 and "SYN_FLOOD" not in stats["threats"]:
                    self.log_forensics(src_ip, f"{syn_count} SYN packets", syn_count*2, "BLOCK")
                    self.block_ip(src_ip)
                    stats["threats"].add("SYN_FLOOD")
                    
                self.packet_queue.task_done()
            except Exception as e:
                print(f"[IDS LOGIC ERROR] {e}")

# Global instance
ids_logic = IDSLogic()

def start_logic_engine():
    ids_logic.reset_state()
    threading.Thread(target=ids_logic.feature_worker, daemon=True).start()
