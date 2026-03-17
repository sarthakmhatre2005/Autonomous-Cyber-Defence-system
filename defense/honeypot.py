import socket
import threading
import time
from datetime import datetime
from data.database import log_honeypot_event
from core.threat_engine import threat_engine

class HoneypotService:
    """
    A lightweight honeypot service that listens on a specific port.
    Detects connection attempts and alerts the threat engine.
    """
    def __init__(self, port=2222, banner="SSH-2.0-OpenSSH_8.2p1\r\n"):
        self.port = port
        self.banner = banner
        self.running = False
        self._thread = None
        self.socket = None

    def start(self):
        if self.running:
            return
        
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        print(f"[Honeypot] Service started on port {self.port}")

    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()

    def _run(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.listen(5)
            self.socket.settimeout(1.0)
        except Exception as e:
            print(f"[Honeypot] Error binding to port {self.port}: {e}")
            self.running = False
            return

        while self.running:
            try:
                client_sock, client_addr = self.socket.accept()
                ip = client_addr[0]
                port = client_addr[1]
                
                print(f"[Honeypot] Connection attempt from {ip}:{port} on decoy port {self.port}")
                
                # 1. Log to database
                log_honeypot_event(ip, port, self.port, "Connection established")
                
                # 2. Alert threat engine
                alert = {
                    "ip": ip,
                    "type": "HONEYPOT_HIT",
                    "score": 10,
                    "detail": f"Decoy Service Hit: port {self.port} (fake SSH)",
                    "severity": "HIGH",
                    "ip_type": "EXTERNAL" # Simplified assumption, threat engine will refine
                }
                threat_engine.process_alert(alert)
                
                # 3. Handle connection (send banner and close)
                client_sock.send(self.banner.encode())
                time.sleep(0.5)
                client_sock.close()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[Honeypot] Error: {e}")
                break

# Global singleton
honeypot_service = HoneypotService(port=2222)

def start_honeypot():
    honeypot_service.start()
