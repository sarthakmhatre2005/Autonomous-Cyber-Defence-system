import socket
import threading
import time
from datetime import datetime
from data.database import log_honeypot_event
from core.threat_engine import threat_engine

class HoneypotService:
    """
    A lightweight honeypot service that listens on multiple ports.
    Detects connection attempts and alerts the threat engine.
    """
    def __init__(self, ports=[21, 22, 23, 80, 443, 3389], banners={22: "SSH-2.0-OpenSSH_8.2p1\r\n"}):
        self.ports = ports
        self.banners = banners
        self.running = False
        self.sockets = []
        self._threads = []

    def start(self):
        if self.running:
            return
        
        self.running = True
        for port in self.ports:
            t = threading.Thread(target=self._run_port, args=(port,), daemon=True)
            t.start()
            self._threads.append(t)
        print(f"[Honeypot] Services started on ports: {self.ports}")

    def stop(self):
        self.running = False
        for sock in self.sockets:
            try: sock.close()
            except: pass

    def _run_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sockets.append(sock)
        try:
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            sock.settimeout(1.0)
            print(f"[Honeypot] Successfully listening on port {port}")
        except Exception as e:
            print(f"[Honeypot] ERROR: Could not bind to port {port}. This port might be in use by another application or require higher privileges: {e}")
            return

        while self.running:
            try:
                client_sock, client_addr = sock.accept()
                ip = client_addr[0]
                
                print(f"[Honeypot] CRITICAL: Honeypot interaction on port {port} from {ip}")
                
                # 1. Log to database
                log_honeypot_event(ip, client_addr[1], port, "Unauthorized access attempt")
                
                # 2. Alert threat engine - IMMEDIATE CRITICAL
                alert = {
                    "ip": ip,
                    "type": "HONEYPOT_HIT",
                    "score": 100, # Max score for immediate block
                    "detail": f"Honeypot interaction detected on port {port} (unauthorized access attempt)",
                    "reason": f"Honeypot interaction detected on port {port} (unauthorized access attempt)",
                    "severity": "CRITICAL",
                    "target_port": port
                }
                threat_engine.process_alert(alert)
                
                # 3. Handle connection
                banner = self.banners.get(port, "Access Denied\r\n")
                client_sock.send(banner.encode())
                time.sleep(0.1)
                client_sock.close()
                
            except socket.timeout:
                continue
            except Exception:
                break

# Global singleton
honeypot_service = HoneypotService()

def start_honeypot():
    honeypot_service.start()
