import os
import threading
import sys
from data.database import init_db
from monitoring.process_monitor import start_process_monitor
from monitoring.persistence_monitor import start_persistence_monitor
from monitoring.packet_capture import start_packet_capture
from defense.honeypot import start_honeypot
from monitoring.dns_monitor import start_dns_monitor
from dashboard.app import app

def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def main():
    print("=" * 60)
    print("Initializing Autonomous AI Cyber Response Engine...")
    print("=" * 60)

    if not is_admin():
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("WARNING: SYSTEM NOT RUNNING AS ADMINISTRATOR")
        print("Firewall blocking and Domain blocking will be DISABLED.")
        print("Please restart the terminal/IDE as Administrator.")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
    
    # 1. Initialize SQLite Database
    init_db()
    print("[+] Database initialized successfully.")

    # 2. Start all background monitoring and defense threads
    start_process_monitor()
    print("[+] Process Monitor started.")
    
    start_persistence_monitor()
    print("[+] Persistence Monitor started.")
    
    start_packet_capture()
    print("[+] Packet Capture engine started.")
    
    start_honeypot()
    print("[+] Deception Honeypot started.")

    start_dns_monitor()
    print("[+] DNS Cache Monitor started (catches DoH + cached lookups).")

    print("\n[+] Background services running. Launching SOC Dashboard...")
    
    # 3. Launch Flask Dashboard Application
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Autonomous AI Cyber Response Engine.")
        sys.exit(0)
