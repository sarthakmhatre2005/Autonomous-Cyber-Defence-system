import socket
import time
import requests

HONEYPOT_PORT = 2222
API_BASE = "http://localhost:5000"

def test_honeypot_connection():
    print(f"[*] Attempting to connect to honeypot on port {HONEYPOT_PORT}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('127.0.0.1', HONEYPOT_PORT))
        banner = s.recv(1024).decode()
        print(f"[+] Connected! Banner received: {banner.strip()}")
        s.close()
        return True
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return False

def verify_logs():
    print("[*] Verifying honeypot logs via API...")
    try:
        response = requests.get(f"{API_BASE}/api/honeypot/events")
        if response.status_code == 200:
            events = response.json()
            if len(events) > 0:
                latest = events[0]
                print(f"[+] Found log entry: {latest['source_ip']} accessed port {latest['honeypot_port']}")
                return True
            else:
                print("[-] No honeypot events found in logs.")
        else:
            print(f"[-] API error: {response.status_code}")
    except Exception as e:
        print(f"[-] Request failed: {e}")
    return False

def verify_threat_score():
    print("[*] Verifying threat score increase...")
    try:
        response = requests.get(f"{API_BASE}/api/network/top-threats")
        if response.status_code == 200:
            threats = response.json()
            # Look for 127.0.0.1 (or loopback) with a score >= 10
            for t in threats:
                if t['ip'] == '127.0.0.1' and t['score'] >= 10:
                    print(f"[+] Verified threat score for 127.0.0.1: {t['score']}")
                    return True
            print("[-] 127.0.0.1 not found in high threats or score too low.")
        else:
            print(f"[-] API error: {response.status_code}")
    except Exception as e:
        print(f"[-] Request failed: {e}")
    return False

if __name__ == "__main__":
    print("=== Honeypot Verification Script ===")
    if test_honeypot_connection():
        time.sleep(1) # Wait for processing
        logs_ok = verify_logs()
        score_ok = verify_threat_score()
        
        if logs_ok and score_ok:
            print("\n[SUCCESS] Honeypot module is working correctly!")
        else:
            print("\n[FAILURE] Verification failed.")
    else:
        print("\n[ERROR] Could not connect to honeypot. Is the app running?")
