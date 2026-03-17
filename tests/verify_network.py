import socket
import time
import requests

API_BASE = "http://localhost:5000"

def verify_udp_quic():
    print("[*] Verifying UDP/QUIC capture via API...")
    try:
        # Give it a moment to capture something if app is running
        time.sleep(2)
        response = requests.get(f"{API_BASE}/api/network/packets")
        if response.status_code == 200:
            pkts = response.json()
            found_udp = False
            found_quic = False
            for p in pkts:
                if p['protocol'] == 'UDP': found_udp = True
                if p['protocol'] == 'QUIC': found_quic = True
            
            if found_udp: print("[+] Found UDP packets in capture!")
            else: print("[-] No UDP packets found yet. Try browsing a bit.")
            
            if found_quic: print("[+] Found QUIC packets in capture!")
            else: print("[-] No QUIC packets found yet. Try opening YouTube.")
            
            return found_udp or found_quic
        else:
            print(f"[-] API error: {response.status_code}")
    except Exception as e:
        print(f"[-] Request failed: {e}")
    return False

if __name__ == "__main__":
    print("=== Network Monitoring Verification ===")
    verify_udp_quic()
