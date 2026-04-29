import socket
import time
import threading

def simulate_port_scan(target_ip="127.0.0.1"):
    print(f"[*] Simulating port scan on {target_ip}...")
    for port in range(100, 150):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.01)
            s.connect((target_ip, port))
            s.close()
        except:
            pass
        # time.sleep(0.01)
    print("[+] Port scan simulation finished.")

def simulate_traffic_burst(target_ip="127.0.0.1"):
    print(f"[*] Simulating traffic burst to {target_ip}...")
    for _ in range(500):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"test", (target_ip, 80))
        except:
            pass
    print("[+] Traffic burst simulation finished.")

if __name__ == "__main__":
    # Note: simulate to an external IP or a different local IP to trigger detection
    # Loopback (127.0.0.1) is often ignored by the threat engine to avoid noise.
    
    # Try to find a local IP that isn't loopback
    local_ip = socket.gethostbyname(socket.gethostname())
    print(f"[!] Using local IP: {local_ip}")
    
    # Run simulation
    simulate_port_scan(local_ip)
    time.sleep(2)
    simulate_traffic_burst(local_ip)
