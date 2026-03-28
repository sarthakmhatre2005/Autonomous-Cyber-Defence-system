import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import time
import random
import threading
from monitoring.traffic_analyzer import traffic_analyzer
from monitoring.packet_capture import get_ip_type

def simulate_packets(n=5000):
    print(f"Starting simulation of {n} packets...")
    start_time = time.time()
    
    ips = [f"192.168.1.{i}" for i in range(1, 100)]
    external_ips = [f"203.0.113.{i}" for i in range(1, 50)]
    all_ips = ips + external_ips
    
    for i in range(n):
        src_ip = random.choice(all_ips)
        pkt_meta = {
            "timestamp": time.time(),
            "src_ip": src_ip,
            "dst_ip": "192.168.1.100",
            "ip_type": get_ip_type(src_ip),
            "protocol": random.choice(["TCP", "UDP", "ICMP", "QUIC"]),
            "dst_port": random.choice([80, 443, 22, 53, 3389] + list(range(1000, 2000))),
            "payload_size": random.randint(0, 1500),
            "source": "simulated"
        }
        
        # Simulate some DNS traffic
        if random.random() < 0.1:
            pkt_meta["dns_query"] = random.choice(["google.com", "malicious-site.xyz", "unknown-domain.io", "github.com"])
            
        traffic_analyzer.process_packet(pkt_meta)
        
        if i % 1000 == 0 and i > 0:
            print(f"Sent {i} packets...")

    print(f"Simulation sent {n} packets in {time.time() - start_time:.2f} seconds.")
    
    # Wait for analyzer to catch up
    print("Waiting for analyzer queue to clear...")
    while not traffic_analyzer.packet_queue.empty():
        time.sleep(0.5)
        
    duration = time.time() - start_time
    stats = traffic_analyzer.get_stats()
    print(f"\nResults:")
    print(f"Total Packets Processed: {stats['total_packets']}")
    print(f"Processing Rate: {n / duration:.2f} packets/sec")
    print(f"Unique IPs: {stats['unique_ips']}")
    print(f"Recent Alerts: {stats['recent_alerts']}")

if __name__ == "__main__":
    simulate_packets(50000)
