from scapy.all import IFACES, IP, sniff, conf
import psutil
import socket
import time

def test_interfaces():
    print("--- SCAPY INTERFACES ---")
    for dev in IFACES.values():
        print(f"Name: {dev.name}, IP: {dev.ip}, Description: {dev.description}")
        
    print("\n--- PSUTIL INTERFACES ---")
    for iface, addrs in psutil.net_if_addrs().items():
        print(f"Interface: {iface}")
        for addr in addrs:
            print(f"  {addr.family}: {addr.address}")

if __name__ == "__main__":
    test_interfaces()
