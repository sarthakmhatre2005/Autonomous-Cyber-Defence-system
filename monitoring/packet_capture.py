"""
Packet Capture Layer - Real Network Traffic Analysis
Captures ALL incoming packets: internal + external IPs
Uses scapy for deep packet inspection with psutil fallback
"""
import threading
import time
import socket
import ipaddress
from collections import defaultdict, deque
from datetime import datetime

# Try scapy import
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR, conf, get_if_list
    conf.verb = 0  # Silent mode
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[PacketCapture] Scapy not available. Using psutil connection monitor.")

import psutil
from functools import lru_cache

# ─── IP Classification ────────────────────────────────────────────────────────

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

@lru_cache(maxsize=1024)
def is_private_ip(ip_str):
    """Returns True if IP is private/loopback/link-local."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_RANGES)
    except ValueError:
        return False

@lru_cache(maxsize=1024)
def get_ip_type(ip_str):
    """Returns 'EXTERNAL', 'INTERNAL', or 'LOOPBACK'."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback:
            return "LOOPBACK"
        if ip.is_private:
            return "INTERNAL"
        return "EXTERNAL"
    except ValueError:
        return "UNKNOWN"

# ─── Packet Storage (Ring Buffer) ─────────────────────────────────────────────

class PacketStore:
    """Thread-safe ring buffer for recent packet metadata."""
    MAX_SIZE = 2000

    def __init__(self):
        self._lock = threading.Lock()
        self._packets = deque(maxlen=self.MAX_SIZE)
        # Per-IP packet rate tracking: ip -> list of timestamps
        self.ip_timestamps = defaultdict(lambda: deque(maxlen=500))
        # Per-IP port tracking: ip -> set of ports
        self.ip_ports = defaultdict(set)
        # Per-IP byte tracking
        self.ip_bytes = defaultdict(int)
        # Per-IP protocol set
        self.ip_protocols = defaultdict(set)
        # Packet counter
        self.total_captured = 0
        self.external_captured = 0
        self.internal_captured = 0

    def add(self, pkt_meta):
        # Move classification and pre-processing out of the lock
        ip = pkt_meta.get("src_ip", "")
        ts = pkt_meta.get("timestamp", time.time())
        port = pkt_meta.get("dst_port")
        bytes_count = pkt_meta.get("payload_size", 0)
        protocol = pkt_meta.get("protocol")
        ip_type = pkt_meta.get("ip_type", "INTERNAL")

        with self._lock:
            self._packets.append(pkt_meta)
            self.ip_timestamps[ip].append(ts)
            if port:
                self.ip_ports[ip].add(port)
            self.ip_bytes[ip] += bytes_count
            if protocol:
                self.ip_protocols[ip].add(protocol)
            self.total_captured += 1
            if ip_type == "EXTERNAL":
                self.external_captured += 1
            else:
                self.internal_captured += 1

    def get_recent(self, n=100):
        with self._lock:
            return list(self._packets)[-n:]

    def get_ip_rate(self, ip, window_sec=10):
        """Packets per second from this IP in last window_sec seconds."""
        with self._lock:
            now = time.time()
            ts_list = self.ip_timestamps.get(ip, deque())
            recent = [t for t in ts_list if now - t <= window_sec]
            return len(recent) / window_sec if window_sec > 0 else 0

    def get_ip_ports(self, ip):
        with self._lock:
            return set(self.ip_ports.get(ip, set()))

    def get_ip_port_count(self, ip):
        with self._lock:
            return len(self.ip_ports.get(ip, set()))

    def get_ip_bytes(self, ip):
        with self._lock:
            return self.ip_bytes.get(ip, 0)

    def get_stats(self):
        with self._lock:
            return {
                "total_captured": self.total_captured,
                "external_captured": self.external_captured,
                "internal_captured": self.internal_captured,
                "unique_ips": len(self.ip_timestamps),
            }

    def get_all_ips(self):
        with self._lock:
            return list(self.ip_timestamps.keys())

    def get_external_ips(self):
        with self._lock:
            return [ip for ip in self.ip_timestamps.keys() if get_ip_type(ip) == "EXTERNAL"]


# Global packet store
packet_store = PacketStore()

# ─── Scapy Packet Handler ─────────────────────────────────────────────────────

# Avoid repeated globals lookup for hot path
_traffic_analyzer_cached = None

def handle_packet(pkt):
    """Process each captured packet and store metadata."""
    global _traffic_analyzer_cached
    try:
        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # We care about INCOMING packets (dst is local) and OUTGOING (src is local)
        # Focus on connections FROM external sources TO this machine
        ip_type = get_ip_type(src_ip)

        protocol = "OTHER"
        dst_port = None
        src_port = None
        payload_size = 0
        flags = None

        meta = {
            "timestamp": time.time(),
            "datetime": datetime.now().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ip_type": ip_type,
            "protocol": protocol,
            "payload_size": 0,
            "source": "scapy"
        }

        if pkt.haslayer(TCP):
            protocol = "TCP"
            dst_port = pkt[TCP].dport
            src_port = pkt[TCP].sport
            flags = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            dst_port = pkt[UDP].dport
            src_port = pkt[UDP].sport
            # Detect QUIC
            if dst_port == 443 or src_port == 443:
                protocol = "QUIC"
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
        elif pkt.haslayer(DNS):
            protocol = "DNS"
        
        meta["protocol"] = protocol
        meta["dst_port"] = dst_port
        meta["src_port"] = src_port
        meta["flags"] = flags

        if pkt.haslayer(IP):
            payload_size = pkt[IP].len
        elif pkt.haslayer(IPv6):
            payload_size = pkt[IPv6].plen
        else:
            payload_size = len(pkt)
        
        meta["payload_size"] = payload_size

        # ─── NEW: DNS Analysis Metadata ─────────────────────────────────────
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode('utf-8').strip('.')
            meta["dns_query"] = query

        packet_store.add(meta)

        # Forward to analysis layer asynchronously via queue
        if _traffic_analyzer_cached is None:
            from monitoring.traffic_analyzer import traffic_analyzer
            _traffic_analyzer_cached = traffic_analyzer
        
        _traffic_analyzer_cached.process_packet(meta)

    except Exception as e:
        pass  # Silent fail on malformed packets


def find_active_interface():
    """Attempts to find the most active network interface (Scapy compatible)."""
    try:
        from scapy.all import IFACES
        import psutil
        
        # 1. Get all active IPs from psutil
        active_ips = set()
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    active_ips.add(addr.address)
                    
        # 2. Match Scapy IFACES by IP
        for dev in IFACES.values():
            if dev.ip in active_ips:
                # Prefer Wi-Fi or Ethernet in description
                desc = dev.description.lower() if hasattr(dev, 'description') else ""
                if "wi-fi" in desc or "wlan" in desc or "ethernet" in desc or "wireless" in desc:
                    print(f"[PacketCapture] Found primary interface: {dev.description} ({dev.ip})")
                    return dev
        
        # Fallback: first non-loopback with an IP
        for dev in IFACES.values():
            if dev.ip and not dev.ip.startswith("127.") and dev.ip != "0.0.0.0":
                print(f"[PacketCapture] Falling back to interface: {dev.description} ({dev.ip})")
                return dev
                
    except Exception as e:
        print(f"[PacketCapture] Interface selection error: {e}")
    return None

def start_scapy_capture():
    """Start capturing packets using scapy."""
    iface = find_active_interface()
    # Scapy-compatible filter: ignore loopback and focus on external traffic
    # 'ip' captures both in/out, we exclude 127.0.0.1 specifically
    bpffilter = "ip"
    
    print(f"[PacketCapture] Starting Scapy capture on: {iface or 'ALL Interfaces'}")
    print(f"[PacketCapture] Filter: {bpffilter}")
    
    try:
        # Optimization: use store=False to avoid memory bloat
        sniff(filter=bpffilter, prn=handle_packet, store=False, iface=iface, count=0)
    except Exception as e:
        print(f"[PacketCapture] Scapy capture error: {e}")


# ─── PSUtil Connection Monitor (Fallback + Supplement) ────────────────────────

class ConnectionMonitor:
    """
    Uses psutil to monitor all active network connections.
    Works on all platforms without root. Tracks connection metadata.
    """
    def __init__(self):
        self.known_connections = set()  # (pid, laddr, raddr, status)
        self.connection_counts = defaultdict(int)  # ip -> connection count

    def scan_connections(self):
        """Scan all current connections and detect new/changed ones."""
        try:
            connections = psutil.net_connections(kind='inet')
            current_set = set()

            for conn in connections:
                if not conn.raddr:
                    continue

                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                local_port = conn.laddr.port if conn.laddr else 0
                status = conn.status
                pid = conn.pid

                # Detect Protocol
                is_udp = conn.type == socket.SOCK_DGRAM
                protocol = "UDP" if is_udp else "TCP"
                if is_udp and (remote_port == 443 or local_port == 443):
                    protocol = "QUIC"

                conn_key = (remote_ip, remote_port, local_port, status, protocol)
                current_set.add(conn_key)

                self.connection_counts[remote_ip] += 1

                if conn_key not in self.known_connections:
                    self.known_connections.add(conn_key)

                    ip_type = get_ip_type(remote_ip)
                    proc_name = "SYSTEM"
                    try:
                        if pid:
                            proc_name = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    meta = {
                        "timestamp": time.time(),
                        "datetime": datetime.now().isoformat(),
                        "src_ip": remote_ip,
                        "dst_ip": "LOCAL",
                        "ip_type": ip_type,
                        "protocol": protocol,
                        "src_port": remote_port,
                        "dst_port": local_port,
                        "payload_size": 0,
                        "flags": status,
                        "ttl": 0,
                        "process": proc_name,
                        "pid": pid,
                        "source": "psutil",
                    }

                    packet_store.add(meta)

                    # Forward to threat engine via async queue
                    try:
                        from monitoring.traffic_analyzer import traffic_analyzer
                        traffic_analyzer.process_packet(meta)
                    except Exception:
                        pass

            # Cleanup stale connections (keep only current + recent)
            self.known_connections &= current_set
            # Bound the connection_counts dict size
            if len(self.connection_counts) > 2000:
                self.connection_counts.clear()

        except Exception as e:
            pass  # Keep monitoring


connection_monitor = ConnectionMonitor()


def start_connection_monitor():
    """Run psutil connection monitor in background loop."""
    print("[PacketCapture] Starting psutil connection monitor...")
    while True:
        try:
            connection_monitor.scan_connections()
        except Exception as e:
            pass
        time.sleep(5)  # 5s is plenty for connection-level tracking; 2s was too heavy


# ─── Network Interface Stats ──────────────────────────────────────────────────

_last_net_io = None
_last_net_time = None

def get_network_throughput():
    """Returns (bytes_sent_per_sec, bytes_recv_per_sec) over last interval."""
    global _last_net_io, _last_net_time
    try:
        current = psutil.net_io_counters()
        now = time.time()
        if _last_net_io is None:
            _last_net_io = current
            _last_net_time = now
            return 0, 0
        elapsed = now - _last_net_time
        if elapsed <= 0:
            return 0, 0
        sent_rate = (current.bytes_sent - _last_net_io.bytes_sent) / elapsed
        recv_rate = (current.bytes_recv - _last_net_io.bytes_recv) / elapsed
        _last_net_io = current
        _last_net_time = now
        return max(0, sent_rate), max(0, recv_rate)
    except Exception:
        return 0, 0


def get_interface_stats():
    """Returns per-interface network statistics."""
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        result = []
        for iface, stat in stats.items():
            iface_addrs = addrs.get(iface, [])
            ips = [a.address for a in iface_addrs if a.family == socket.AF_INET]
            result.append({
                "interface": iface,
                "is_up": stat.isup,
                "speed": stat.speed,
                "ips": ips,
            })
        return result
    except Exception:
        return []


# ─── Startup ──────────────────────────────────────────────────────────────────

def start_packet_capture():
    """Start all capture layers."""

    # Always start psutil connection monitor (lightweight, no root needed)
    t1 = threading.Thread(target=start_connection_monitor, daemon=True)
    t1.start()

    # Start Scapy if available (needs WinPcap/Npcap on Windows)
    if SCAPY_AVAILABLE:
        t2 = threading.Thread(target=start_scapy_capture, daemon=True)
        t2.start()
        print("[PacketCapture] Both Scapy + psutil monitors active.")
    else:
        print("[PacketCapture] psutil monitor active (install Npcap + scapy for deep packet inspection).")

    return packet_store
