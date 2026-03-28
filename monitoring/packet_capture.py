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

def get_all_local_ips():
    """Returns a set of all local IP addresses active on this machine."""
    ips = {"127.0.0.1", "::1", "localhost"}
    try:
        import psutil
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ips.add(addr.address)
    except:
        pass
    
    # Try to add default gateway
    try:
        # On Windows, this is a bit tricky without extra libs, 
        # but we can infer it from 'route print' or common patterns.
        # Simple heuristic: if we know our IP and it's 192.168.x.y, 
        # 192.168.x.1 is often the gateway.
        for ip in list(ips):
            if ip.startswith("192.168.") or ip.startswith("10."):
                parts = ip.split('.')
                gateway = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
                ips.add(gateway)
    except:
        pass
    return ips

# Global set of protected IPs
PROTECTED_IPS = get_all_local_ips()

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
            # Avoid repeated lookups in loop
            return [ip for ip in self.ip_timestamps.keys() if get_ip_type(ip) == "EXTERNAL"]


# Global packet store
packet_store = PacketStore()

# ─── Process Correlation Map ──────────────────────────────────────────────────
# (proto, src_ip, src_port, dst_ip, dst_port) -> (process_name, pid)
_CONNECTION_PROCESS_MAP = {}
_CONN_LOCK = threading.Lock()

def update_process_map(conn_data):
    """Updates the global connection-to-process mapping."""
    with _CONN_LOCK:
        # Keep map size bounded
        if len(_CONNECTION_PROCESS_MAP) > 5000:
            _CONNECTION_PROCESS_MAP.clear()
        
        # Add both directions
        key1 = (conn_data['protocol'], conn_data['src_ip'], conn_data['src_port'], conn_data['dst_ip'], conn_data['dst_port'])
        key2 = (conn_data['protocol'], conn_data['dst_ip'], conn_data['dst_port'], conn_data['src_ip'], conn_data['src_port'])
        _CONNECTION_PROCESS_MAP[key1] = (conn_data.get('process'), conn_data.get('pid'))
        _CONNECTION_PROCESS_MAP[key2] = (conn_data.get('process'), conn_data.get('pid'))

def get_process_for_packet(proto, sip, sport, dip, dport):
    """Looks up the process associated with a network 5-tuple."""
    with _CONN_LOCK:
        return _CONNECTION_PROCESS_MAP.get((proto, sip, sport, dip, dport), ("UNKNOWN", None))

# Avoid repeated globals lookup for hot path
_traffic_analyzer_cached = None

def handle_packet(pkt):
    """
    ULTRA-LIGHTWEIGHT Handler: 
    Extract minimal metadata and enqueue IMMEDIATELY.
    All classification/DNS analysis moved to worker threads.
    """
    global _traffic_analyzer_cached
    try:
        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Minimal metadata for the queue
        meta = {
            "timestamp": time.time(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": "OTHER",
            "payload_size": ip_layer.len,
            "source": "scapy"
        }

        # Pass protocol and ports for the worker to correlate with processes
        if pkt.haslayer(TCP):
            meta["protocol"] = "TCP"
            meta["dst_port"] = pkt[TCP].dport
            meta["src_port"] = pkt[TCP].sport
            meta["flags"] = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            meta["protocol"] = "UDP"
            meta["dst_port"] = pkt[UDP].dport
            meta["src_port"] = pkt[UDP].sport
        elif pkt.haslayer(ICMP):
            meta["protocol"] = "ICMP"
        
        # New: Defer deep inspection (DNS) to worker
        if pkt.haslayer(DNS):
            meta["has_dns"] = True
            if pkt.haslayer(DNSQR):
                # Only pass the raw qname object, don't decode here (CPU expensive)
                try: meta["_dns_raw_qname"] = pkt[DNSQR].qname 
                except: pass

        # Forward to analysis layer IMMEDIATELY
        if _traffic_analyzer_cached is None:
            from monitoring.traffic_analyzer import traffic_analyzer
            _traffic_analyzer_cached = traffic_analyzer
        
        _traffic_analyzer_cached.process_packet(meta)

    except Exception:
        pass  # Silent fail is better than crashing the capture thread


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
                    
        # 2. Get local IP and default gateway
        local_ip = None
        try:
            # Simple way to get local IP used for internet
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except: pass

        # 3. Match Scapy IFACES by IP
        best_fallback = None
        for dev in IFACES.values():
            if not dev.ip or dev.ip.startswith("127.") or dev.ip == "0.0.0.0":
                continue
            
            # Perfect match: current local IP
            if dev.ip == local_ip:
                print(f"[PacketCapture] Found LOCAL interface: {dev.description} ({dev.ip})")
                return dev
            
            # Good match: active IPs from psutil
            if dev.ip in active_ips:
                desc = dev.description.lower() if hasattr(dev, 'description') else ""
                if any(x in desc for x in ["wi-fi", "wlan", "ethernet", "wireless", "gigabit", "realtek", "intel"]):
                    best_fallback = dev
        
        if best_fallback:
            print(f"[PacketCapture] Found active interface: {best_fallback.description} ({best_fallback.ip})")
            return best_fallback
        
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
    # Filter: capture all IP traffic, but EXCLUDE port 5000 (dashboard itself) to reduce noise.
    # Exclude port 53 (DNS) if we want to focus on data, but let's keep it and just exclude 5000.
    bpffilter = "ip and not port 5000"
    
    # If no specific interface found, use None to sniff on all active interfaces
    if iface is None:
        print("[PacketCapture] No specific active interface found. Sniffing on ALL interfaces.")
    else:
        print(f"[PacketCapture] Starting Scapy capture on: {iface.description if hasattr(iface, 'description') else iface}")

    try:
        # Optimization: use store=False to avoid memory bloat
        # count=0 means infinity
        sniff(filter=bpffilter, prn=handle_packet, store=False, iface=iface, count=0)
    except Exception as e:
        print(f"[PacketCapture] Scapy capture error: {e}")
        # Try one more time with iface=None as ultimate fallback
        if iface is not None:
            try:
                print("[PacketCapture] Retrying on ALL interfaces...")
                sniff(filter=bpffilter, prn=handle_packet, store=False, iface=None, count=0)
            except: pass


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
                    local_ip = conn.laddr.ip if conn.laddr else "127.0.0.1"
                    proc_name = "SYSTEM"
                    try:
                        if pid:
                            proc_name = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    # Update global process map for Scapy correlation
                    update_process_map({
                        'protocol': protocol,
                        'src_ip': local_ip,
                        'src_port': local_port,
                        'dst_ip': remote_ip,
                        'dst_port': remote_port,
                        'process': proc_name,
                        'pid': pid
                    })

                    meta = {
                        "timestamp": time.time(),
                        "datetime": datetime.now().isoformat(),
                        "src_ip": local_ip,
                        "dst_ip": remote_ip,
                        "ip_type": ip_type,
                        "protocol": protocol,
                        "src_port": local_port,
                        "dst_port": remote_port,
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
    while True:
        try:
            connection_monitor.scan_connections()
        except Exception:
            pass
        time.sleep(2)


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
