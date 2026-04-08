import psutil
import time
import threading
import ctypes
import sqlite3
from ctypes import wintypes
from data.database import log_event, block_entity_db

from core.threat_engine import threat_engine

# Windows API setup for active window title
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

def get_active_window_info():
    """Returns (process_name, window_title)"""
    hWnd = user32.GetForegroundWindow()
    
    # Get Title
    length = user32.GetWindowTextLengthW(hWnd)
    if length == 0:
        title = "System / Idle"
    else:
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hWnd, buf, length + 1)
        title = buf.value if buf.value else "System / Idle"
    
    # Get Process Name
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hWnd, ctypes.byref(pid))
    try:
        proc_name = psutil.Process(pid.value).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        proc_name = "System"

    # Clean Title - DISABLED to provide full visibility as requested
    # for noise in [" - Google Chrome", " - Microsoft Edge", " - Visual Studio Code"]:
    #     if noise in title: title = title.replace(noise, "")

    return proc_name, title

# Whitelist of common safe processes
SAFE_PROCESSES = ["system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "python.exe", "cmd.exe", "conhost.exe"]

# Suspicious parent-child relationships
SUSPICIOUS_SPAWNS = {
    "iis.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "bitsadmin.exe"],
    "w3wp.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "bitsadmin.exe"],
    "sqlservr.exe": ["cmd.exe", "powershell.exe"],
    "httpd.exe": ["cmd.exe", "powershell.exe", "sh", "bash"],
    "nginx.exe": ["cmd.exe", "powershell.exe", "sh", "bash"],
}

def get_process_score(proc):
    """
    Calculates threat score (0-10) for a process.
    """
    score = 0
    try:
        # 1. Resource usage
        cpu = proc.cpu_percent(interval=None) # Non-blocking
        mem = proc.memory_info().rss / (1024 * 1024) # MB
        
        if cpu > 85:
            score += 3
        if mem > 1000: # 1GB
            score += 2
        
        # 2. Suspicious lineage (Parent-Child)
        try:
            name = proc.name().lower()
            parent = proc.parent()
            if parent:
                parent_name = parent.name().lower()
                if parent_name in SUSPICIOUS_SPAWNS:
                    if name in SUSPICIOUS_SPAWNS[parent_name]:
                        score += 7 # HIGH penalty for suspicious spawns
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # 3. Known Safe Processes
        name = proc.name().lower()
        if name not in [p.lower() for p in SAFE_PROCESSES]:
            score += 1
        
        # 4. Network Activity
        try:
            connections = proc.connections()
            if len(connections) > 20: 
                score += 2
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return score

def track_process_connections(pid, proc_name):
    """Proactively check for connections on a specific process."""
    time.sleep(2)
    try:
        proc = psutil.Process(pid)
        connections = proc.connections(kind='inet')
        for conn in connections:
            if conn.raddr:
                remote_ip = conn.raddr.ip
                # Get current threat level for this IP
                state = threat_engine.get_state(remote_ip)
                score = state.get('score', 0)
                severity = state.get('severity', 'LOW')
                log_event(
                    src_ip=remote_ip,
                    dest_ip="INTERNAL",
                    protocol="TRACK",
                    severity=severity,
                    anomaly_score=score / 10.0,
                    active_window=proc_name,
                    details={"pid": pid, "app": proc_name, "type": "Proactive Track"}
                )
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

def monitor_processes():
    """
    Main background loop for Host monitoring.
    """
    print("[*] Starting Host Behavior Monitor...")
    known_pids = set(p.pid for p in psutil.process_iter(['pid']))
    last_process_scan = 0
    last_scan = 0
    last_window_title = ""
    # Cache for scores to avoid re-calculating too often
    process_scores = {}

    while True:
        try:
            # 1. Active Window Tracking
            proc_name, title = get_active_window_info()
            if title != last_window_title:
                log_event(
                    src_ip="127.0.0.1",
                    dest_ip="LOCAL",
                    protocol="WINDOW_SWITCH",
                    severity="LOW",
                    anomaly_score=0.0,
                    active_window=title,
                    details={"app": proc_name, "title": title, "type": "Activity"}
                )
                last_window_title = title
                
            # 2. New Process Detection (Every 1s)
            current_pids = set()
            should_scan_scores = (time.time() - last_process_scan > 5)
            
            for proc in psutil.process_iter(['pid', 'name']):
                pid = proc.pid
                current_pids.add(pid)
                
                # Detect New Processes
                if pid not in known_pids:
                    known_pids.add(pid)
                    try:
                        name = proc.name()
                        log_event(
                            src_ip="127.0.0.1", dest_ip="LOCAL", protocol="SYSTEM",
                            severity="LOW", anomaly_score=0.0, active_window=name,
                            # Include app name so the dashboard can render "chrome.exe started"
                            details={"pid": pid, "app": name, "type": "New Process", "event": f"{name} started"}
                        )
                        threading.Thread(target=track_process_connections, args=(pid, name), daemon=True).start()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                # 3. Malicious Activity Detection (Every 5s to save CPU)
                if should_scan_scores:
                    try:
                        score = get_process_score(proc)
                        if score >= 6:
                            p_name = proc.name()
                            from data.database import is_whitelisted
                            if is_whitelisted("PROCESS", p_name): continue
                                
                            log_event(
                                src_ip="127.0.0.1", dest_ip="LOCAL", protocol="SYSTEM",
                                severity="HIGH", anomaly_score=score/10.0, active_window=p_name,
                                # Include app name for clearer event rendering
                                details={"pid": pid, "app": p_name, "score": score, "type": "Process Kill", "event": f"{p_name} suspicious activity detected"},
                                threat_score=int(score)
                            )
                            proc.terminate()
                            block_entity_db("PROCESS", p_name, f"Malicious behavior (score {score})")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            
            if should_scan_scores:
                last_process_scan = time.time()
            
            known_pids = known_pids & current_pids
            
            # 4. Background System Metadata (Scan visible apps every 30s)
            if time.time() - last_scan > 30:
                last_scan = time.time()
                # (Optional logic for background enumeration)

        except Exception as e:
            print(f"Monitor Loop Error: {e}")
        time.sleep(1)

def start_process_monitor():
    t = threading.Thread(target=monitor_processes, daemon=True)
    t.start()

def get_active_window_title():
    hWnd = user32.GetForegroundWindow()
    length = user32.GetWindowTextLengthW(hWnd)
    if length == 0: return "Unknown"
    buf = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(hWnd, buf, length + 1)
    return buf.value if buf.value else "Unknown"
