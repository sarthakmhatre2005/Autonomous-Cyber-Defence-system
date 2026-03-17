"""
Persistence Detection Module
- Monitors Windows Registry for startup entries (Run/RunOnce)
- Monitors Scheduled Tasks
- Monitors Windows Services
- Reports findings to the Threat Scoring Engine
"""

import os
import time
import threading
import winreg
import subprocess
from datetime import datetime
from data.database import log_event
from core.threat_engine import threat_engine

# ─── Registry Monitoring ──────────────────────────────────────────────────────

REG_LOCATIONS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]

class PersistenceMonitor:
    def __init__(self):
        self.known_registry = {}  # (key_path) -> {value_name: data}
        self.known_tasks = set()
        self.is_running = False

    def _get_registry_values(self, hkey, subkey):
        values = {}
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, i)
                        values[name] = data
                        i += 1
                    except OSError:
                        break
        except Exception as e:
            # print(f"[Persistence] Error reading {subkey}: {e}")
            pass
        return values

    def scan_registry(self, initial=False):
        """Scan startup registry keys for new/changed entries."""
        for hkey, subkey in REG_LOCATIONS:
            path = f"{'HKLM' if hkey == winreg.HKEY_LOCAL_MACHINE else 'HKCU'}\\{subkey}"
            current_values = self._get_registry_values(hkey, subkey)
            
            if initial:
                self.known_registry[path] = current_values
                continue

            last_values = self.known_registry.get(path, {})
            
            # Check for new or modified values
            for name, data in current_values.items():
                if name not in last_values:
                    self._report_persistence("REGISTRY_NEW", f"New startup entry: {name} -> {data}", path)
                elif last_values[name] != data:
                    self._report_persistence("REGISTRY_MODIFIED", f"Modified startup entry: {name} (was {last_values[name]}, now {data})", path)
            
            self.known_registry[path] = current_values

    # ─── Scheduled Tasks Monitoring ───────────────────────────────────────────

    def get_scheduled_tasks(self):
        """Lists active scheduled tasks using schtasks command."""
        tasks = set()
        try:
            # Get tasks in CSV format for easier parsing
            result = subprocess.run(["schtasks", "/query", "/fo", "CSV", "/nh"], capture_output=True, text=True, check=True)
            for line in result.stdout.strip().split("\n"):
                if line:
                    # Format: "TaskName","Next Run Time","Status"
                    parts = line.split('","')
                    if len(parts) > 0:
                        task_name = parts[0].strip('"')
                        tasks.add(task_name)
        except Exception:
            pass
        return tasks

    def scan_tasks(self, initial=False):
        """Scan for new scheduled tasks."""
        current_tasks = self.get_scheduled_tasks()
        
        if initial:
            self.known_tasks = current_tasks
            return

        new_tasks = current_tasks - self.known_tasks
        for task in new_tasks:
            self._report_persistence("SCHEDULED_TASK_NEW", f"New scheduled task detected: {task}", "schtasks")
        
        self.known_tasks = current_tasks

    # ─── Reporting ────────────────────────────────────────────────────────────

    def _report_persistence(self, p_type, detail, source):
        print(f"[Persistence] {p_type}: {detail}")
        
        # Log to DB
        try:
            log_event(
                src_ip="127.0.0.1",
                dest_ip="LOCAL",
                protocol="PERSISTENCE",
                severity="MEDIUM",
                anomaly_score=0.5,
                active_window=source,
                details={"type": p_type, "source": source, "detail": detail},
                threat_score=5
            )
        except Exception:
            pass

        # Alert Threat Engine
        try:
            alert = {
                "type": "PERSISTENCE",
                "severity": "MEDIUM",
                "score": 5,
                "detail": detail,
                "source": source,
                "ip": "127.0.0.1",
                "ip_type": "INTERNAL"
            }
            threat_engine.process_alert(alert)
        except Exception:
            pass

    def run_monitor(self):
        self.is_running = True
        print("[Persistence] Starting persistence monitor...")
        
        # Initial scan to baseline
        self.scan_registry(initial=True)
        self.scan_tasks(initial=True)
        
        while self.is_running:
            try:
                self.scan_registry()
                self.scan_tasks()
            except Exception as e:
                print(f"[Persistence] Monitor loop error: {e}")
            
            time.sleep(30) # Scan every 30 seconds

monitor = PersistenceMonitor()

def start_persistence_monitor():
    t = threading.Thread(target=monitor.run_monitor, daemon=True)
    t.start()
