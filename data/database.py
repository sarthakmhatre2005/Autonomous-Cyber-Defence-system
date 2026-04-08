import sqlite3
import time
import json
import logging
from datetime import datetime
import os
import threading
import queue

# ─── Async Database Logger ──────────────────────────────────────────────────────

class AsyncDatabaseLogger:
    """ Offloads database writes to a background thread to prevent blocking monitoring scripts. """
    def __init__(self, db_file):
        self.db_file = db_file
        self.queue = queue.Queue(maxsize=10000)
        self.fallback_log = os.path.join(os.path.dirname(db_file), 'telemetry_fallback.log')
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()

    def _worker_loop(self):
        while True:
            try:
                conn = sqlite3.connect(self.db_file, timeout=30)
                conn.execute("PRAGMA journal_mode=WAL") # Better concurrency
                while True:
                    item = self.queue.get()
                    if item is None: break
                    
                    func, args, kwargs = item
                    retry_count = 0
                    success = False
                    
                    while retry_count < 3 and not success:
                        try:
                            func(conn, *args, **kwargs)
                            conn.commit()
                            success = True
                        except sqlite3.OperationalError as e:
                            if "locked" in str(e).lower():
                                retry_count += 1
                                time.sleep(0.1 * retry_count)
                            else:
                                self._fallback_write(func.__name__, args, kwargs, str(e))
                                break
                        except Exception as e:
                            self._fallback_write(func.__name__, args, kwargs, str(e))
                            break
                    
                    self.queue.task_done()
                conn.close()
                break # Exit loop if shutdown signal received
            except Exception as e:
                print(f"[AsyncDBLogger] Fatal Connection Error: {e}")
                time.sleep(5)

    def _fallback_write(self, func_name, args, kwargs, error):
        """ Write to a text file if the database fails. """
        try:
            with open(self.fallback_log, 'a') as f:
                entry = {
                    "timestamp": datetime.now().isoformat(),
                    "func": func_name,
                    "args": [str(a) for a in args],
                    "kwargs": {k: str(v) for k, v in kwargs.items()},
                    "error": error
                }
                f.write(json.dumps(entry) + "\n")
        except:
            pass # Last resort failure

    def submit(self, func, *args, **kwargs):
        try:
            self.queue.put_nowait((func, args, kwargs))
        except queue.Full:
            # Fallback directly if queue is full to prevent lockup
            self._fallback_write(func.__name__, args, kwargs, "Queue Full")

# Ensure database path resolves correctly from any working directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, 'cyber_defense.db')

# Global logger instance
db_logger = AsyncDatabaseLogger(DB_FILE)

# ─── Whitelist Cache ────────────────────────────────────────────────────────────

class WhitelistCache:
    """ Maintains an in-memory set of whitelisted entities for O(1) checks. """
    def __init__(self):
        self._whitelist = set() 
        self._lock = threading.Lock()
        self.refresh()

    def refresh(self):
        if not os.path.exists(DB_FILE): return
        try:
            conn = sqlite3.connect(DB_FILE, timeout=10)
            c = conn.cursor()
            c.execute("CREATE TABLE IF NOT EXISTS whitelist (id INTEGER PRIMARY KEY AUTOINCREMENT, entity_type TEXT, entity_value TEXT, timestamp TEXT)")
            c.execute("SELECT entity_type, entity_value FROM whitelist")
            rows = c.fetchall()
            with self._lock:
                self._whitelist = set(rows)
            conn.close()
        except:
            pass

    def is_whitelisted(self, entity_type, entity_value):
        with self._lock:
            return (entity_type, entity_value) in self._whitelist

    def add(self, entity_type, entity_value):
        with self._lock:
            self._whitelist.add((entity_type, entity_value))

    def remove(self, entity_type, entity_value):
        with self._lock:
            self._whitelist.discard((entity_type, entity_value))

whitelist_cache = WhitelistCache()

# ─── Functions ───────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    c = conn.cursor()

    # Optimized events table
    c.execute('''CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    src_ip TEXT,
                    dest_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    payload_size INTEGER,
                    severity TEXT,
                    anomaly_score REAL DEFAULT 0.0,
                    threat_score INTEGER DEFAULT 0,
                    active_window TEXT,
                    details TEXT
                )''')

    c.execute('''CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    entity_type TEXT,
                    entity_value TEXT,
                    action_type TEXT,
                    reason TEXT
                )''')

    c.execute('''CREATE TABLE IF NOT EXISTS blocked_entities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT,
                    entity_value TEXT,
                    timestamp TEXT,
                    reason TEXT,
                    active INTEGER DEFAULT 1
                )''')
    # Backward-compatible enrichments for unified threat object storage.
    for col, typ in (
        ("ip", "TEXT"),
        ("domain", "TEXT"),
        ("process", "TEXT"),
        ("source_type", "TEXT"),
        ("risk", "INTEGER DEFAULT 0"),
        ("threat_level", "TEXT"),
        ("attack_type", "TEXT"),
        ("action", "TEXT"),
    ):
        try:
            c.execute(f"ALTER TABLE blocked_entities ADD COLUMN {col} {typ}")
        except Exception:
            pass

    c.execute('''CREATE TABLE IF NOT EXISTS whitelist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT,
                    entity_value TEXT,
                    timestamp TEXT
                )''')

    c.execute('''CREATE TABLE IF NOT EXISTS threat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    source_ip TEXT,
                    ip_type TEXT,
                    event_type TEXT,
                    score_delta INTEGER,
                    cumulative_score INTEGER,
                    severity TEXT,
                    detail TEXT
                )''')

    c.execute('''CREATE TABLE IF NOT EXISTS visited_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    domain TEXT,
                    requesting_ip TEXT,
                    threat_score REAL,
                    process TEXT
                )''')

    c.execute('''CREATE TABLE IF NOT EXISTS honeypot_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    source_ip TEXT,
                    source_port INTEGER,
                    honeypot_port INTEGER,
                    data TEXT
                )''')

    # ─── Persistent IP Memory (hybrid RAM + DB) ─────────────────────────────
    c.execute('''CREATE TABLE IF NOT EXISTS ip_memory (
                    ip TEXT PRIMARY KEY,
                    total_flags INTEGER DEFAULT 0,
                    past_blocks INTEGER DEFAULT 0,
                    last_seen REAL DEFAULT 0.0
                )''')

    conn.commit()
    conn.close()


def load_ip_memory():
    """
    Load persistent IP behavior memory into RAM on startup.
    Returns: dict[ip] = {"total_flags": int, "past_blocks": int, "last_seen": float}
    """
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT ip, total_flags, past_blocks, last_seen FROM ip_memory")
        rows = c.fetchall()
        conn.close()
        out = {}
        for r in rows:
            ip = r["ip"]
            out[ip] = {
                "total_flags": int(r["total_flags"] or 0),
                "past_blocks": int(r["past_blocks"] or 0),
                "last_seen": float(r["last_seen"] or 0.0),
            }
        return out
    except Exception:
        return {}


def save_ip_memory(ip, data):
    """
    Save/Upsert IP memory to DB asynchronously.
    data expected keys: total_flags, past_blocks, last_seen
    """
    def _write(conn, ip, total_flags, past_blocks, last_seen):
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO ip_memory (ip, total_flags, past_blocks, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                total_flags=excluded.total_flags,
                past_blocks=excluded.past_blocks,
                last_seen=excluded.last_seen
            """,
            (ip, int(total_flags), int(past_blocks), float(last_seen)),
        )

    try:
        total_flags = data.get("total_flags", 0)
        past_blocks = data.get("past_blocks", 0)
        last_seen = data.get("last_seen", time.time())
        db_logger.submit(_write, ip, total_flags, past_blocks, last_seen)
    except Exception:
        # Never crash the detection pipeline due to persistence errors.
        pass

def log_event(src_ip="0.0.0.0", dest_ip="0.0.0.0", src_port=0, dst_port=0, protocol="UNKNOWN", 
              payload_size=0, severity="LOW", anomaly_score=0.0, active_window="N/A", details=None, threat_score=0):
    """ Fixed and robust logging function. Handles flexible arguments. """
    def _write(conn, src_ip, dest_ip, src_port, dst_port, protocol, payload_size, severity, anomaly_score, active_window, details, threat_score):
        c = conn.cursor()
        detail_json = json.dumps(details) if details else "{}"
        c.execute(
            """INSERT INTO events (timestamp, src_ip, dest_ip, src_port, dst_port, protocol, payload_size, 
                                 severity, anomaly_score, active_window, details, threat_score) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (datetime.now().isoformat(), src_ip, dest_ip, src_port, dst_port, protocol, payload_size, 
             severity, anomaly_score, active_window, detail_json, threat_score)
        )
    
    db_logger.submit(_write, src_ip, dest_ip, src_port, dst_port, protocol, payload_size, 
                     severity, anomaly_score, active_window, details, threat_score)

def log_action(entity_type, entity_value, action_type, reason):
    def _write(conn, entity_type, entity_value, action_type, reason):
        c = conn.cursor()
        c.execute(
            "INSERT INTO actions (timestamp, entity_type, entity_value, action_type, reason) VALUES (?, ?, ?, ?, ?)",
            (datetime.now().isoformat(), entity_type, entity_value, action_type, reason)
        )
    db_logger.submit(_write, entity_type, entity_value, action_type, reason)

def _blocked_entity_insert(conn, entity_type, entity_value, reason, threat_object):
    """Ensure an active blocked_entities row exists. Idempotent if already active."""
    c = conn.cursor()
    c.execute(
        "SELECT id FROM blocked_entities WHERE entity_type=? AND entity_value=? AND active=1",
        (entity_type, entity_value),
    )
    if c.fetchone():
        return
    threat_object = threat_object or {}
    ip = str(threat_object.get("ip") or (entity_value if entity_type == "IP" else "unknown"))
    domain = str(threat_object.get("domain") or ("unknown" if entity_type == "IP" else entity_value))
    process = str(threat_object.get("process") or "unknown process")
    source_type = str(threat_object.get("source_type") or "EXTERNAL_SOURCE")
    risk = int(threat_object.get("risk") or 0)
    threat_level = str(threat_object.get("threat_level") or "SUSPICIOUS")
    attack_type = str(threat_object.get("attack_type") or "SUSPICIOUS_BEHAVIOR")
    action = str(threat_object.get("action") or "BLOCK")
    c.execute(
        """INSERT INTO blocked_entities
           (entity_type, entity_value, timestamp, reason, active, ip, domain, process, source_type, risk, threat_level, attack_type, action)
           VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            entity_type,
            entity_value,
            datetime.now().isoformat(),
            reason,
            ip,
            domain,
            process,
            source_type,
            risk,
            threat_level,
            attack_type,
            action,
        ),
    )


def block_entity_db(entity_type, entity_value, reason, threat_object=None):
    def _write(conn, entity_type, entity_value, reason, threat_object):
        _blocked_entity_insert(conn, entity_type, entity_value, reason, threat_object)

    db_logger.submit(_write, entity_type, entity_value, reason, threat_object)


def block_entity_db_sync(entity_type, entity_value, reason, threat_object=None):
    """Same as block_entity_db but commits immediately so UI/API see the row right away."""
    conn = sqlite3.connect(DB_FILE, timeout=10)
    try:
        _blocked_entity_insert(conn, entity_type, entity_value, reason, threat_object)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def unblock_entity_db(entity_type, entity_value):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        c = conn.cursor()
        c.execute("UPDATE blocked_entities SET active=0 WHERE entity_type=? AND entity_value=?", (entity_type, entity_value))
        conn.commit()
        conn.close()
    except: pass

def get_recent_events(limit=50):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except: return []

def get_recent_actions(limit=50):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except: return []

def get_stats():
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM events")
        total_requests = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM events WHERE severity != 'LOW'")
        anomalies = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM blocked_entities WHERE active=1")
        blocked = c.fetchone()[0]
        
        # Threat engine stats
        try:
            from core.threat_engine import threat_engine
            te_stats = threat_engine.get_stats()
        except: te_stats = {}

        conn.close()
        return {
            "total_requests": total_requests, 
            "anomalies": anomalies, 
            "blocked": blocked,
            "external_ips_tracked": te_stats.get("total_ips_tracked", 0),
            "high_threat_ips": te_stats.get("high_threat_ips", 0),
            "suspicious_ips": te_stats.get("suspicious_ips", 0),
        }
    except: return {"total_requests": 0, "anomalies": 0, "blocked": 0}

def get_blocked_entities(limit=50):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM blocked_entities WHERE active=1 ORDER BY id DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        conn.close()
        out = []
        for row in rows:
            d = dict(row)
            # Return full object shape with safe defaults.
            d["ip"] = str(d.get("ip") or (d.get("entity_value") if d.get("entity_type") == "IP" else "unknown"))
            d["domain"] = str(d.get("domain") or ("unknown" if d.get("entity_type") == "IP" else (d.get("entity_value") or "unknown")))
            d["process"] = str(d.get("process") or "unknown process")
            d["source_type"] = str(d.get("source_type") or "EXTERNAL_SOURCE")
            d["risk"] = int(d.get("risk") or 0)
            d["threat_level"] = str(d.get("threat_level") or "SUSPICIOUS")
            d["attack_type"] = str(d.get("attack_type") or "SUSPICIOUS_BEHAVIOR")
            d["action"] = str(d.get("action") or "BLOCK")
            d["reason"] = str(d.get("reason") or "No reason provided")
            out.append(d)
        return out
    except: return []

def get_top_ips(limit=10):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        c = conn.cursor()
        c.execute("SELECT src_ip, COUNT(*) as count FROM events GROUP BY src_ip ORDER BY count DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        conn.close()
        return [{"ip": row[0], "count": row[1]} for row in rows]
    except: return []

def log_dns_query(domain, requesting_ip, threat_score, process="UNKNOWN"):
    def _write(conn, domain, requesting_ip, threat_score, process):
        c = conn.cursor()
        c.execute(
            "INSERT INTO visited_domains (timestamp, domain, requesting_ip, threat_score, process) VALUES (?, ?, ?, ?, ?)",
            (datetime.now().isoformat(), domain, requesting_ip, threat_score, process)
        )
    db_logger.submit(_write, domain, requesting_ip, threat_score, process)

def get_dns_history(limit=100):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM visited_domains ORDER BY id DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except: return []

def log_honeypot_event(ip, port, honeypot_port, data):
    def _write(conn, ip, port, honeypot_port, data):
        c = conn.cursor()
        c.execute(
            "INSERT INTO honeypot_events (timestamp, source_ip, source_port, honeypot_port, data) VALUES (?, ?, ?, ?, ?)",
            (datetime.now().isoformat(), ip, port, honeypot_port, data)
        )
    db_logger.submit(_write, ip, port, honeypot_port, data)

def get_recent_honeypot_events(limit=50):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM honeypot_events ORDER BY id DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except: return []

def add_to_whitelist(entity_type, entity_value):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        c = conn.cursor()
        c.execute("SELECT id FROM whitelist WHERE entity_type=? AND entity_value=?", (entity_type, entity_value))
        if c.fetchone():
            conn.close()
            return False
        c.execute("INSERT INTO whitelist (entity_type, entity_value, timestamp) VALUES (?, ?, ?)",
                  (entity_type, entity_value, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        whitelist_cache.add(entity_type, entity_value)
        return True
    except: return False

def remove_from_whitelist(entity_type, entity_value):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        c = conn.cursor()
        c.execute("DELETE FROM whitelist WHERE entity_type=? AND entity_value=?", (entity_type, entity_value))
        conn.commit()
        conn.close()
        whitelist_cache.remove(entity_type, entity_value)
        return True
    except: return False

def get_whitelist():
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM whitelist ORDER BY id DESC")
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except: return []

def is_whitelisted(entity_type, entity_value):
    return whitelist_cache.is_whitelisted(entity_type, entity_value)
