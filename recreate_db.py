import sqlite3
import os
import json

DB_FILE = r'd:\Autonomous Cyber Defence system\data\cyber_defense.db'

def migrate():
    if not os.path.exists(DB_FILE):
        print("Database not found. Initializing new database...")
        from data.database import init_db
        init_db()
        return

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # 1. Backup existing data from events if it exists
    try:
        c.execute("SELECT * FROM events LIMIT 1")
        has_events = True
    except sqlite3.OperationalError:
        has_events = False

    if has_events:
        print("Backing up existing events...")
        c.execute("PRAGMA table_info(events)")
        existing_cols = [row[1] for row in c.fetchall()]
        
        c.execute("SELECT * FROM events")
        old_data = c.fetchall()
        
        # 2. Drop old table
        c.execute("DROP TABLE events")
    else:
        old_data = []
        existing_cols = []

    # 3. Create new table with correct schema
    print("Creating events table with new schema...")
    c.execute('''CREATE TABLE events (
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

    # 4. Restore data if possible (mapping old columns to new ones)
    if old_data:
        print(f"Restoring {len(old_data)} records...")
        col_map = {
            "source_ip": "src_ip",
            "dest_ip": "dest_ip",
            "source_port": "src_port",
            "dest_port": "dst_port",
            "protocol": "protocol",
            "payload_size": "payload_size",
            "severity": "severity",
            "anomaly_score": "anomaly_score",
            "active_window": "active_window",
            "details": "details",
            "timestamp": "timestamp"
        }
        
        # Build insert query
        for row in old_data:
            record = {}
            for i, col in enumerate(existing_cols):
                new_col = col_map.get(col, col)
                record[new_col] = row[i]
            
            # Ensure safe defaults for new columns if they didn't exist
            keys = record.keys()
            placeholders = ", ".join(["?" for _ in keys])
            cols_str = ", ".join(keys)
            
            try:
                c.execute(f"INSERT INTO events ({cols_str}) VALUES ({placeholders})", list(record.values()))
            except Exception as e:
                print(f"Skipping record due to error: {e}")

    conn.commit()
    conn.close()
    print("Migration successful.")

if __name__ == "__main__":
    migrate()
