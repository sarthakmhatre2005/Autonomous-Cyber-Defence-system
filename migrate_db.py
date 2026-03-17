import sqlite3
import os

DB_FILE = r'd:\Autonomous Cyber Defence system\data\cyber_defense.db'

def migrate():
    if not os.path.exists(DB_FILE):
        print("Database not found.")
        return

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Check current columns in events
    c.execute("PRAGMA table_info(events)")
    columns = [row[1] for row in c.fetchall()]
    print(f"Current columns: {columns}")
    
    needed_columns = {
        "dest_ip": "TEXT",
        "source_port": "INTEGER",
        "dest_port": "INTEGER",
        "protocol": "TEXT",
        "payload_size": "INTEGER",
        "anomaly_score": "REAL",
        "active_window": "TEXT"
    }
    
    for col, type in needed_columns.items():
        if col not in columns:
            print(f"Adding column {col}...")
            try:
                c.execute(f"ALTER TABLE events ADD COLUMN {col} {type}")
            except Exception as e:
                print(f"Error adding {col}: {e}")
                
    conn.commit()
    conn.close()
    print("Migration complete.")

if __name__ == "__main__":
    migrate()
