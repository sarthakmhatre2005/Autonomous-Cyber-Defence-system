import sqlite3
import os

db_path = r"d:\Autonomous Cyber Defence system\data\cyber_defense.db"
if not os.path.exists(db_path):
    print(f"DB not found at {db_path}")
    exit(1)

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
c = conn.cursor()

c.execute("SELECT count(*) FROM events")
count = c.fetchone()[0]
print(f"Total events in database: {count}")

print("\nLast 5 Network Events:")
c.execute("SELECT src_ip, dest_ip, protocol, threat_score, severity FROM events ORDER BY id DESC LIMIT 5")
rows = c.fetchall()
for row in rows:
    print(dict(row))

c.execute("SELECT count(*) FROM blocked_entities WHERE active=1")
blocked_count = c.fetchone()[0]
print(f"\nActive blocked entities: {blocked_count}")

print("\nLast 5 Blocks:")
c.execute("SELECT entity_type, entity_value, reason FROM blocked_entities WHERE active=1 ORDER BY id DESC LIMIT 5")
rows = c.fetchall()
for row in rows:
    print(dict(row))

print("\nLast 5 DNS Queries:")
c.execute("SELECT domain, requesting_ip, threat_score FROM visited_domains ORDER BY id DESC LIMIT 5")
rows = c.fetchall()
for row in rows:
    print(dict(row))

conn.close()
