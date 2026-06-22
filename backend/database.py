import sqlite3

def init_db():
    conn = sqlite3.connect("phishing.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type TEXT,
        content TEXT,
        prediction TEXT,
        threat_level TEXT,
        risk_score INTEGER,
        scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

init_db()