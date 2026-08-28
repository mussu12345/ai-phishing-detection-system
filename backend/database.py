import sqlite3
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "phishing.db")


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def init_database():

    conn = get_db_connection()
    cursor = conn.cursor()

    # ========================================================
    # SCANS TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT,
            content TEXT,
            prediction TEXT,
            threat_level TEXT,
            risk_score REAL,
            scan_time TEXT
        )
    """)

    # ========================================================
    # BLOCKED URLS TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            risk_score REAL,
            threat_level TEXT,
            reason TEXT,
            blocked_time TEXT
        )
    """)

    # ========================================================
    # TRUSTED DOMAINS TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS trusted_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            organization TEXT,
            verification_source TEXT,
            verified_at TEXT,
            status TEXT DEFAULT 'VERIFIED'
        )
    """)

    # ========================================================
    # THREAT INTELLIGENCE / IOC TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT UNIQUE,
            indicator_type TEXT,
            threat_type TEXT,
            source TEXT,
            severity TEXT,
            created_at TEXT
        )
    """)

    # ========================================================
    # INITIAL TRUSTED DOMAINS
    # ========================================================

    trusted_domains = [
        ("google.com", "Google", "Manual Verification"),
        ("microsoft.com", "Microsoft", "Manual Verification"),
        ("github.com", "GitHub", "Manual Verification"),
        ("wikipedia.org", "Wikipedia", "Manual Verification")
    ]

    for domain, organization, source in trusted_domains:

        cursor.execute("""
            INSERT OR IGNORE INTO trusted_domains
            (
                domain,
                organization,
                verification_source,
                verified_at,
                status
            )
            VALUES (?, ?, ?, ?, 'VERIFIED')
        """, (
            domain,
            organization,
            source,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

    conn.commit()
    conn.close()


# ============================================================
# GET THREAT INDICATOR
# ============================================================

def get_threat_indicator(indicator):

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM threat_indicators
        WHERE indicator = ?
        LIMIT 1
    """, (indicator,))

    result = cursor.fetchone()

    conn.close()

    if result:
        return dict(result)

    return None


# ============================================================
# ADD THREAT INDICATOR
# ============================================================

def add_threat_indicator(
    indicator,
    indicator_type="domain",
    threat_type="phishing",
    source="Local Database",
    severity="HIGH"
):

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO threat_indicators
        (
            indicator,
            indicator_type,
            threat_type,
            source,
            severity,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        indicator,
        indicator_type,
        threat_type,
        source,
        severity,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


# ============================================================
# SAVE BLOCKED URL
# ============================================================

def save_blocked_url(
    url,
    risk_score,
    threat_level,
    reason
):

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO blocked_urls
        (
            url,
            risk_score,
            threat_level,
            reason,
            blocked_time
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        url,
        float(risk_score or 0),
        threat_level,
        reason,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


# ============================================================
# GET TRUSTED DOMAIN
# ============================================================

def get_trusted_domain(domain):

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM trusted_domains
        WHERE domain = ?
        AND status = 'VERIFIED'
        LIMIT 1
    """, (domain.lower(),))

    result = cursor.fetchone()

    conn.close()

    if result:
        return dict(result)

    return None


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

init_database()


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("============================================")
    print("DATABASE INITIALIZED SUCCESSFULLY")
    print("============================================")
    print("Database:", DATABASE_PATH)
    print("============================================")