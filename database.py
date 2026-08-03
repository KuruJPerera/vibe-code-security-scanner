import os
import sqlite3
from datetime import datetime, timezone

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, "security_scanner.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_url TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                total_findings INTEGER NOT NULL,
                vulnerability_rate REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                check_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                file_path TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                detail TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
            """
        )
        conn.commit()


def save_scan(repo_url, total_findings, vulnerability_rate):
    timestamp = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans (repo_url, timestamp, total_findings, vulnerability_rate)
            VALUES (?, ?, ?, ?)
            """,
            (repo_url, timestamp, total_findings, vulnerability_rate),
        )
        conn.commit()
        return cursor.lastrowid


def save_finding(scan_id, check_name, severity, file_path, line_number, detail):
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO findings (scan_id, check_name, severity, file_path, line_number, detail)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (scan_id, check_name, severity, file_path, line_number, detail),
        )
        conn.commit()


def get_all_scans():
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, repo_url, timestamp, total_findings, vulnerability_rate FROM scans ORDER BY timestamp DESC"
        ).fetchall()
        return [dict(row) for row in rows]


def get_findings_by_scan(scan_id):
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, scan_id, check_name, severity, file_path, line_number, detail
            FROM findings
            WHERE scan_id = ?
            ORDER BY id ASC
            """,
            (scan_id,),
        ).fetchall()
        return [dict(row) for row in rows]
