"""
Database manager — SQLite for storing scan history and vulnerabilities.
"""
import sqlite3
import os
from datetime import datetime
from typing import List, Optional, Dict
from app.models.schemas import Vulnerability


DB_FILE = "moku_analyzer.db"


class Database:
    def __init__(self, db_file: str = DB_FILE):
        self.db_file = db_file
        self._init_db()

    def _init_db(self):
        """Create tables if they don't exist."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                adapter TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                total_vulns INTEGER,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0
            )
        """)

        # Vulnerabilities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                confidence REAL,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        """)

        conn.commit()
        conn.close()

    def save_scan(self, scan_id: str, url: str, adapter: str, vulns: List[Vulnerability]):
        """Save scan and vulnerabilities to database."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Count by severity
        severity_counts = {
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
        }
        for v in vulns:
            sev = v.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Insert scan
        cursor.execute("""
            INSERT INTO scans 
            (id, url, adapter, total_vulns, critical_count, high_count, medium_count, low_count, info_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id, url, adapter, len(vulns),
            severity_counts['critical'],
            severity_counts['high'],
            severity_counts['medium'],
            severity_counts['low'],
            severity_counts['info']
        ))

        # Insert vulnerabilities
        for v in vulns:
            confidence = v.meta.get('confidence', 0.0) if v.meta else 0.0
            cursor.execute("""
                INSERT INTO vulnerabilities
                (scan_id, type, severity, description, evidence, confidence)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (scan_id, v.vuln_type, v.severity, v.description, v.evidence or '', confidence))

        conn.commit()
        conn.close()

    def get_history(self) -> List[Dict]:
        """Get all past scans."""
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, url, adapter, timestamp, total_vulns, critical_count, high_count, medium_count
            FROM scans
            ORDER BY timestamp DESC
        """)
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows

    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Get specific scan details."""
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_vulnerabilities(self, scan_id: str) -> List[Dict]:
        """Get all vulnerabilities for a scan."""
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity DESC", (scan_id,))
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows

    def get_scan_with_vulns(self, scan_id: str) -> tuple:
        """Get scan and all its vulnerabilities."""
        scan = self.get_scan(scan_id)
        vulns = self.get_vulnerabilities(scan_id)
        return scan, vulns

    def export_all_csv(self, filename: str = "all_scans_export.csv") -> str:
        """Export all scans to CSV."""
        import csv
        scans = self.get_history()
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Scan ID', 'URL', 'Scanner', 'Date', 'Total Issues', 'Critical', 'High', 'Medium'])
            for scan in scans:
                writer.writerow([
                    scan['id'],
                    scan['url'],
                    scan['adapter'],
                    scan['timestamp'],
                    scan['total_vulns'],
                    scan['critical_count'],
                    scan['high_count'],
                    scan['medium_count']
                ])
        return filename


# Shared instance
db = Database()