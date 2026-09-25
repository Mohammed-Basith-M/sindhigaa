"""
CyberShield SQLite Database Persistence Layer
Stores analysis dossiers, historical audit records, and dashboard metrics.
"""

import sqlite3
import json
import os
import time
from typing import List, Dict, Any, Optional
try:
    from ..config import DATABASE_PATH
except (ImportError, ValueError):
    from config import DATABASE_PATH

def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initializes tables for analyses, events, and telemetry cache.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            analysis_id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            created_at REAL NOT NULL,
            status TEXT NOT NULL,
            is_demo INTEGER NOT NULL DEFAULT 0,
            threat TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL,
            total_packets INTEGER NOT NULL,
            total_bytes INTEGER NOT NULL,
            total_flows INTEGER NOT NULL,
            duration_seconds REAL NOT NULL,
            data_json TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_analysis(analysis_data: Dict[str, Any]) -> str:
    """
    Persists complete analysis record to SQLite.
    """
    init_db()
    conn = get_db()
    cursor = conn.cursor()
    
    aid = analysis_data["analysis_id"]
    filename = analysis_data.get("filename", "unknown.pcap")
    file_size = analysis_data.get("file_size", 0)
    created_at = analysis_data.get("created_at", time.time())
    status = analysis_data.get("status", "completed")
    is_demo = 1 if analysis_data.get("is_demo") else 0
    threat = analysis_data.get("threat", "Benign")
    severity = analysis_data.get("severity", "BENIGN")
    confidence = analysis_data.get("confidence")
    
    summary = analysis_data.get("summary", {})
    total_packets = summary.get("total_packets", 0)
    total_bytes = summary.get("total_bytes", 0)
    total_flows = summary.get("total_flows", 0)
    duration_seconds = summary.get("duration_seconds", 0.0)
    
    data_json = json.dumps(analysis_data)
    
    cursor.execute("""
        INSERT OR REPLACE INTO analyses (
            analysis_id, filename, file_size, created_at, status, is_demo,
            threat, severity, confidence, total_packets, total_bytes, total_flows,
            duration_seconds, data_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        aid, filename, file_size, created_at, status, is_demo,
        threat, severity, confidence, total_packets, total_bytes, total_flows,
        duration_seconds, data_json
    ))
    conn.commit()
    conn.close()
    return aid

def get_analysis(analysis_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves a single complete analysis by its ID.
    """
    init_db()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT data_json FROM analyses WHERE analysis_id = ?", (analysis_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return json.loads(row["data_json"])
    return None

def get_history(search: str = "", severity: str = "all", limit: int = 50) -> List[Dict[str, Any]]:
    """
    Retrieves summary audit rows for history listing with optional search & filter.
    """
    init_db()
    conn = get_db()
    cursor = conn.cursor()
    
    query = "SELECT analysis_id, filename, file_size, created_at, status, is_demo, threat, severity, confidence, total_packets, total_bytes, duration_seconds FROM analyses WHERE 1=1"
    params = []
    
    if search:
        query += " AND (filename LIKE ? OR threat LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
        
    if severity and severity.lower() != "all":
        query += " AND UPPER(severity) = ?"
        params.append(severity.upper())
        
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        results.append({
            "analysis_id": r["analysis_id"],
            "filename": r["filename"],
            "file_size": r["file_size"],
            "created_at": r["created_at"],
            "status": r["status"],
            "is_demo": bool(r["is_demo"]),
            "threat": r["threat"],
            "severity": r["severity"],
            "confidence": r["confidence"],
            "total_packets": r["total_packets"],
            "total_bytes": r["total_bytes"],
            "duration_seconds": r["duration_seconds"]
        })
    return results

def delete_analysis(analysis_id: str) -> bool:
    """
    Removes an analysis record from SQLite.
    """
    init_db()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM analyses WHERE analysis_id = ?", (analysis_id,))
    affected = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return affected

def get_dashboard_stats() -> Dict[str, Any]:
    """
    Computes dashboard telemetry summary cards.
    """
    init_db()
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) as total FROM analyses")
    total_analyses = cursor.fetchone()["total"]
    
    cursor.execute("SELECT COUNT(*) as live FROM analyses WHERE is_demo = 0")
    live_pcap_files = cursor.fetchone()["live"]
    
    cursor.execute("SELECT COUNT(*) as threats FROM analyses WHERE threat NOT IN ('Benign', 'Insufficient Evidence')")
    threats_detected = cursor.fetchone()["threats"]
    
    cursor.execute("SELECT COUNT(*) as high_risk FROM analyses WHERE severity IN ('HIGH', 'CRITICAL')")
    high_risk_events = cursor.fetchone()["high_risk"]
    
    conn.close()
    return {
        "total_analyses": total_analyses,
        "pcap_files": live_pcap_files,
        "threats_detected": threats_detected,
        "high_risk_events": high_risk_events
    }
