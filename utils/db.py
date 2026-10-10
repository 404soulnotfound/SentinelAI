"""
utils/db.py
------------
Database helper functions for reading incident reports.
"""
import sqlite3
import pandas as pd
import os

DB_PATH = "reports/alerts.db"

def get_all_incidents() -> pd.DataFrame:
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql("SELECT * FROM incidents ORDER BY created_at DESC", conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()

def get_incident_by_id(alert_id: str) -> dict:
    if not os.path.exists(DB_PATH):
        return {}
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql(
            "SELECT * FROM incidents WHERE alert_id = ?",
            conn, params=(alert_id,)
        )
        conn.close()
        return df.iloc[0].to_dict() if len(df) > 0 else {}
    except Exception:
        return {}

def count_by_severity() -> dict:
    df = get_all_incidents()
    if df.empty:
        return {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    return df["severity"].value_counts().to_dict()
