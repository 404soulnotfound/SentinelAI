"""
data/feature_engineer.py
-------------------------
Converts raw network logs into ML features.

Key idea: raw logs are individual connection records.
Attacks span MULTIPLE connections over time.
We aggregate into 1-minute rolling windows per source IP
to capture the patterns that reveal attack behaviour.
"""

import pandas as pd
import numpy as np
from datetime import datetime


FEATURE_COLS = [
    "bytes_sent_sum",
    "bytes_recv_sum",
    "bytes_ratio",
    "packets_sum",
    "unique_dst_ports",
    "unique_dst_ips",
    "failed_conn_rate",
    "conn_rate",
    "avg_duration",
    "bytes_per_packet",
]


def parse_logs(df: pd.DataFrame) -> pd.DataFrame:
    """Clean and type-cast raw log dataframe."""
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["bytes_sent"] = pd.to_numeric(df["bytes_sent"], errors="coerce").fillna(0)
    df["bytes_recv"] = pd.to_numeric(df["bytes_recv"], errors="coerce").fillna(0)
    df["packets"]    = pd.to_numeric(df["packets"],    errors="coerce").fillna(1)
    df["duration"]   = pd.to_numeric(df["duration"],   errors="coerce").fillna(0.1)
    df["success"]    = pd.to_numeric(df["success"],    errors="coerce").fillna(0)
    df["dst_port"]   = pd.to_numeric(df["dst_port"],   errors="coerce").fillna(0)
    return df.sort_values("timestamp").reset_index(drop=True)


def engineer_features(df: pd.DataFrame, window: str = "1min") -> pd.DataFrame:
    """
    Aggregate raw logs into rolling-window features per source IP.

    Each row in the output represents one source IP's behaviour
    in a 1-minute window — the unit the Isolation Forest scores.

    Parameters
    ----------
    df     : Parsed log DataFrame
    window : Rolling window size (default: 1 minute)

    Returns
    -------
    DataFrame with FEATURE_COLS ready for Isolation Forest
    """
    df = parse_logs(df)
    df = df.set_index("timestamp")

    records = []

    for src_ip, group in df.groupby("src_ip"):
        group = group.sort_index()

        # Rolling window aggregation
        roll = group.rolling(window)

        # Build feature rows at each event
        for ts, row in group.iterrows():
            window_data = group[:ts].last(window)

            if len(window_data) == 0:
                continue

            bytes_sent = window_data["bytes_sent"].sum()
            bytes_recv = window_data["bytes_recv"].sum()
            n_events   = len(window_data)
            n_failed   = (window_data["success"] == 0).sum()

            features = {
                "timestamp":        ts,
                "src_ip":           src_ip,
                # Volume features
                "bytes_sent_sum":   bytes_sent,
                "bytes_recv_sum":   bytes_recv,
                "bytes_ratio":      bytes_sent / max(bytes_recv, 1),
                "packets_sum":      window_data["packets"].sum(),
                # Spread features — key for detecting scans and lateral movement
                "unique_dst_ports": window_data["dst_port"].nunique(),
                "unique_dst_ips":   window_data["dst_ip"].nunique(),
                # Failure rate — key for brute force
                "failed_conn_rate": n_failed / max(n_events, 1),
                # Rate features
                "conn_rate":        n_events,
                "avg_duration":     window_data["duration"].mean(),
                "bytes_per_packet": bytes_sent / max(window_data["packets"].sum(), 1),
                # Label (if available — for evaluation only, not used in training)
                "label":            row.get("label", "unknown"),
                "dst_ip":           row.get("dst_ip", ""),
                "dst_port":         row.get("dst_port", 0),
            }
            records.append(features)

    result = pd.DataFrame(records)
    result = result.dropna(subset=FEATURE_COLS)
    print(f"[Features] Engineered {len(result)} feature rows from {df['src_ip'].nunique()} source IPs")
    return result.reset_index(drop=True)


def engineer_features_fast(df: pd.DataFrame) -> pd.DataFrame:
    """
    Faster feature engineering using groupby aggregation.
    Less granular than sliding window but much faster for large datasets.
    Used for training on large historical datasets.
    """
    df = parse_logs(df)

    # Round timestamp to 1-minute buckets
    df["time_bucket"] = df["timestamp"].dt.floor("1min")

    agg = df.groupby(["src_ip", "time_bucket"]).agg(
        bytes_sent_sum  = ("bytes_sent",  "sum"),
        bytes_recv_sum  = ("bytes_recv",  "sum"),
        packets_sum     = ("packets",     "sum"),
        unique_dst_ports= ("dst_port",    "nunique"),
        unique_dst_ips  = ("dst_ip",      "nunique"),
        n_failed        = ("success",     lambda x: (x == 0).sum()),
        n_total         = ("success",     "count"),
        avg_duration    = ("duration",    "mean"),
        label           = ("label",       "first"),
    ).reset_index()

    agg["bytes_ratio"]      = agg["bytes_sent_sum"] / (agg["bytes_recv_sum"] + 1)
    agg["failed_conn_rate"] = agg["n_failed"] / (agg["n_total"] + 1)
    agg["conn_rate"]        = agg["n_total"]
    agg["bytes_per_packet"] = agg["bytes_sent_sum"] / (agg["packets_sum"] + 1)

    print(f"[Features] Fast-engineered {len(agg)} feature rows")
    return agg.reset_index(drop=True)


def get_feature_matrix(df: pd.DataFrame) -> np.ndarray:
    """Extract just the feature columns as a numpy array for sklearn."""
    return df[FEATURE_COLS].fillna(0).values
