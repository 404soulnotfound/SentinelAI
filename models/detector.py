"""
models/detector.py
-------------------
Isolation Forest anomaly detection engine with SHAP explanations.

Trains on clean baseline traffic, then scores new events
and explains WHY each alert was flagged.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import shap
import joblib
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from data.feature_engineer import FEATURE_COLS, engineer_features_fast, get_feature_matrix

MODEL_DIR = "saved_models"
os.makedirs(MODEL_DIR, exist_ok=True)

# Severity thresholds — tune these based on your network
THRESHOLDS = {
    "Critical": 0.85,
    "High":     0.70,
    "Medium":   0.55,
    "Normal":   0.0,
}

ATTACK_RULES = {
    "port_scan":      lambda r: r.get("unique_dst_ports", 0) > 50,
    "brute_force":    lambda r: r.get("failed_conn_rate", 0) > 0.7 and r.get("conn_rate", 0) > 30,
    "data_exfil":     lambda r: r.get("bytes_ratio", 0) > 50 and r.get("bytes_sent_sum", 0) > 100_000,
    "lateral_movement": lambda r: r.get("unique_dst_ips", 0) > 10,
    "c2_beacon":      lambda r: 0.8 < r.get("bytes_ratio", 0) < 1.2 and r.get("conn_rate", 0) < 5,
    "ddos":           lambda r: r.get("conn_rate", 0) > 200 and r.get("bytes_per_packet", 0) < 100,
}


@dataclass
class AlertEvent:
    """Enriched alert passed to the LangGraph investigation agent."""
    alert_id:          str
    timestamp:         datetime
    src_ip:            str
    dst_ip:            str
    dst_port:          int
    anomaly_score:     float
    severity:          str
    feature_values:    dict
    top_features:      List[tuple]       # [(feature_name, shap_value), ...]
    attack_type_hint:  str
    raw_features:      dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "alert_id":         self.alert_id,
            "timestamp":        self.timestamp.isoformat(),
            "src_ip":           self.src_ip,
            "dst_ip":           self.dst_ip,
            "dst_port":         self.dst_port,
            "anomaly_score":    round(self.anomaly_score, 4),
            "severity":         self.severity,
            "top_features":     [(f, round(v, 4)) for f, v in self.top_features],
            "attack_type_hint": self.attack_type_hint,
            "feature_values":   {k: round(float(v), 3) for k, v in self.feature_values.items()},
        }


class AnomalyDetector:
    """
    Isolation Forest based network anomaly detector.

    Train on clean baseline traffic → score new events →
    explain alerts with SHAP → create AlertEvent objects
    for the LangGraph agent.
    """

    def __init__(self, contamination: float = 0.02, n_estimators: int = 200):
        self.contamination  = contamination
        self.n_estimators   = n_estimators
        self.model          = IsolationForest(
            n_estimators  = n_estimators,
            contamination = contamination,
            max_samples   = "auto",
            random_state  = 42,
            n_jobs        = -1,
        )
        self.scaler        = StandardScaler()
        self.explainer     = None
        self.is_trained    = False
        self._score_min    = None
        self._score_max    = None

    # ─── Training ─────────────────────────────────────────────────────────────

    def train(self, df: pd.DataFrame) -> dict:
        """
        Train on clean baseline traffic.

        Parameters
        ----------
        df : Feature-engineered DataFrame (from engineer_features_fast)

        Returns
        -------
        dict with training stats
        """
        # Use only normal traffic for training
        if "label" in df.columns:
            train_df = df[df["label"] == "normal"]
            print(f"[Detector] Using {len(train_df)} normal samples for training (excluded {len(df) - len(train_df)} labelled attacks)")
        else:
            train_df = df
            print(f"[Detector] Training on all {len(train_df)} samples (no labels)")

        X = get_feature_matrix(train_df)
        X_scaled = self.scaler.fit_transform(X)

        self.model.fit(X_scaled)

        # Compute score range on training data for normalisation
        raw = self.model.score_samples(X_scaled)
        self._score_min = float(raw.min())
        self._score_max = float(raw.max())

        # SHAP explainer — TreeExplainer works with Isolation Forest
        self.explainer = shap.TreeExplainer(self.model)
        self.is_trained = True

        # Quick validation if labels exist
        stats = {"n_trained": len(train_df), "contamination": self.contamination}
        if "label" in df.columns:
            scored = self.score(df)
            attacks = df["label"] != "normal"
            detected = scored.loc[attacks, "is_anomaly"]
            stats["detection_rate"] = round(detected.mean(), 3) if attacks.any() else None

        print(f"[Detector] Training complete. Stats: {stats}")
        return stats

    # ─── Scoring ──────────────────────────────────────────────────────────────

    def score(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Score a DataFrame of feature rows.

        Returns the input DataFrame with added columns:
            anomaly_score (0-1), is_anomaly (bool), severity (str)
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call .train() first.")

        X = get_feature_matrix(df)
        X_scaled = self.scaler.transform(X)

        raw_scores = self.model.score_samples(X_scaled)

        # Normalise to 0-1 (1 = most anomalous)
        score_range = self._score_max - self._score_min
        if score_range == 0:
            anomaly_scores = np.zeros(len(raw_scores))
        else:
            anomaly_scores = 1 - (raw_scores - self._score_min) / score_range

        anomaly_scores = np.clip(anomaly_scores, 0, 1)

        result = df.copy()
        result["anomaly_score"] = anomaly_scores
        result["is_anomaly"]    = anomaly_scores >= THRESHOLDS["Medium"]
        result["severity"]      = pd.cut(
            anomaly_scores,
            bins   = [0, THRESHOLDS["Medium"], THRESHOLDS["High"], THRESHOLDS["Critical"], 1.001],
            labels = ["Normal", "Medium", "High", "Critical"],
            right  = True,
        ).astype(str)
        return result

    def explain(self, row: pd.Series) -> List[tuple]:
        """
        Get SHAP explanation for a single alert row.
        Returns list of (feature_name, shap_value) sorted by importance.
        """
        if self.explainer is None:
            return []

        X = row[FEATURE_COLS].fillna(0).values.reshape(1, -1)
        X_scaled = self.scaler.transform(X)

        try:
            shap_values = self.explainer.shap_values(X_scaled)[0]
            feature_impact = list(zip(FEATURE_COLS, shap_values))
            feature_impact.sort(key=lambda x: abs(x[1]), reverse=True)
            return feature_impact[:5]
        except Exception:
            return []

    def rule_classify(self, row: dict) -> str:
        """Fast rule-based pre-classification before LLM."""
        for attack_type, rule in ATTACK_RULES.items():
            if rule(row):
                return attack_type
        return "unknown"

    # ─── Alert creation ───────────────────────────────────────────────────────

    def create_alert(self, row: pd.Series, alert_id: str = None) -> AlertEvent:
        """Create an enriched AlertEvent from a scored feature row."""
        import uuid
        feature_dict = {col: float(row.get(col, 0)) for col in FEATURE_COLS}

        return AlertEvent(
            alert_id         = alert_id or str(uuid.uuid4())[:8],
            timestamp        = pd.to_datetime(row.get("timestamp", datetime.now())),
            src_ip           = str(row.get("src_ip", "unknown")),
            dst_ip           = str(row.get("dst_ip", "unknown")),
            dst_port         = int(row.get("dst_port", 0)),
            anomaly_score    = float(row.get("anomaly_score", 0)),
            severity         = str(row.get("severity", "Medium")),
            feature_values   = feature_dict,
            top_features     = self.explain(row),
            attack_type_hint = self.rule_classify(feature_dict),
        )

    def get_alerts(self, scored_df: pd.DataFrame) -> List[AlertEvent]:
        """Extract all anomalous rows and convert to AlertEvent list."""
        anomalies = scored_df[scored_df["is_anomaly"] == True]
        alerts = []
        for _, row in anomalies.iterrows():
            alerts.append(self.create_alert(row))
        return alerts

    # ─── Persistence ──────────────────────────────────────────────────────────

    def save(self, name: str = "detector"):
        path = os.path.join(MODEL_DIR, f"{name}.joblib")
        joblib.dump({
            "model":       self.model,
            "scaler":      self.scaler,
            "score_min":   self._score_min,
            "score_max":   self._score_max,
            "contamination": self.contamination,
        }, path)
        print(f"[Detector] Saved to {path}")

    @classmethod
    def load(cls, name: str = "detector") -> "AnomalyDetector":
        path = os.path.join(MODEL_DIR, f"{name}.joblib")
        if not os.path.exists(path):
            raise FileNotFoundError(f"No saved detector at {path}. Run train.py first.")
        saved = joblib.load(path)
        obj = cls(contamination=saved["contamination"])
        obj.model       = saved["model"]
        obj.scaler      = saved["scaler"]
        obj._score_min  = saved["score_min"]
        obj._score_max  = saved["score_max"]
        obj.is_trained  = True
        print(f"[Detector] Loaded from {path}")
        return obj

    @staticmethod
    def is_saved(name: str = "detector") -> bool:
        return os.path.exists(os.path.join(MODEL_DIR, f"{name}.joblib"))
