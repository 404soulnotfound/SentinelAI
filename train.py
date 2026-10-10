"""
train.py
--------
One-time setup script. Run this before launching the app.

Does three things:
    1. Generates sample network logs (if no real logs provided)
    2. Trains the Isolation Forest anomaly detector
    3. Builds the CVE knowledge base

Run with:
    python train.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import pandas as pd
import warnings
warnings.filterwarnings("ignore")

from data.log_generator import generate_full_dataset
from data.feature_engineer import engineer_features_fast
from models.detector import AnomalyDetector
from rag.cve_knowledge_base import CVEKnowledgeBase


def main():
    print("=" * 60)
    print("  Cybersecurity Threat Intelligence Agent — Setup")
    print("=" * 60)
    print()

    # ── Step 1: Generate / load logs ──────────────────────────────
    print("── Step 1: Network log data ──────────────────────────────")
    log_path = "logs_sample/network_logs.csv"

    if os.path.exists(log_path):
        print(f"  Loading existing logs from {log_path}")
        df_raw = pd.read_csv(log_path)
        df_raw["timestamp"] = pd.to_datetime(df_raw["timestamp"])
    else:
        print("  Generating synthetic network logs (normal + attack scenarios)...")
        df_raw = generate_full_dataset(n_normal=8000, include_attacks=True)

    print(f"  ✓ {len(df_raw)} raw log events loaded\n")

    # ── Step 2: Feature engineering ───────────────────────────────
    print("── Step 2: Feature engineering ───────────────────────────")
    df_features = engineer_features_fast(df_raw)
    print(f"  ✓ {len(df_features)} feature rows engineered\n")

    # ── Step 3: Train Isolation Forest ────────────────────────────
    print("── Step 3: Training Isolation Forest ─────────────────────")
    detector = AnomalyDetector(contamination=0.02)
    stats = detector.train(df_features)
    detector.save("detector")

    print(f"  ✓ Trained on {stats['n_trained']} normal samples")
    if stats.get("detection_rate"):
        print(f"  ✓ Detection rate on labelled attacks: {stats['detection_rate']:.1%}")
    print()

    # ── Step 4: Build CVE knowledge base ──────────────────────────
    print("── Step 4: Building CVE knowledge base ───────────────────")
    kb = CVEKnowledgeBase()
    kb.build(use_nvd_api=False)  # Set to True + add NVD key for live data
    print(f"  ✓ Knowledge base ready: {kb.count()} CVE records\n")

    # ── Step 5: Quick validation ───────────────────────────────────
    print("── Step 5: Validation ────────────────────────────────────")
    scored = detector.score(df_features)
    n_anomalies = scored["is_anomaly"].sum()
    n_critical  = (scored["severity"] == "Critical").sum()
    print(f"  ✓ Scored {len(scored)} events")
    print(f"  ✓ Flagged {n_anomalies} anomalies ({n_anomalies/len(scored)*100:.1f}%)")
    print(f"  ✓ Critical: {n_critical} | High: {(scored['severity']=='High').sum()} | Medium: {(scored['severity']=='Medium').sum()}")
    print()

    print("=" * 60)
    print("  ✓ Setup complete!")
    print()
    print("  Next steps:")
    print("  1. Copy .env.example to .env")
    print("  2. (Optional) Add your ABUSEIPDB_API_KEY to .env")
    print("  3. Install Ollama: https://ollama.com")
    print("     Then run: ollama pull mistral")
    print("  4. Launch the app: streamlit run app.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
