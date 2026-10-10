"""
pages/1_Live_Monitor.py
------------------------
Real-time anomaly detection dashboard.
Simulates a stream of network events and shows live alerts.
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import sys, os, time, json, sqlite3
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from data.log_generator import (
    generate_normal_traffic, generate_port_scan, generate_brute_force,
    generate_data_exfiltration, generate_lateral_movement, generate_c2_beacon
)
from data.feature_engineer import engineer_features_fast
from models.detector import AnomalyDetector

st.set_page_config(page_title="Live Monitor", page_icon="📡", layout="wide")

st.markdown("""
<style>
.stApp { background-color: #080d14; }
div[data-testid="stMetric"] { background:#0d1520;border:1px solid #1a2a3a;border-radius:8px;padding:0.75rem; }
.alert-critical { background:#1a0a0a;border:1px solid #ff3333;border-radius:8px;padding:0.9rem;margin-bottom:8px; }
.alert-high     { background:#1a1200;border:1px solid #ff8800;border-radius:8px;padding:0.9rem;margin-bottom:8px; }
.alert-medium   { background:#0a1400;border:1px solid #ffcc00;border-radius:8px;padding:0.9rem;margin-bottom:8px; }
.alert-normal   { background:#0a1520;border:1px solid #1a3a2a;border-radius:8px;padding:0.7rem;margin-bottom:6px; }
</style>
""", unsafe_allow_html=True)

SEVERITY_COLORS = {"Critical": "#ff3333", "High": "#ff8800", "Medium": "#ffcc00", "Normal": "#00ff88"}
ATTACK_EMOJI    = {"port_scan": "🔍", "brute_force": "🔑", "data_exfil": "📤",
                   "lateral_movement": "🔀", "c2_beacon": "📡", "ddos": "💥", "unknown": "⚠️"}

st.markdown("# 📡 Live Network Monitor")
st.caption("Real-time anomaly detection on simulated network traffic")

# ── Sidebar controls ──────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🎛️ Simulation Controls")
    attack_type = st.selectbox("Inject attack scenario", [
        "None (normal traffic only)",
        "Port Scan",
        "Brute Force (SSH)",
        "Data Exfiltration",
        "Lateral Movement",
        "C2 Beacon",
    ])
    n_events    = st.slider("Events to generate", 100, 2000, 500, 100)
    show_normal = st.checkbox("Show normal events", value=False)
    auto_investigate = st.checkbox("Auto-investigate Critical alerts", value=True)
    st.markdown("---")
    run_btn = st.button("▶ Run Detection", type="primary", use_container_width=True)

# ── Check model ───────────────────────────────────────────────────────────────
if not AnomalyDetector.is_saved("detector"):
    st.error("⚠️ No trained model found. Run `python train.py` first.")
    st.stop()

@st.cache_resource
def get_detector():
    return AnomalyDetector.load("detector")

detector = get_detector()

# ── Run detection ─────────────────────────────────────────────────────────────
if run_btn:
    with st.spinner("Generating network traffic..."):
        from datetime import datetime
        now = datetime.now()

        # Generate normal base traffic
        df_normal = generate_normal_traffic(n_events, start_time=now)

        # Inject attack if selected
        attack_map = {
            "Port Scan":          generate_port_scan,
            "Brute Force (SSH)":  generate_brute_force,
            "Data Exfiltration":  generate_data_exfiltration,
            "Lateral Movement":   generate_lateral_movement,
            "C2 Beacon":          generate_c2_beacon,
        }
        if attack_type != "None (normal traffic only)":
            attack_fn = attack_map[attack_type]
            df_attack = attack_fn(start_time=now)
            df_raw = pd.concat([df_normal, df_attack], ignore_index=True)
            st.info(f"💉 Injected: **{attack_type}** ({len(df_attack)} events from a simulated malicious IP)")
        else:
            df_raw = df_normal

        df_raw = df_raw.sort_values("timestamp").reset_index(drop=True)

    with st.spinner("Engineering features and running Isolation Forest..."):
        df_features = engineer_features_fast(df_raw)
        df_scored   = detector.score(df_features)

    # ── Summary metrics ───────────────────────────────────────────
    st.markdown("---")
    total      = len(df_scored)
    n_anomaly  = df_scored["is_anomaly"].sum()
    n_critical = (df_scored["severity"] == "Critical").sum()
    n_high     = (df_scored["severity"] == "High").sum()
    n_medium   = (df_scored["severity"] == "Medium").sum()

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total events",   f"{total:,}")
    m2.metric("Anomalies",      f"{n_anomaly:,}",  f"{n_anomaly/total*100:.1f}%")
    m3.metric("🔴 Critical",    f"{n_critical}")
    m4.metric("🟠 High",        f"{n_high}")
    m5.metric("🟡 Medium",      f"{n_medium}")

    # ── Charts ────────────────────────────────────────────────────
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown("#### Anomaly Score Distribution")
        fig_hist = go.Figure()
        fig_hist.add_trace(go.Histogram(
            x=df_scored["anomaly_score"], nbinsx=50,
            marker_color="#4a9eff", opacity=0.7, name="All events"
        ))
        anomalies = df_scored[df_scored["is_anomaly"]]
        fig_hist.add_trace(go.Histogram(
            x=anomalies["anomaly_score"], nbinsx=30,
            marker_color="#ff3333", opacity=0.8, name="Anomalies"
        ))
        for thresh, color, label in [(0.55, "#ffcc00","Medium"), (0.70,"#ff8800","High"), (0.85,"#ff3333","Critical")]:
            fig_hist.add_vline(x=thresh, line_dash="dash", line_color=color,
                               annotation_text=label, annotation_font_color=color)
        fig_hist.update_layout(
            paper_bgcolor="#080d14", plot_bgcolor="#0d1520", font_color="#c0d0e0",
            height=280, barmode="overlay", showlegend=True,
            legend=dict(bgcolor="#0d1520"),
            xaxis=dict(title="Anomaly Score", showgrid=True, gridcolor="#1a2a3a", color="#6080a0"),
            yaxis=dict(title="Count", showgrid=True, gridcolor="#1a2a3a", color="#6080a0"),
            margin=dict(l=0, r=0, t=10, b=0),
        )
        st.plotly_chart(fig_hist, use_container_width=True)

    with col_right:
        st.markdown("#### Severity Breakdown")
        sev_counts = df_scored["severity"].value_counts()
        colors     = [SEVERITY_COLORS.get(s, "#888") for s in sev_counts.index]
        fig_pie = go.Figure(go.Pie(
            labels=sev_counts.index, values=sev_counts.values,
            marker=dict(colors=colors),
            hole=0.5, textinfo="label+value",
            textfont=dict(color="#c0d0e0"),
        ))
        fig_pie.update_layout(
            paper_bgcolor="#080d14", font_color="#c0d0e0",
            height=280, showlegend=False,
            margin=dict(l=0, r=0, t=10, b=0),
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    # ── Alert feed ────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("#### 🚨 Alert Feed")

    display_df = df_scored[df_scored["is_anomaly"]] if not show_normal else df_scored
    display_df = display_df.sort_values("anomaly_score", ascending=False).head(50)

    if len(display_df) == 0:
        st.success("✅ No anomalies detected in this traffic sample.")
    else:
        for _, row in display_df.iterrows():
            sev   = str(row.get("severity", "Normal"))
            score = float(row.get("anomaly_score", 0))
            src   = str(row.get("src_ip", "?"))
            port  = int(row.get("dst_port", 0))
            color = SEVERITY_COLORS.get(sev, "#888")
            hint  = detector.rule_classify({col: row.get(col, 0) for col in ["unique_dst_ports","failed_conn_rate","bytes_ratio","bytes_sent_sum","unique_dst_ips","conn_rate","bytes_per_packet"]})
            emoji = ATTACK_EMOJI.get(hint, "⚠️")

            st.markdown(f"""
            <div style="background:#0d1520;border:1px solid {color};border-radius:8px;
            padding:0.75rem;margin-bottom:6px;display:flex;justify-content:space-between;align-items:center">
                <div>
                    <span style="color:{color};font-weight:700">{sev}</span>
                    <span style="color:#6080a0;margin:0 10px">|</span>
                    <span style="color:#c0d0e0">{emoji} {hint.replace('_',' ').title()}</span>
                    <span style="color:#6080a0;margin:0 10px">|</span>
                    <span style="color:#4a9eff">src: {src}</span>
                    <span style="color:#6080a0;margin:0 10px">→</span>
                    <span style="color:#c0d0e0">port {port}</span>
                </div>
                <div style="color:{color};font-weight:700;font-family:monospace">
                    score: {score:.3f}
                </div>
            </div>""", unsafe_allow_html=True)

    # ── Auto-investigate critical ─────────────────────────────────
    if auto_investigate and n_critical > 0:
        st.markdown("---")
        st.markdown("#### 🤖 Auto-Investigation (Critical Alerts)")
        critical_rows = df_scored[df_scored["severity"] == "Critical"].head(2)

        for _, row in critical_rows.iterrows():
            alert_ev = detector.create_alert(row)
            alert_dict = alert_ev.to_dict()
            st.info(f"🔍 Investigating alert from **{alert_dict['src_ip']}** | Score: {alert_dict['anomaly_score']:.3f}")
            st.page_link("pages/2_Investigate_Alert.py", label="→ Open full investigation panel")

else:
    st.info("👈 Configure simulation settings and click **Run Detection** to start.")
    st.markdown("""
    **How this page works:**
    - Generates realistic network traffic (normal + optional attack scenario)
    - Runs Isolation Forest anomaly detection on engineered features
    - Shows real-time alert feed with severity classification
    - Critical alerts can trigger the LangGraph investigation agent
    """)
