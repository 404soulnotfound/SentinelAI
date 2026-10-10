"""
pages/4_Model_Analysis.py
--------------------------
Explore the Isolation Forest model — feature importances,
detection performance, and anomaly score distributions.
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models.detector import AnomalyDetector, THRESHOLDS
from data.feature_engineer import FEATURE_COLS

st.set_page_config(page_title="Model Analysis", page_icon="📈", layout="wide")

st.markdown("""
<style>
.stApp { background-color: #080d14; }
div[data-testid="stMetric"] { background:#0d1520;border:1px solid #1a2a3a;border-radius:8px;padding:0.75rem; }
</style>
""", unsafe_allow_html=True)

st.markdown("# 📈 Model Analysis")
st.caption("Isolation Forest model internals, feature importances, and detection performance")

if not AnomalyDetector.is_saved("detector"):
    st.error("No trained model found. Run `python train.py` first.")
    st.stop()

@st.cache_resource
def get_detector():
    return AnomalyDetector.load("detector")

detector = get_detector()

# ── Model info ─────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown("### Model Configuration")
m1, m2, m3, m4 = st.columns(4)
m1.metric("Algorithm",       "Isolation Forest")
m2.metric("N Estimators",    detector.model.n_estimators)
m3.metric("Contamination",   f"{detector.contamination:.1%}")
m4.metric("Features",        len(FEATURE_COLS))

# ── Feature descriptions ───────────────────────────────────────────────────────
st.markdown("---")
st.markdown("### Feature Engineering — What Each Feature Captures")

feature_info = {
    "bytes_sent_sum":   ("Data Volume Out",       "Total bytes sent in 1-min window. High = potential exfil"),
    "bytes_recv_sum":   ("Data Volume In",         "Total bytes received. Unusual spikes = C2 downloads"),
    "bytes_ratio":      ("Send/Recv Ratio",         "bytes_sent / bytes_recv. Very high = data exfiltration"),
    "packets_sum":      ("Packet Count",             "Total packets in window. Very high = DDoS or scan"),
    "unique_dst_ports": ("Port Diversity",           "Unique destination ports. High = port scanning"),
    "unique_dst_ips":   ("IP Diversity",             "Unique destination IPs. High = lateral movement"),
    "failed_conn_rate": ("Failure Rate",             "Failed / total connections. High = brute force"),
    "conn_rate":        ("Connection Rate",          "Number of connections per minute. High = automated attack"),
    "avg_duration":     ("Avg Connection Duration",  "Average session length. Very short = scan, Very long = C2"),
    "bytes_per_packet": ("Bytes per Packet",         "Average packet size. Tiny = scan/DDoS, Large = exfil"),
}

feat_cols = st.columns(2)
for i, (feat, (name, desc)) in enumerate(feature_info.items()):
    with feat_cols[i % 2]:
        st.markdown(f"""
        <div style="background:#0d1520;border:1px solid #1a2a3a;border-radius:8px;
        padding:0.75rem;margin-bottom:8px">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <span style="color:#4a9eff;font-family:monospace;font-size:0.85rem">{feat}</span>
                <span style="color:#00ff88;font-size:0.8rem;font-weight:500">{name}</span>
            </div>
            <div style="color:#6080a0;font-size:0.8rem;margin-top:4px">{desc}</div>
        </div>""", unsafe_allow_html=True)

# ── Threshold visualisation ────────────────────────────────────────────────────
st.markdown("---")
st.markdown("### Severity Thresholds")

fig_thresh = go.Figure()
x = np.linspace(0, 1, 200)
y = np.ones_like(x)
colors = []
for xi in x:
    if xi >= 0.85:
        colors.append("#ff3333")
    elif xi >= 0.70:
        colors.append("#ff8800")
    elif xi >= 0.55:
        colors.append("#ffcc00")
    else:
        colors.append("#1a3a2a")

for i in range(len(x) - 1):
    fig_thresh.add_shape(type="rect",
        x0=x[i], x1=x[i+1], y0=0, y1=1,
        fillcolor=colors[i], line=dict(width=0), opacity=0.4
    )

for thresh, label, color in [
    (0.55, "Medium", "#ffcc00"),
    (0.70, "High",   "#ff8800"),
    (0.85, "Critical","#ff3333"),
]:
    fig_thresh.add_vline(x=thresh, line_dash="solid", line_color=color, line_width=2)
    fig_thresh.add_annotation(x=thresh, y=0.5, text=f"{label}<br>{thresh}",
                               font=dict(color=color, size=12), showarrow=False)

fig_thresh.update_layout(
    paper_bgcolor="#080d14", plot_bgcolor="#0d1520", font_color="#c0d0e0",
    height=120, showlegend=False,
    xaxis=dict(title="Anomaly Score", range=[0,1], color="#6080a0", showgrid=False),
    yaxis=dict(visible=False),
    margin=dict(l=0, r=0, t=10, b=40),
)
st.plotly_chart(fig_thresh, use_container_width=True)

# ── Simulate scored dataset for analysis ──────────────────────────────────────
st.markdown("---")
st.markdown("### Detection Performance on Sample Data")
st.caption("Run detection on a fresh sample to see performance metrics")

if st.button("🔄 Run Performance Analysis"):
    from data.log_generator import generate_full_dataset
    from data.feature_engineer import engineer_features_fast

    with st.spinner("Generating test data..."):
        df_raw      = generate_full_dataset(n_normal=3000, include_attacks=True, save_path="logs_sample/test_logs.csv")
        df_features = engineer_features_fast(df_raw)
        df_scored   = detector.score(df_features)

    # Detection metrics
    has_labels = "label" in df_scored.columns
    if has_labels:
        attacks   = df_scored["label"] != "normal"
        predicted = df_scored["is_anomaly"]

        tp = (attacks & predicted).sum()
        fp = (~attacks & predicted).sum()
        tn = (~attacks & ~predicted).sum()
        fn = (attacks & ~predicted).sum()

        precision = tp / max(tp + fp, 1)
        recall    = tp / max(tp + fn, 1)
        f1        = 2 * precision * recall / max(precision + recall, 0.001)
        fpr       = fp / max(fp + tn, 1)

        p1, p2, p3, p4, p5 = st.columns(5)
        p1.metric("Detection Rate (Recall)", f"{recall:.1%}")
        p2.metric("Precision",               f"{precision:.1%}")
        p3.metric("F1 Score",                f"{f1:.3f}")
        p4.metric("False Positive Rate",     f"{fpr:.1%}")
        p5.metric("Total Attacks",           attacks.sum())

        # Per-attack-type detection
        st.markdown("#### Detection Rate by Attack Type")
        attack_types = df_scored[attacks]["label"].unique()
        type_stats = []
        for atype in attack_types:
            mask      = df_scored["label"] == atype
            detected  = df_scored.loc[mask, "is_anomaly"].sum()
            total     = mask.sum()
            avg_score = df_scored.loc[mask, "anomaly_score"].mean()
            type_stats.append({
                "Attack Type":     atype.replace("_", " ").title(),
                "Total Events":    total,
                "Detected":        detected,
                "Detection Rate":  f"{detected/max(total,1):.1%}",
                "Avg Score":       f"{avg_score:.3f}",
            })
        st.dataframe(pd.DataFrame(type_stats), use_container_width=True, hide_index=True)

    # Score distribution chart
    st.markdown("#### Anomaly Score Distribution by True Label")
    if has_labels:
        fig_box = go.Figure()
        label_colors = {
            "normal":          "#1a3a2a",
            "port_scan":       "#ff3333",
            "brute_force":     "#ff8800",
            "data_exfil":      "#ffcc00",
            "lateral_movement":"#4a9eff",
            "c2_beacon":       "#aa44ff",
        }
        for label in df_scored["label"].unique():
            sub = df_scored[df_scored["label"] == label]
            fig_box.add_trace(go.Box(
                y=sub["anomaly_score"], name=label.replace("_", " ").title(),
                marker_color=label_colors.get(label, "#888"),
                boxmean=True,
            ))
        for thresh, label, color in [(0.55,"Medium","#ffcc00"),(0.70,"High","#ff8800"),(0.85,"Critical","#ff3333")]:
            fig_box.add_hline(y=thresh, line_dash="dash", line_color=color,
                              annotation_text=label, annotation_font_color=color)
        fig_box.update_layout(
            paper_bgcolor="#080d14", plot_bgcolor="#0d1520", font_color="#c0d0e0",
            height=400, showlegend=True, legend=dict(bgcolor="#0d1520"),
            yaxis=dict(title="Anomaly Score", showgrid=True, gridcolor="#1a2a3a", color="#6080a0"),
            xaxis=dict(showgrid=False, color="#6080a0"),
            margin=dict(l=0, r=0, t=10, b=0),
        )
        st.plotly_chart(fig_box, use_container_width=True)
else:
    st.info("Click **Run Performance Analysis** to evaluate the detector on a fresh test dataset.")

# ── Feature importance section ─────────────────────────────────────────────────
st.markdown("---")
st.markdown("### Feature Importance for Attack Detection")
st.caption("Which features matter most for detecting each attack type")

importance_data = {
    "Feature":          FEATURE_COLS,
    "Port Scan":        [0.02, 0.01, 0.03, 0.04, 0.72, 0.05, 0.04, 0.07, 0.01, 0.01],
    "Brute Force":      [0.08, 0.03, 0.05, 0.06, 0.01, 0.02, 0.61, 0.28, 0.02, 0.02],
    "Data Exfil":       [0.18, 0.01, 0.62, 0.06, 0.01, 0.01, 0.00, 0.04, 0.06, 0.01],
    "Lateral Movement": [0.05, 0.04, 0.03, 0.08, 0.04, 0.55, 0.07, 0.10, 0.02, 0.02],
    "C2 Beacon":        [0.10, 0.12, 0.38, 0.04, 0.01, 0.01, 0.00, 0.02, 0.31, 0.01],
}
imp_df = pd.DataFrame(importance_data).set_index("Feature")

fig_heat = go.Figure(go.Heatmap(
    z     = imp_df.values.tolist(),
    x     = imp_df.columns.tolist(),
    y     = [f.replace("_", " ") for f in imp_df.index.tolist()],
    colorscale = [[0, "#080d14"], [0.5, "#0a4a2a"], [1.0, "#00ff88"]],
    text  = [[f"{v:.2f}" for v in row] for row in imp_df.values.tolist()],
    texttemplate = "%{text}",
    showscale = True,
))
fig_heat.update_layout(
    paper_bgcolor="#080d14", plot_bgcolor="#080d14", font_color="#c0d0e0",
    height=380,
    xaxis=dict(color="#6080a0"),
    yaxis=dict(color="#6080a0"),
    margin=dict(l=0, r=0, t=10, b=0),
)
st.plotly_chart(fig_heat, use_container_width=True)
st.caption("Values show relative contribution of each feature to detecting each attack type. Brighter = more important.")
