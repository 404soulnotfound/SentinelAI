"""
pages/2_Investigate_Alert.py
-----------------------------
Interactive LangGraph investigation panel.
User configures an alert → agent investigates → shows full incident report.
"""

import streamlit as st
import pandas as pd
import json, sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models.detector import AnomalyDetector, AlertEvent
from agent.investigation_agent import investigate_alert, build_investigation_graph
from rag.cve_knowledge_base import CVEKnowledgeBase

st.set_page_config(page_title="Investigate Alert", page_icon="🔍", layout="wide")

st.markdown("""
<style>
.stApp { background-color: #080d14; }
div[data-testid="stMetric"] { background:#0d1520;border:1px solid #1a2a3a;border-radius:8px;padding:0.75rem; }
.node-box { background:#0d1520;border:1px solid #1a2a3a;border-radius:8px;padding:0.9rem;margin-bottom:8px; }
.node-done { border-color:#00ff88; }
.node-run  { border-color:#4a9eff; animation: pulse 1s infinite; }
</style>
""", unsafe_allow_html=True)

ATTACK_SCENARIOS = {
    "SSH Brute Force": {
        "src_ip": "185.220.101.45", "dst_ip": "10.0.0.10", "dst_port": 22,
        "anomaly_score": 0.91, "severity": "Critical",
        "attack_type_hint": "brute_force",
        "feature_values": {
            "bytes_sent_sum": 28000, "bytes_recv_sum": 5000, "bytes_ratio": 5.6,
            "packets_sum": 860, "unique_dst_ports": 1, "unique_dst_ips": 1,
            "failed_conn_rate": 0.96, "conn_rate": 287, "avg_duration": 0.04,
            "bytes_per_packet": 32.5,
        },
        "top_features": [["failed_conn_rate", 0.61], ["conn_rate", 0.28], ["bytes_ratio", 0.08]],
    },
    "Port Scan": {
        "src_ip": "23.129.64.214", "dst_ip": "10.0.0.20", "dst_port": 443,
        "anomaly_score": 0.88, "severity": "Critical",
        "attack_type_hint": "port_scan",
        "feature_values": {
            "bytes_sent_sum": 32000, "bytes_recv_sum": 0, "bytes_ratio": 999,
            "packets_sum": 512, "unique_dst_ports": 487, "unique_dst_ips": 3,
            "failed_conn_rate": 0.99, "conn_rate": 498, "avg_duration": 0.001,
            "bytes_per_packet": 62.5,
        },
        "top_features": [["unique_dst_ports", 0.72], ["failed_conn_rate", 0.18], ["conn_rate", 0.07]],
    },
    "Data Exfiltration": {
        "src_ip": "192.168.1.45", "dst_ip": "199.87.154.255", "dst_port": 443,
        "anomaly_score": 0.83, "severity": "High",
        "attack_type_hint": "data_exfil",
        "feature_values": {
            "bytes_sent_sum": 4500000, "bytes_recv_sum": 1200, "bytes_ratio": 3750,
            "packets_sum": 3200, "unique_dst_ports": 1, "unique_dst_ips": 1,
            "failed_conn_rate": 0.0, "conn_rate": 42, "avg_duration": 8.5,
            "bytes_per_packet": 1406.0,
        },
        "top_features": [["bytes_ratio", 0.68], ["bytes_sent_sum", 0.21], ["avg_duration", 0.08]],
    },
    "Lateral Movement": {
        "src_ip": "192.168.1.55", "dst_ip": "192.168.1.100", "dst_port": 445,
        "anomaly_score": 0.76, "severity": "High",
        "attack_type_hint": "lateral_movement",
        "feature_values": {
            "bytes_sent_sum": 125000, "bytes_recv_sum": 48000, "bytes_ratio": 2.6,
            "packets_sum": 890, "unique_dst_ports": 4, "unique_dst_ips": 28,
            "failed_conn_rate": 0.31, "conn_rate": 112, "avg_duration": 1.2,
            "bytes_per_packet": 140.4,
        },
        "top_features": [["unique_dst_ips", 0.55], ["conn_rate", 0.24], ["failed_conn_rate", 0.14]],
    },
    "C2 Beacon": {
        "src_ip": "192.168.1.33", "dst_ip": "178.73.215.171", "dst_port": 443,
        "anomaly_score": 0.67, "severity": "High",
        "attack_type_hint": "c2_beacon",
        "feature_values": {
            "bytes_sent_sum": 480, "bytes_recv_sum": 520, "bytes_ratio": 0.92,
            "packets_sum": 12, "unique_dst_ports": 1, "unique_dst_ips": 1,
            "failed_conn_rate": 0.0, "conn_rate": 4, "avg_duration": 0.08,
            "bytes_per_packet": 40.0,
        },
        "top_features": [["bytes_ratio", 0.44], ["bytes_sent_sum", 0.31], ["avg_duration", 0.18]],
    },
    "Custom": None,
}

# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown("# 🔍 Alert Investigation Panel")
st.caption("Configure an alert → LangGraph agent autonomously investigates → Full incident report")
st.markdown("---")

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🎯 Alert Configuration")
    scenario = st.selectbox("Use pre-built scenario", list(ATTACK_SCENARIOS.keys()))

    if scenario == "Custom":
        st.markdown("**Custom alert parameters:**")
        src_ip     = st.text_input("Source IP",   "185.220.101.45")
        dst_ip     = st.text_input("Dest IP",     "10.0.0.10")
        dst_port   = st.number_input("Dest port", 1, 65535, 22)
        score      = st.slider("Anomaly score", 0.0, 1.0, 0.88, 0.01)
        severity   = st.selectbox("Severity", ["Critical", "High", "Medium"])
        hint       = st.selectbox("Attack hint", ["brute_force", "port_scan", "data_exfil",
                                                   "lateral_movement", "c2_beacon", "unknown"])
    st.markdown("---")
    investigate_btn = st.button("🤖 Run Full Investigation", type="primary", use_container_width=True)

# ── Build alert dict ───────────────────────────────────────────────────────────
if scenario != "Custom":
    sc = ATTACK_SCENARIOS[scenario]
    alert_dict = {
        "alert_id":         f"ALT-{int(time.time()) % 10000:04d}",
        "timestamp":        pd.Timestamp.now().isoformat(),
        "src_ip":           sc["src_ip"],
        "dst_ip":           sc["dst_ip"],
        "dst_port":         sc["dst_port"],
        "anomaly_score":    sc["anomaly_score"],
        "severity":         sc["severity"],
        "attack_type_hint": sc["attack_type_hint"],
        "feature_values":   sc["feature_values"],
        "top_features":     sc["top_features"],
    }
else:
    alert_dict = {
        "alert_id":         f"ALT-{int(time.time()) % 10000:04d}",
        "timestamp":        pd.Timestamp.now().isoformat(),
        "src_ip":           src_ip,
        "dst_ip":           dst_ip,
        "dst_port":         dst_port,
        "anomaly_score":    score,
        "severity":         severity,
        "attack_type_hint": hint,
        "feature_values":   {},
        "top_features":     [],
    }

# ── Show alert preview ─────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)
sev_color = {"Critical": "#ff3333", "High": "#ff8800", "Medium": "#ffcc00"}.get(alert_dict["severity"], "#888")
col1.metric("Source IP",     alert_dict["src_ip"])
col2.metric("Dest Port",     alert_dict["dst_port"])
col3.metric("Anomaly Score", f"{alert_dict['anomaly_score']:.3f}")
col4.markdown(f"""
<div style="background:#0d1520;border:1px solid {sev_color};border-radius:8px;
padding:0.75rem;text-align:center;margin-top:4px">
    <div style="font-size:0.7rem;color:#6080a0;text-transform:uppercase;letter-spacing:1px">Severity</div>
    <div style="color:{sev_color};font-size:1.3rem;font-weight:700">{alert_dict['severity']}</div>
</div>""", unsafe_allow_html=True)

st.markdown("---")

# ── Run investigation ──────────────────────────────────────────────────────────
if investigate_btn:
    @st.cache_resource
    def get_kb():
        kb = CVEKnowledgeBase()
        if not kb.is_built():
            kb.build()
        return kb

    kb = get_kb()

    # Show agent graph progress
    st.markdown("### 🤖 LangGraph Investigation — Live Progress")

    NODES = [
        ("ingest_alert",       "📥 Ingest Alert",        "Validate and prepare alert for investigation"),
        ("classify_threat",    "🏷️  Classify Threat",    "Ollama classifies attack type from features"),
        ("check_threat_intel", "🌐 Threat Intelligence", "Query AbuseIPDB for IP reputation"),
        ("query_cve_rag",      "📚 CVE Knowledge Base",  "Semantic search for matching vulnerabilities"),
        ("mitre_mapping",      "🗺️  MITRE ATT&CK",       "Map to industry attack framework"),
        ("score_severity",     "⚖️  Score Severity",     "Combine signals into final severity score"),
        ("generate_report",    "📝 Generate Report",     "Ollama writes structured incident report"),
        ("route & store",      "💾 Route & Store",       "Save report, alert human if Critical"),
    ]

    node_placeholders = []
    for name, label, desc in NODES:
        ph = st.empty()
        ph.markdown(f"""
        <div class="node-box">
            <span style="color:#4a6a8a;font-size:0.75rem">○</span>
            <span style="color:#4a6a8a;margin-left:8px">{label}</span>
            <span style="color:#2a3a4a;margin-left:8px;font-size:0.75rem">{desc}</span>
        </div>""", unsafe_allow_html=True)
        node_placeholders.append(ph)

    # Actually run the investigation
    result_placeholder = st.empty()

    with st.spinner("Agent investigating..."):
        for i, (name, label, desc) in enumerate(NODES):
            # Mark current node as running
            node_placeholders[i].markdown(f"""
            <div style="background:#0d1520;border:1px solid #4a9eff;border-radius:8px;padding:0.9rem;margin-bottom:8px">
                <span style="color:#4a9eff;font-size:0.75rem">▶</span>
                <span style="color:#4a9eff;margin-left:8px;font-weight:500">{label}</span>
                <span style="color:#6080a0;margin-left:8px;font-size:0.75rem">{desc}</span>
            </div>""", unsafe_allow_html=True)
            time.sleep(0.3)

        # Run the actual LangGraph investigation
        try:
            result = investigate_alert(alert_dict, kb=kb)
            success = True
        except Exception as e:
            result = {"error": str(e)}
            success = False

        # Mark all nodes done
        for i, (name, label, desc) in enumerate(NODES):
            node_placeholders[i].markdown(f"""
            <div style="background:#0d1520;border:1px solid #00ff88;border-radius:8px;padding:0.9rem;margin-bottom:8px">
                <span style="color:#00ff88;font-size:0.75rem">✓</span>
                <span style="color:#00ff88;margin-left:8px;font-weight:500">{label}</span>
                <span style="color:#4a6a8a;margin-left:8px;font-size:0.75rem">{desc}</span>
            </div>""", unsafe_allow_html=True)

    if not success:
        st.error(f"Investigation failed: {result.get('error')}")
        st.stop()

    # ── Results ───────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 📊 Investigation Results")

    r1, r2, r3, r4 = st.columns(4)
    r1.metric("Threat Class",    result.get("threat_class", "?").replace("_", " ").title())
    r2.metric("Confidence",      f"{result.get('confidence', 0):.0%}")
    r3.metric("Final Severity",  result.get("final_severity", "?"))
    r4.metric("CVEs Found",      len(result.get("cve_matches", [])))

    tabs = st.tabs(["📝 Incident Report", "🌐 Threat Intel", "📚 CVE Matches", "🗺️ MITRE", "🔬 Raw State"])

    with tabs[0]:
        report = result.get("incident_report", "No report generated.")
        st.markdown(report)

    with tabs[1]:
        intel = result.get("threat_intel", {})
        if intel:
            i1, i2, i3 = st.columns(3)
            abuse = intel.get("abuse_score", 0)
            color = "#ff3333" if abuse > 75 else "#ffaa00" if abuse > 25 else "#00ff88"
            i1.markdown(f"""
            <div style="background:#0d1520;border:1px solid {color};border-radius:8px;padding:1rem;text-align:center">
                <div style="color:#6080a0;font-size:0.75rem;text-transform:uppercase">Abuse Score</div>
                <div style="color:{color};font-size:2rem;font-weight:700">{abuse}/100</div>
            </div>""", unsafe_allow_html=True)
            i2.metric("Known Malicious", "YES" if intel.get("is_known_malicious") else "NO")
            i3.metric("Total Reports",   intel.get("total_reports", 0))
            st.json(intel)
        else:
            st.info("No threat intel data available.")

    with tabs[2]:
        cves = result.get("cve_matches", [])
        if cves:
            for cve in cves:
                cvss  = cve.get("cvss", 0)
                color = "#ff3333" if cvss >= 9 else "#ff8800" if cvss >= 7 else "#ffcc00"
                st.markdown(f"""
                <div style="background:#0d1520;border:1px solid {color};border-radius:8px;
                padding:0.9rem;margin-bottom:8px">
                    <div style="display:flex;justify-content:space-between;align-items:center">
                        <span style="color:{color};font-weight:700;font-family:monospace">{cve['cve_id']}</span>
                        <span style="color:{color};font-weight:700">CVSS {cvss}</span>
                    </div>
                    <div style="color:#8090a0;font-size:0.85rem;margin-top:6px">{cve.get('description','')[:300]}</div>
                    <div style="color:#4a6a8a;font-size:0.75rem;margin-top:4px">Relevance: {cve.get('relevance',0):.0%}</div>
                </div>""", unsafe_allow_html=True)
        else:
            st.info("No CVE matches found.")

    with tabs[3]:
        mitre = result.get("mitre_technique", {})
        if mitre:
            st.markdown(f"""
            <div style="background:#0d1520;border:1px solid #4a9eff;border-radius:8px;padding:1.2rem">
                <div style="font-size:1.5rem;font-weight:700;color:#4a9eff;font-family:monospace">
                    {mitre.get('id','N/A')}
                </div>
                <div style="font-size:1rem;font-weight:500;color:#c0d0e0;margin:4px 0">
                    {mitre.get('name','N/A')}
                </div>
                <div style="color:#6080a0;font-size:0.85rem;margin-bottom:10px">
                    Tactic: {mitre.get('tactic','N/A')}
                </div>
                <div style="color:#8090a0;font-size:0.85rem;line-height:1.6">
                    {mitre.get('description','N/A')}
                </div>
            </div>""", unsafe_allow_html=True)
            st.markdown("**Recommended Mitigations:**")
            for m in mitre.get("mitigations", []):
                st.markdown(f"- {m}")
        else:
            st.info("No MITRE mapping available.")

    with tabs[4]:
        # Show raw state (minus the full report for cleanliness)
        raw = {k: v for k, v in result.items() if k != "incident_report"}
        st.json(raw)

else:
    st.markdown("""
    ### How the LangGraph investigation works

    When you click **Run Full Investigation**, this is what happens:

    1. **ingest_alert** — Alert data is loaded into the shared AgentState
    2. **classify_threat** — Ollama reads the anomalous features and classifies the attack type
    3. **check_threat_intel** — AbuseIPDB is queried for the source IP's reputation score
    4. **query_cve_rag** — ChromaDB is searched for CVEs matching the attack pattern
    5. **mitre_mapping** — Attack is mapped to MITRE ATT&CK technique ID and tactic
    6. **score_severity** — All signals combined into a final severity score
    7. **generate_report** — Ollama writes a complete structured incident report
    8. **route & store** — Critical alerts trigger human notification; all saved to SQLite
    
    Select a scenario from the sidebar and click **Run Full Investigation** to try it.
    """)
