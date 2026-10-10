"""
pages/3_Incident_Reports.py
-----------------------------
Browse all saved incident reports from the SQLite database.
"""

import streamlit as st
import pandas as pd
import json, sqlite3, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

st.set_page_config(page_title="Incident Reports", page_icon="📋", layout="wide")

st.markdown("""
<style>
.stApp { background-color: #080d14; }
div[data-testid="stMetric"] { background:#0d1520;border:1px solid #1a2a3a;border-radius:8px;padding:0.75rem; }
</style>
""", unsafe_allow_html=True)

DB_PATH = "reports/alerts.db"
SEVERITY_COLORS = {"Critical": "#ff3333", "High": "#ff8800", "Medium": "#ffcc00", "Low": "#00ff88"}

st.markdown("# 📋 Incident Reports")
st.caption("All investigated alerts with full incident reports")

def load_incidents():
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql("SELECT * FROM incidents ORDER BY created_at DESC", conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()

df = load_incidents()

if df.empty:
    st.info("No incident reports yet. Go to **Investigate Alert** and run an investigation first.")
    st.markdown("""
    **To generate your first report:**
    1. Go to → Investigate Alert
    2. Select any pre-built scenario (e.g. SSH Brute Force)
    3. Click **Run Full Investigation**
    4. Come back here to see the saved report
    """)
    st.stop()

# ── Summary metrics ────────────────────────────────────────────────────────────
st.markdown("---")
m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Total Reports",  len(df))
m2.metric("🔴 Critical",   (df["severity"] == "Critical").sum())
m3.metric("🟠 High",       (df["severity"] == "High").sum())
m4.metric("🟡 Medium",     (df["severity"] == "Medium").sum())
m5.metric("Unique Source IPs", df["src_ip"].nunique())

# ── Filters ────────────────────────────────────────────────────────────────────
st.markdown("---")
col1, col2, col3 = st.columns(3)
with col1:
    sev_filter = st.multiselect("Filter by severity", ["Critical","High","Medium","Low"],
                                default=["Critical","High","Medium","Low"])
with col2:
    type_filter = st.multiselect("Filter by attack type",
                                  df["threat_class"].unique().tolist(),
                                  default=df["threat_class"].unique().tolist())
with col3:
    sort_by = st.selectbox("Sort by", ["Most recent", "Highest severity score", "Highest anomaly score"])

# Apply filters
filtered = df[df["severity"].isin(sev_filter) & df["threat_class"].isin(type_filter)]
if sort_by == "Most recent":
    filtered = filtered.sort_values("created_at", ascending=False)
elif sort_by == "Highest severity score":
    filtered = filtered.sort_values("severity_score", ascending=False)
else:
    filtered = filtered.sort_values("anomaly_score", ascending=False)

st.markdown(f"**Showing {len(filtered)} of {len(df)} reports**")
st.markdown("---")

# ── Report cards ──────────────────────────────────────────────────────────────
for _, row in filtered.iterrows():
    sev   = row.get("severity", "Unknown")
    color = SEVERITY_COLORS.get(sev, "#888")
    tc    = str(row.get("threat_class", "?")).replace("_", " ").title()

    with st.expander(
        f"{'🔴' if sev=='Critical' else '🟠' if sev=='High' else '🟡'} "
        f"[{sev}] {tc} | {row.get('src_ip','?')} → port {row.get('dst_port','?')} | "
        f"Score: {row.get('severity_score', 0):.3f} | {row.get('created_at','')[:16]}",
        expanded=(sev == "Critical")
    ):
        # Metrics row
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Alert ID",       row.get("alert_id", "?"))
        c2.metric("MITRE Technique", row.get("mitre_id", "N/A"))
        c3.metric("CVEs Found",     row.get("cve_count", 0))
        c4.metric("Anomaly Score",  f"{row.get('anomaly_score', 0):.3f}")
        c5.metric("Severity Score", f"{row.get('severity_score', 0):.3f}")

        # Executive summary
        summary = row.get("executive_summary", "")
        if summary:
            st.info(f"**Executive Summary:** {summary}")

        # IOCs
        try:
            iocs = json.loads(row.get("iocs", "[]"))
            if iocs:
                st.markdown("**Indicators of Compromise:**")
                for ioc in iocs:
                    st.markdown(f"- `{ioc}`")
        except Exception:
            pass

        # Remediation
        try:
            rem = json.loads(row.get("remediation", "[]"))
            if rem:
                st.markdown("**Remediation Steps:**")
                for i, step in enumerate(rem, 1):
                    st.markdown(f"{i}. {step}")
        except Exception:
            pass

        # Full report
        report = row.get("full_report", "")
        if report:
            st.markdown("---")
            st.markdown("**Full Incident Report:**")
            st.markdown(report)

# ── Export ────────────────────────────────────────────────────────────────────
st.markdown("---")
if st.button("📥 Export all reports as CSV"):
    csv = filtered[["alert_id","timestamp","src_ip","dst_port","threat_class",
                     "severity","anomaly_score","severity_score","mitre_id",
                     "cve_count","executive_summary","created_at"]].to_csv(index=False)
    st.download_button("Download CSV", csv, "incident_reports.csv", "text/csv")
