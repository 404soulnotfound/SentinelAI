"""
app.py
------
Cybersecurity Threat Intelligence Agent — Streamlit dashboard.
Run with: streamlit run app.py
"""

import streamlit as st
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from models.detector import AnomalyDetector
from rag.cve_knowledge_base import CVEKnowledgeBase

st.set_page_config(
    page_title = "Threat Intelligence Agent",
    page_icon  = "🛡️",
    layout     = "wide",
    initial_sidebar_state = "expanded",
)

st.markdown("""
<style>
.stApp { background-color: #080d14; }
.hero {
    font-family: 'Courier New', monospace;
    font-size: 2.8rem; font-weight: 900;
    color: #00ff88; letter-spacing: 3px;
    line-height: 1.1; margin-bottom: 0.3rem;
}
.hero-sub { color: #4a9eff; font-size: 1rem; letter-spacing: 2px; margin-bottom: 1.5rem; }
.status-ok  { color: #00ff88; font-weight: 700; }
.status-no  { color: #ff4444; font-weight: 700; }
.status-warn{ color: #ffaa00; font-weight: 700; }
.feat-card {
    background: #0d1520; border: 1px solid #1a2a3a;
    border-radius: 10px; padding: 1.1rem; height: 100%;
}
.feat-icon  { font-size: 1.8rem; margin-bottom: 6px; }
.feat-title { font-weight: 700; color: #e0e8ff; font-size: 0.95rem; margin-bottom: 4px; }
.feat-desc  { color: #6080a0; font-size: 0.82rem; line-height: 1.5; }
div[data-testid="stMetric"] {
    background: #0d1520; border: 1px solid #1a2a3a;
    border-radius: 8px; padding: 0.75rem;
}
</style>
""", unsafe_allow_html=True)

# ─── Hero ─────────────────────────────────────────────────────────────────────
st.markdown('<p class="hero">🛡️ THREAT INTELLIGENCE<br>AGENT</p>', unsafe_allow_html=True)
st.markdown('<p class="hero-sub">ISOLATION FOREST · LANGGRAPH · OLLAMA · CVE RAG · FULLY LOCAL</p>', unsafe_allow_html=True)

st.markdown("""
> **What this is:** A fully autonomous cybersecurity threat detection and investigation system.  
> Isolation Forest monitors network logs for anomalies. LangGraph autonomously investigates each alert —  
> querying CVE databases, checking threat intelligence, mapping to MITRE ATT&CK, and writing incident reports.  
> Everything runs locally with Ollama — no data leaves your network.
""")

st.markdown("---")

# ─── System status ────────────────────────────────────────────────────────────
st.markdown("### 🔧 System Status")

col1, col2, col3, col4 = st.columns(4)

# Detector
detector_ok = AnomalyDetector.is_saved("detector")
col1.markdown(f"""
<div style="background:#0d1520;border:1px solid {'#00ff88' if detector_ok else '#ff4444'};
border-radius:8px;padding:0.9rem;text-align:center">
<div style="font-size:0.7rem;color:#4a6a8a;text-transform:uppercase;letter-spacing:1px">Anomaly Detector</div>
<div class="{'status-ok' if detector_ok else 'status-no'}">{'✓ Trained' if detector_ok else '✗ Not trained'}</div>
</div>""", unsafe_allow_html=True)

# CVE Knowledge Base
kb = CVEKnowledgeBase()
kb_ok = kb.is_built()
col2.markdown(f"""
<div style="background:#0d1520;border:1px solid {'#00ff88' if kb_ok else '#ff4444'};
border-radius:8px;padding:0.9rem;text-align:center">
<div style="font-size:0.7rem;color:#4a6a8a;text-transform:uppercase;letter-spacing:1px">CVE Knowledge Base</div>
<div class="{'status-ok' if kb_ok else 'status-no'}">{'✓ ' + str(kb.count()) + ' CVEs' if kb_ok else '✗ Not built'}</div>
</div>""", unsafe_allow_html=True)

# Ollama
import requests as req
try:
    r = req.get(f"{os.getenv('OLLAMA_BASE_URL','http://localhost:11434')}/api/tags", timeout=2)
    ollama_ok   = r.status_code == 200
    models = [m["name"] for m in r.json().get("models", [])]
    mistral_ok  = any("mistral" in m for m in models)
    ollama_text = "✓ Running" if ollama_ok else "✗ Offline"
    ollama_color= "#00ff88" if ollama_ok else "#ff4444"
except Exception:
    ollama_ok   = False
    mistral_ok  = False
    ollama_text = "✗ Offline"
    ollama_color= "#ff4444"

col3.markdown(f"""
<div style="background:#0d1520;border:1px solid {ollama_color};
border-radius:8px;padding:0.9rem;text-align:center">
<div style="font-size:0.7rem;color:#4a6a8a;text-transform:uppercase;letter-spacing:1px">Ollama LLM</div>
<div style="color:{ollama_color};font-weight:700">{ollama_text}</div>
</div>""", unsafe_allow_html=True)

# Mistral model
col4.markdown(f"""
<div style="background:#0d1520;border:1px solid {'#00ff88' if mistral_ok else '#ffaa00'};
border-radius:8px;padding:0.9rem;text-align:center">
<div style="font-size:0.7rem;color:#4a6a8a;text-transform:uppercase;letter-spacing:1px">Mistral Model</div>
<div class="{'status-ok' if mistral_ok else 'status-warn'}">{'✓ Loaded' if mistral_ok else '⚠ Not pulled'}</div>
</div>""", unsafe_allow_html=True)

# Setup instructions if not ready
if not detector_ok or not kb_ok:
    st.error("⚠️ System not fully set up. Run `python train.py` in your terminal to train the detector and build the CVE knowledge base.")

if not ollama_ok:
    st.warning("⚠️ Ollama is not running. The agent will use template reports instead of AI-generated analysis. Install Ollama and run `ollama pull mistral` for full AI capability.")

st.markdown("---")

# ─── Feature cards ────────────────────────────────────────────────────────────
st.markdown("### 🚀 System Capabilities")

features = [
    ("🔍", "Anomaly Detection",      "Isolation Forest trained on baseline network traffic. Scores every connection 0-1. Flags deviations from normal behaviour with SHAP explanations."),
    ("🤖", "Autonomous Investigation","LangGraph 8-node agent: classify threat → check IP reputation → query CVE database → map to MITRE ATT&CK → score severity → generate report."),
    ("📚", "CVE Knowledge Base",      "20+ recent high-severity CVE records embedded in ChromaDB. Semantic search finds matching vulnerabilities for any attack pattern."),
    ("🧠", "Local AI (Ollama)",       "Mistral 7B runs entirely on your machine. No API keys, no cloud, no data leaving your network. Critical for security compliance."),
    ("🗺️", "MITRE ATT&CK Mapping",   "Every alert mapped to the industry-standard ATT&CK framework — technique ID, tactic, and specific mitigations."),
    ("📊", "Live Dashboard",          "Real-time alert feed, severity distribution, attack timeline, and full markdown incident reports — all in your browser."),
]

cols = st.columns(3)
for i, (icon, title, desc) in enumerate(features):
    with cols[i % 3]:
        st.markdown(f"""
        <div class="feat-card">
            <div class="feat-icon">{icon}</div>
            <div class="feat-title">{title}</div>
            <div class="feat-desc">{desc}</div>
        </div><br>""", unsafe_allow_html=True)

st.markdown("---")

# ─── Quick start ──────────────────────────────────────────────────────────────
st.markdown("### 📋 Quick Start")

steps = [
    ("python train.py",                   "Generate sample logs, train Isolation Forest, build CVE knowledge base"),
    ("Go to → Live Monitor",              "Watch real-time anomaly detection on simulated network traffic"),
    ("Go to → Investigate Alert",         "Trigger a manual investigation and see the full LangGraph agent in action"),
    ("Go to → Incident Reports",          "Browse all generated reports with MITRE mappings and CVE references"),
    ("Go to → Model Analysis",            "Explore feature importances and detection performance metrics"),
]

for i, (cmd, desc) in enumerate(steps, 1):
    st.markdown(f"""
    <div style="display:flex;align-items:center;gap:14px;padding:8px 12px;
    background:#0d1520;border:1px solid #1a2a3a;border-radius:8px;margin-bottom:8px">
        <div style="background:#00ff88;color:#080d14;width:24px;height:24px;
        border-radius:50%;display:flex;align-items:center;justify-content:center;
        font-weight:700;font-size:12px;flex-shrink:0">{i}</div>
        <div>
            <code style="color:#00ff88;font-size:0.85rem">{cmd}</code>
            <div style="color:#4a6a8a;font-size:0.8rem;margin-top:2px">{desc}</div>
        </div>
    </div>""", unsafe_allow_html=True)

st.markdown("---")

# ─── Tech stack ───────────────────────────────────────────────────────────────
st.markdown("### 🛠️ Tech Stack")
stack = [
    ("Isolation Forest", "Anomaly detection — no labels needed"),
    ("LangGraph",        "Multi-node investigation agent"),
    ("LangChain",        "LLM orchestration + RAG pipeline"),
    ("Ollama + Mistral", "Local LLM — zero data leakage"),
    ("ChromaDB",         "Local CVE vector database"),
    ("SHAP",             "Alert explainability"),
    ("MITRE ATT&CK",     "Industry threat framework"),
    ("Streamlit",        "Monitoring dashboard"),
]

scols = st.columns(4)
for i, (name, role) in enumerate(stack):
    with scols[i % 4]:
        st.markdown(f"""
        <div style="background:#0d1520;border:1px solid #1a2a3a;border-radius:8px;
        padding:0.75rem;text-align:center;margin-bottom:8px">
            <div style="color:#e0e8ff;font-weight:700;font-size:0.88rem">{name}</div>
            <div style="color:#4a6a8a;font-size:0.75rem">{role}</div>
        </div>""", unsafe_allow_html=True)

st.markdown("---")
st.caption("🔒 Fully local — no data leaves your machine · Not affiliated with any security vendor · Portfolio project")
