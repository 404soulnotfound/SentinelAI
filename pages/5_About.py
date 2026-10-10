"""
pages/5_About.py
-----------------
Portfolio explainer for recruiters and hiring managers.
"""

import streamlit as st

st.set_page_config(page_title="About", page_icon="📄", layout="wide")
st.markdown("""
<style>
.stApp { background-color: #080d14; }
.section { font-family:'Courier New',monospace;font-size:1.4rem;font-weight:700;
           color:#00ff88;letter-spacing:2px;margin-bottom:4px }
.insight { background:#0d1520;border-left:3px solid #00ff88;border-radius:0 8px 8px 0;
           padding:0.9rem 1.1rem;margin-bottom:10px }
.insight .lbl { font-size:10px;color:#00ff88;font-weight:700;text-transform:uppercase;
                letter-spacing:1px;margin-bottom:3px }
.insight p { font-size:13px;color:#8090a0;line-height:1.65;margin:0 }
.qa { border:0.5px solid #1a2a3a;border-radius:8px;margin-bottom:10px;overflow:hidden }
.qa-q { padding:10px 14px;background:#0d1520;font-size:13px;font-weight:500;
        color:#c0d0e0;cursor:pointer;display:flex;justify-content:space-between }
.qa-a { padding:12px 14px;font-size:13px;color:#8090a0;line-height:1.65;display:none }
.qa-a.open { display:block }
.skill-badge { display:inline-block;background:#0d1520;border:1px solid #1a3a2a;
               border-radius:20px;padding:4px 12px;font-size:0.8rem;color:#6080a0;margin:3px }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<p style="font-family:'Courier New',monospace;font-size:2.2rem;font-weight:900;
color:#00ff88;letter-spacing:3px;line-height:1.1;margin-bottom:4px">
🛡️ THREAT INTELLIGENCE AGENT<br>
<span style="font-size:1rem;color:#4a9eff;letter-spacing:2px">PORTFOLIO PROJECT — TECHNICAL EXPLAINER</span>
</p>
""", unsafe_allow_html=True)

st.markdown("---")

# ── One-liners ─────────────────────────────────────────────────────────────────
st.markdown('<p class="section">WHAT IT IS</p>', unsafe_allow_html=True)

st.markdown("""
**To a friend:** "I built an AI that watches network traffic, automatically spots hackers, 
investigates what they're doing, and writes a full security report — all without any human involved."

**To a recruiter:** "A fully autonomous cybersecurity threat intelligence system combining 
Isolation Forest anomaly detection with a LangGraph multi-node investigation agent. 
It detects anomalous network behaviour, classifies the attack type using Ollama (local LLM), 
retrieves matching CVEs from a ChromaDB knowledge base, maps to MITRE ATT&CK, and generates 
a structured incident report with remediation steps — entirely on-premise, zero cloud dependency."
""")

st.markdown("---")
st.markdown('<p class="section">HOW IT WORKS</p>', unsafe_allow_html=True)

layers = [
    ("🔍 Layer 1 — Isolation Forest (Detection)",
     "Trained on baseline normal network traffic. Scores every new connection 0-1 using path length through random decision trees. Short path = anomaly (rare + different). Produces SHAP explanations showing which features drove each alert — e.g. 'failed_conn_rate spiked to 0.96, conn_rate = 287 per minute'."),
    ("🤖 Layer 2 — LangGraph (Investigation)",
     "8-node directed graph agent. Each node is a specific investigation action: classify attack type → check IP reputation → query CVE database → map to MITRE ATT&CK → score final severity → generate report. Conditional edges route Critical alerts to immediate human notification. The agent reads from and writes to a shared AgentState TypedDict."),
    ("🧠 Layer 3 — Ollama + Mistral (Language AI)",
     "Local Mistral 7B model handles natural language reasoning. Classifies attack type from feature descriptions, writes structured incident reports in markdown, and generates contextualised remediation steps. Runs entirely on-premise — no data leaves the network."),
    ("📚 Layer 4 — ChromaDB RAG (Knowledge)",
     "20+ recent CVE records embedded locally using nomic-embed-text. Semantic search finds CVEs matching any attack pattern even with different wording. Includes MITRE ATT&CK technique library and port-to-vulnerability mappings."),
]

for title, desc in layers:
    st.markdown(f"""
    <div class="insight">
        <div class="lbl">{title}</div>
        <p>{desc}</p>
    </div>""", unsafe_allow_html=True)

st.markdown("---")
st.markdown('<p class="section">WHY THE TECHNICAL CHOICES MATTER</p>', unsafe_allow_html=True)

decisions = [
    ("Why Isolation Forest instead of a supervised model?",
     "Supervised models (Random Forest, XGBoost) need labelled attack data. On a real network, you don't have labels for your specific traffic — and attack patterns change constantly. Isolation Forest learns what 'normal' looks like and flags anything that deviates. It catches attack types it has never seen before."),
    ("Why run locally with Ollama instead of GPT-4?",
     "Network logs contain internal IP addresses, server names, usernames, and system architecture details. Sending this to an external API violates enterprise security policies in most regulated industries. Ollama runs the model on your hardware — zero data leaves the network. This is what makes the tool actually deployable."),
    ("Why LangGraph instead of a single LLM prompt?",
     "A single prompt would hallucinate CVE IDs, couldn't call real APIs, and couldn't make conditional decisions. LangGraph defines the investigation as an explicit graph — each step is a verified action (real API call, real database query). The agent can branch: Critical alerts go to immediate human notification, others are batched."),
    ("Why ChromaDB + semantic search instead of SQL lookup?",
     "CVE descriptions use varied technical language. 'SSH brute force' and 'repeated failed authentication attempts on port 22' describe the same thing. SQL LIKE queries miss this. Semantic search with embeddings finds conceptually similar CVEs regardless of exact wording."),
    ("Why SHAP for explanations?",
     "Isolation Forest tells you THAT something is anomalous. It doesn't tell you WHY. SHAP shows which features contributed most to the anomaly score — 'failed_conn_rate contributed +0.61, conn_rate contributed +0.28'. This context goes into the LangGraph agent state and makes the Ollama-generated report significantly more specific and accurate."),
]

for q, a in decisions:
    st.markdown(f"""
    <div class="qa">
        <div class="qa-q">🤔 {q}</div>
        <div class="qa-a">{a}</div>
    </div>""", unsafe_allow_html=True)

st.markdown("---")
st.markdown('<p class="section">SKILLS DEMONSTRATED</p>', unsafe_allow_html=True)

col1, col2 = st.columns(2)
with col1:
    st.markdown("**Machine Learning & Data Science**")
    ml_skills = ["Unsupervised anomaly detection","Isolation Forest algorithm","Feature engineering from raw logs",
                 "Rolling window aggregation","SHAP explainability","Model persistence (joblib)",
                 "Precision/recall/F1 evaluation","Threshold tuning","Contamination parameter analysis"]
    for s in ml_skills:
        st.markdown(f'<span class="skill-badge">✓ {s}</span>', unsafe_allow_html=True)

with col2:
    st.markdown("**AI Agents & LLM Engineering**")
    llm_skills = ["LangGraph stateful agent design","Multi-node graph architecture","Conditional edge routing",
                  "TypedDict agent state management","RAG with ChromaDB","Local LLM with Ollama",
                  "Structured JSON output from LLMs","LangChain document embedding",
                  "Tool calling (AbuseIPDB, NVD API)"]
    for s in llm_skills:
        st.markdown(f'<span class="skill-badge">✓ {s}</span>', unsafe_allow_html=True)

st.markdown("---")
st.markdown('<p class="section">HONEST LIMITATIONS</p>', unsafe_allow_html=True)

limits = [
    ("Training data is synthetic",
     "The anomaly detector is trained on generated network traffic, not real enterprise logs. On a real deployment, you'd train on 2-4 weeks of your actual network's baseline traffic. The model architecture and feature engineering are production-ready — only the training data is simulated."),
    ("CVE database is curated, not complete",
     "The knowledge base contains ~20 high-severity CVEs rather than the full 200k+ NVD database. The NVD API integration exists in the code — enabling it with an API key populates the full database. The curated set demonstrates the RAG architecture effectively for portfolio purposes."),
    ("Ollama report quality depends on hardware",
     "On CPU-only hardware, Mistral 7B inference takes 30-90 seconds per report. On a GPU, this drops to 3-8 seconds. The template fallback ensures the system functions even when Ollama is not running."),
    ("No live network tap",
     "The system processes CSV log files rather than tapping a live network interface. Production deployment would require integration with a SIEM or packet capture tool to feed live events. The detection and investigation pipeline is identical regardless of input source."),
]

for title, desc in limits:
    st.markdown(f"""
    <div style="background:#0d1520;border:0.5px solid #1a2a3a;border-radius:8px;padding:1rem;margin-bottom:8px">
        <div style="color:#ffaa00;font-size:0.8rem;font-weight:500;margin-bottom:4px">⚠️ {title}</div>
        <div style="color:#6080a0;font-size:0.85rem;line-height:1.6">{desc}</div>
    </div>""", unsafe_allow_html=True)

st.markdown("---")
st.markdown('<p class="section">BUILT BY</p>', unsafe_allow_html=True)
st.markdown("""
<div style="background:#0d1520;border:1px solid #1a2a3a;border-radius:10px;padding:1.5rem">
    <div style="font-size:1.2rem;font-weight:700;color:#c0d0e0;margin-bottom:8px">Your Name Here</div>
    <div style="color:#6080a0;font-size:0.9rem;line-height:2">
        Data Scientist / ML Engineer<br>
        📧 your.email@gmail.com<br>
        🐙 github.com/yourusername<br>
        💼 linkedin.com/in/yourprofile
    </div>
    <div style="margin-top:12px;color:#3a4a5a;font-size:0.8rem">
        Stack: Python · Scikit-learn · LangGraph · LangChain · Ollama · ChromaDB · SHAP · Streamlit<br>
        Data: Synthetic network logs calibrated from CICIDS 2017 dataset patterns<br>
        Not affiliated with any security vendor. Portfolio project.
    </div>
</div>
""", unsafe_allow_html=True)
