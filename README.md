# 🛡️ Cybersecurity Threat Intelligence Agent

> Autonomous threat detection and investigation system combining Isolation Forest anomaly detection with a LangGraph multi-node investigation agent, CVE RAG knowledge base, and Ollama local LLM. Everything runs on your machine — no data leaves your network.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.35-red)
![LangGraph](https://img.shields.io/badge/LangGraph-0.1-orange)
![Ollama](https://img.shields.io/badge/Ollama-Local_LLM-green)

---

## What it does

| Layer | Tool | Role |
|---|---|---|
| 🔍 Detection | Isolation Forest + SHAP | Scores network events 0–1, flags anomalies, explains why |
| 🤖 Investigation | LangGraph (8 nodes) | Autonomous multi-step investigation agent |
| 🧠 Language AI | Ollama + Mistral 7B | Local LLM for classification and report writing |
| 📚 Knowledge | ChromaDB + CVE RAG | Semantic search over CVE vulnerability database |
| 🗺️ Framework | MITRE ATT&CK | Industry-standard attack technique mapping |
| 📊 Dashboard | Streamlit | Live monitoring and incident report browser |

**Detects:** Port scans · Brute force · Data exfiltration · Lateral movement · C2 beacons · DDoS

---

## Project structure

```
threat_agent/
├── app.py                          # Streamlit homepage
├── train.py                        # One-time setup script
├── requirements.txt
├── .env.example                    # Copy to .env and fill in keys
│
├── data/
│   ├── log_generator.py            # Synthetic network log generator
│   └── feature_engineer.py        # Rolling-window feature engineering
│
├── models/
│   └── detector.py                 # Isolation Forest + SHAP + AlertEvent
│
├── rag/
│   └── cve_knowledge_base.py       # ChromaDB + CVE records + MITRE ATT&CK
│
├── agent/
│   └── investigation_agent.py      # LangGraph graph — all 8 nodes + edges
│
├── pages/
│   ├── 1_Live_Monitor.py           # Real-time detection dashboard
│   ├── 2_Investigate_Alert.py      # LangGraph investigation UI
│   ├── 3_Incident_Reports.py       # Browse saved reports
│   ├── 4_Model_Analysis.py         # Isolation Forest internals
│   └── 5_About.py                  # Portfolio explainer
│
├── saved_models/                   # Trained detector (auto-created)
├── cve_knowledge_base/             # ChromaDB store (auto-created)
├── reports/                        # SQLite incident database (auto-created)
└── logs_sample/                    # Sample network logs (auto-created)
```

---

## Quick start (5 commands)

```bash
# 1. Clone the repo
git clone https://github.com/YOURNAME/threat-intelligence-agent
cd threat-intelligence-agent

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Mac/Linux
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Train model + build knowledge base
python train.py

# 5. Launch the app
streamlit run app.py
```

Open your browser at **http://localhost:8501**

---

## Optional: Enable full AI reports with Ollama

Without Ollama, the system uses structured template reports. With Ollama, reports are AI-generated.

```bash
# Install Ollama from https://ollama.com
ollama pull mistral              # Main reasoning model (4.1GB)
ollama pull nomic-embed-text     # Embedding model for RAG (274MB)
```

Then restart the app. The homepage shows ✓ Running when Ollama is detected.

---

## Optional: Live IP reputation with AbuseIPDB

```bash
cp .env.example .env
# Edit .env and add your free API key from abuseipdb.com
```

Without the key, the system uses demo reputation data for known malicious IPs.

---

## How the LangGraph investigation works

```
Alert received
    │
    ▼
ingest_alert ──→ classify_threat ──→ check_threat_intel
                                              │
                                              ▼
                              query_cve_rag ──→ mitre_mapping
                                                      │
                                                      ▼
                              score_severity ──→ generate_report
                                                      │
                              ┌───────────────────────┤
                              ▼                       ▼
                        [Critical]              [High/Med/Low]
                        alert_human             store_report
                              │                       │
                              └───────────────→ END ←─┘
```

Each node reads from `AgentState` (shared TypedDict), does its work, and writes back. Conditional edges route Critical severity alerts to immediate human notification.

---

## Key concepts implemented

### Isolation Forest — why no labels needed
```python
# Train on CLEAN baseline traffic only
detector.train(df_features[df_features["label"] == "normal"])

# Score any new event — no labels required
# Short isolation path = anomaly (rare + different from normal)
scores = detector.score(new_traffic)
```

### SHAP explanations — why each alert was flagged
```python
# Returns which features drove the anomaly score
# e.g. [("failed_conn_rate", 0.61), ("conn_rate", 0.28), ...]
top_features = detector.explain(alert_row)
```

### LangGraph — stateful multi-step agent
```python
graph = StateGraph(AgentState)
graph.add_node("classify_threat", classify_threat_node)
graph.add_node("query_cve_rag",   lambda s: query_cve_rag_node(s, kb))
graph.add_conditional_edges("generate_report", route_severity,
    {"alert_human": "alert_human", "store_report": "store_report"})
result = graph.compile().invoke(initial_state)
```

### RAG — grounded CVE retrieval
```python
# Semantic search: finds CVEs matching attack pattern
# even if they use different technical wording
cves = kb.query(attack_type="brute_force", dst_port=22, top_k=5)
```

---

## Detection performance (on synthetic test data)

| Attack Type | Detection Rate | Avg Anomaly Score |
|---|---|---|
| Port Scan | ~91% | 0.87 |
| Brute Force | ~89% | 0.84 |
| Data Exfiltration | ~85% | 0.79 |
| Lateral Movement | ~82% | 0.74 |
| C2 Beacon | ~78% | 0.69 |
| False Positive Rate | ~3.2% | — |

*Measured on synthetic CICIDS-calibrated data. Results on real network traffic will vary.*

---

## Sample incident report output

```markdown
## Executive Summary
A critical-severity brute force attack was detected from 185.220.101.45 
targeting SSH (port 22) on internal server 10.0.0.10. The source IP has 
an AbuseIPDB confidence score of 89/100 with 47 prior malicious reports. 
Immediate isolation and credential review is recommended.

## Technical Analysis
Isolation Forest flagged this connection with anomaly score 0.912. 
Top contributing features: failed_conn_rate=0.96 (+0.61 SHAP), 
conn_rate=287/min (+0.28 SHAP). Pattern consistent with automated 
SSH password guessing at ~5 attempts/second.

## MITRE ATT&CK Mapping
- Technique: T1110 — Brute Force
- Tactic: Credential Access

## Matching CVEs
- CVE-2023-38408 (CVSS 9.8): Remote code execution in OpenSSH ssh-agent

## Remediation Steps
1. Block 185.220.101.45 at perimeter firewall immediately
2. Review SSH auth logs for successful logins from this IP
3. Rotate credentials for all accounts on 10.0.0.10
4. Apply OpenSSH patch (CVE-2023-38408)
5. Enable SSH key-based auth, disable password authentication
```

---

## Portfolio talking points

- **Real problem, real tools** — uses the same technical stack (Isolation Forest, LangGraph, MITRE ATT&CK) as production security systems
- **No labels required** — unsupervised anomaly detection works on any network without manual labelling
- **Fully local** — Ollama means zero data leaves the network; critical for enterprise compliance
- **Explainable AI** — SHAP shows exactly which features drove each alert; not a black box
- **Multi-step agent** — LangGraph proves you can build complex, stateful AI workflows with conditional logic

---

## Disclaimer

Portfolio project. Uses synthetic network traffic data. Not affiliated with any security vendor or the MITRE Corporation. Not intended for use in production security environments without additional validation.
