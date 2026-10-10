"""
agent/investigation_agent.py
-----------------------------
LangGraph investigation agent for cybersecurity threat analysis.

Graph flow:
    ingest_alert
        → classify_threat
        → check_threat_intel
        → query_cve_rag
        → mitre_mapping
        → score_severity
        → generate_report
        → route_severity
            → [Critical] alert_human  → END
            → [Other]    store_report → END

Each node reads from AgentState, does its work, and writes back.
"""

import os
import json
import uuid
import requests
import sqlite3
from datetime import datetime
from typing import Optional, List
from typing_extensions import TypedDict

from langgraph.graph import StateGraph, END

# Try importing Ollama — graceful fallback if not running
try:
    from langchain_ollama import ChatOllama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

OLLAMA_URL   = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
DB_PATH      = "reports/alerts.db"

os.makedirs("reports", exist_ok=True)


# ─── Agent State ──────────────────────────────────────────────────────────────

class AgentState(TypedDict):
    """
    Shared state across all investigation nodes.
    Every node reads from this and writes back to it.
    Think of it as the agent's working notepad.
    """
    # Input
    alert:                  dict

    # Classification results
    threat_class:           str
    confidence:             float
    technique_hypothesis:   str

    # Investigation results
    threat_intel:           dict
    cve_matches:            List[dict]
    mitre_technique:        dict
    correlated_alerts:      List[dict]

    # Scoring
    final_severity:         str
    severity_score:         float

    # Report
    incident_report:        str
    iocs:                   List[str]
    remediation_steps:      List[str]
    executive_summary:      str

    # Control
    should_alert_human:     bool
    investigation_done:     bool
    error_log:              List[str]


# ─── LLM Setup ────────────────────────────────────────────────────────────────

def get_llm():
    """Get Ollama LLM — returns None if Ollama not running."""
    if not OLLAMA_AVAILABLE:
        return None
    try:
        llm = ChatOllama(
            model       = OLLAMA_MODEL,
            base_url    = OLLAMA_URL,
            temperature = 0.1,
            timeout     = 120,
        )
        return llm
    except Exception:
        return None


def llm_invoke(prompt: str, expect_json: bool = False) -> str:
    """Call Ollama with fallback for when it's not running."""
    llm = get_llm()
    if llm is None:
        if expect_json:
            return '{"error": "Ollama not available"}'
        return "Ollama not running. Install Ollama and pull mistral to enable AI analysis."

    try:
        response = llm.invoke(prompt)
        return response.content
    except Exception as e:
        if expect_json:
            return json.dumps({"error": str(e)})
        return f"LLM error: {str(e)}"


# ─── Node: Ingest Alert ───────────────────────────────────────────────────────

def ingest_alert_node(state: AgentState) -> AgentState:
    """
    Entry node — validate and prepare the alert for investigation.
    Sets up the initial state for downstream nodes.
    """
    alert = state["alert"]
    print(f"[Agent] Investigating alert {alert.get('alert_id')} | {alert.get('severity')} | {alert.get('src_ip')}")

    # Set safe defaults for all state fields
    state["threat_class"]         = "unknown"
    state["confidence"]           = 0.0
    state["technique_hypothesis"] = ""
    state["threat_intel"]         = {}
    state["cve_matches"]          = []
    state["mitre_technique"]      = {}
    state["correlated_alerts"]    = []
    state["final_severity"]       = alert.get("severity", "Medium")
    state["severity_score"]       = alert.get("anomaly_score", 0.5)
    state["incident_report"]      = ""
    state["iocs"]                 = [alert.get("src_ip", "")]
    state["remediation_steps"]    = []
    state["executive_summary"]    = ""
    state["should_alert_human"]   = False
    state["investigation_done"]   = False
    state["error_log"]            = []

    return state


# ─── Node: Classify Threat ────────────────────────────────────────────────────

def classify_threat_node(state: AgentState) -> AgentState:
    """
    Classify the attack type using rule-based hint + Ollama confirmation.
    Writes: threat_class, confidence, technique_hypothesis
    """
    alert = state["alert"]
    hint  = alert.get("attack_type_hint", "unknown")
    top_f = alert.get("top_features", [])

    prompt = f"""You are a cybersecurity analyst. Classify this network security alert.

Alert Details:
- Source IP: {alert.get('src_ip')}
- Destination Port: {alert.get('dst_port')}
- Anomaly Score: {alert.get('anomaly_score', 0):.3f}
- Initial classification hint: {hint}
- Top anomalous features: {top_f}
- Feature values: {json.dumps(alert.get('feature_values', {}), indent=2)}

Possible threat classes: port_scan, brute_force, data_exfil, lateral_movement, c2_beacon, ddos, unknown

Respond with ONLY a valid JSON object. No markdown, no explanation, just JSON:
{{"threat_class": "brute_force", "confidence": 0.92, "technique": "Repeated SSH authentication failures indicating automated password guessing"}}"""

    response = llm_invoke(prompt, expect_json=True)

    try:
        # Strip any markdown code blocks if present
        clean = response.strip().strip("```json").strip("```").strip()
        parsed = json.loads(clean)
        state["threat_class"]         = parsed.get("threat_class", hint)
        state["confidence"]           = float(parsed.get("confidence", 0.7))
        state["technique_hypothesis"] = parsed.get("technique", "")
    except (json.JSONDecodeError, ValueError):
        # Fallback to rule-based hint
        state["threat_class"]         = hint
        state["confidence"]           = 0.6
        state["technique_hypothesis"] = f"Rule-based classification: {hint}"
        state["error_log"].append("LLM classification parse failed — using rule-based hint")

    print(f"[Agent] Classified as: {state['threat_class']} (confidence: {state['confidence']:.2f})")
    return state


# ─── Node: Check Threat Intel ─────────────────────────────────────────────────

def check_threat_intel_node(state: AgentState) -> AgentState:
    """
    Query AbuseIPDB for IP reputation.
    Writes: threat_intel dict
    """
    src_ip = state["alert"].get("src_ip", "")

    # Skip private/internal IPs
    if src_ip.startswith(("192.168.", "10.", "172.16.", "127.", "::1")):
        state["threat_intel"] = {
            "src_ip":              src_ip,
            "is_known_malicious":  False,
            "abuse_score":         0,
            "total_reports":       0,
            "country":             "Internal",
            "note":                "Internal IP — skipped AbuseIPDB check",
        }
        return state

    if not ABUSEIPDB_KEY:
        # No API key — use demo data for known malicious IPs
        known_bad = ["185.220.101.45", "23.129.64.214", "162.247.74.27",
                     "199.87.154.255", "178.73.215.171"]
        is_bad = src_ip in known_bad
        state["threat_intel"] = {
            "src_ip":              src_ip,
            "is_known_malicious":  is_bad,
            "abuse_score":         87 if is_bad else 5,
            "total_reports":       47 if is_bad else 0,
            "country":             "Unknown",
            "note":                "Demo mode — add ABUSEIPDB_API_KEY to .env for live lookups",
        }
        return state

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params  = {"ipAddress": src_ip, "maxAgeInDays": 30},
            headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout = 10,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})

        state["threat_intel"] = {
            "src_ip":              src_ip,
            "is_known_malicious":  data.get("abuseConfidenceScore", 0) > 50,
            "abuse_score":         data.get("abuseConfidenceScore", 0),
            "total_reports":       data.get("totalReports", 0),
            "country":             data.get("countryCode", "Unknown"),
            "isp":                 data.get("isp", "Unknown"),
            "last_reported":       data.get("lastReportedAt", ""),
        }

        if state["threat_intel"]["is_known_malicious"]:
            state["iocs"].append(f"Known malicious IP: {src_ip} (abuse score: {state['threat_intel']['abuse_score']})")

    except requests.exceptions.RequestException as e:
        state["threat_intel"] = {
            "src_ip":   src_ip,
            "error":    str(e),
            "note":     "AbuseIPDB lookup failed",
        }
        state["error_log"].append(f"Threat intel lookup failed: {e}")

    print(f"[Agent] Threat intel: abuse_score={state['threat_intel'].get('abuse_score', 'N/A')}")
    return state


# ─── Node: Query CVE RAG ──────────────────────────────────────────────────────

def query_cve_rag_node(state: AgentState, kb=None) -> AgentState:
    """
    Search the CVE knowledge base for matching vulnerabilities.
    Writes: cve_matches list
    """
    if kb is None:
        from rag.cve_knowledge_base import CVEKnowledgeBase
        kb = CVEKnowledgeBase()

    attack_type = state["threat_class"]
    dst_port    = int(state["alert"].get("dst_port", 0))

    cve_matches = kb.query(attack_type=attack_type, dst_port=dst_port, top_k=5)
    state["cve_matches"] = cve_matches

    # Add high-severity CVEs to IOCs
    for cve in cve_matches:
        if cve.get("cvss", 0) >= 9.0:
            state["iocs"].append(f"High-severity CVE: {cve['cve_id']} (CVSS {cve['cvss']})")

    print(f"[Agent] Found {len(cve_matches)} matching CVEs. Top: {cve_matches[0]['cve_id'] if cve_matches else 'none'}")
    return state


# ─── Node: MITRE Mapping ──────────────────────────────────────────────────────

def mitre_mapping_node(state: AgentState, kb=None) -> AgentState:
    """
    Map the detected attack to MITRE ATT&CK framework.
    Writes: mitre_technique dict
    """
    if kb is None:
        from rag.cve_knowledge_base import CVEKnowledgeBase
        kb = CVEKnowledgeBase()

    technique = kb.get_mitre_technique(state["threat_class"])
    state["mitre_technique"] = technique
    print(f"[Agent] MITRE: {technique['id']} — {technique['name']} ({technique['tactic']})")
    return state


# ─── Node: Score Severity ─────────────────────────────────────────────────────

def score_severity_node(state: AgentState) -> AgentState:
    """
    Compute final severity by combining multiple signals.
    Writes: final_severity, severity_score
    """
    alert       = state["alert"]
    base_score  = float(alert.get("anomaly_score", 0.5))
    intel       = state["threat_intel"]
    cves        = state["cve_matches"]

    # Signals that increase severity
    boost = 0.0
    if intel.get("is_known_malicious"):
        boost += 0.15
    if intel.get("abuse_score", 0) > 75:
        boost += 0.05
    if cves and cves[0].get("cvss", 0) >= 9.0:
        boost += 0.10
    if state["threat_class"] in ["data_exfil", "lateral_movement", "c2_beacon"]:
        boost += 0.10

    final_score = min(1.0, base_score + boost)
    state["severity_score"] = round(final_score, 4)

    if final_score >= 0.85:
        state["final_severity"]    = "Critical"
        state["should_alert_human"] = True
    elif final_score >= 0.70:
        state["final_severity"]    = "High"
    elif final_score >= 0.55:
        state["final_severity"]    = "Medium"
    else:
        state["final_severity"]    = "Low"

    print(f"[Agent] Final severity: {state['final_severity']} (score: {final_score:.3f})")
    return state


# ─── Node: Generate Report ────────────────────────────────────────────────────

def generate_report_node(state: AgentState) -> AgentState:
    """
    Generate a structured incident report using Ollama.
    Writes: incident_report, executive_summary, remediation_steps
    """
    alert   = state["alert"]
    mitre   = state["mitre_technique"]
    intel   = state["threat_intel"]
    cves    = state["cve_matches"][:3]
    cve_str = "\n".join([f"  - {c['cve_id']} (CVSS {c['cvss']}): {c['description'][:100]}..." for c in cves]) or "  None found"

    prompt = f"""You are a senior cybersecurity analyst writing an incident report. Be precise and professional.

ALERT SUMMARY:
- Alert ID: {alert.get('alert_id')}
- Timestamp: {alert.get('timestamp')}
- Source IP: {alert.get('src_ip')} (Country: {intel.get('country', 'Unknown')})
- Destination Port: {alert.get('dst_port')}
- Attack Type: {state['threat_class'].replace('_', ' ').title()}
- Anomaly Score: {alert.get('anomaly_score', 0):.3f}
- Final Severity: {state['final_severity']}
- Confidence: {state['confidence']:.0%}

THREAT INTELLIGENCE:
- IP Known Malicious: {intel.get('is_known_malicious', False)}
- Abuse Score: {intel.get('abuse_score', 0)}/100
- Total Reports: {intel.get('total_reports', 0)}

MITRE ATT&CK:
- Technique: {mitre.get('id', 'N/A')} — {mitre.get('name', 'N/A')}
- Tactic: {mitre.get('tactic', 'N/A')}

MATCHING CVEs:
{cve_str}

TOP ANOMALOUS FEATURES:
{json.dumps(alert.get('top_features', []), indent=2)}

Write a structured incident report with these exact sections:

## Executive Summary
(2-3 sentences summarising the threat for non-technical management)

## Technical Analysis
(Technical details of what was detected and why it's suspicious)

## Indicators of Compromise (IOCs)
(List the specific IOCs: IPs, ports, CVE IDs)

## MITRE ATT&CK Mapping
(Map this to the framework)

## Recommended Remediation Steps
(Numbered list of 5 specific, actionable steps — most urgent first)

## Risk Assessment
(Business impact if left unaddressed)"""

    report = llm_invoke(prompt)

    # If Ollama not available, generate a structured template
    if "Ollama not running" in report or "LLM error" in report:
        report = _generate_template_report(state)

    state["incident_report"] = report

    # Extract executive summary (first paragraph after ## Executive Summary)
    lines = report.split("\n")
    summary_lines = []
    in_summary = False
    for line in lines:
        if "Executive Summary" in line:
            in_summary = True
            continue
        if in_summary and line.startswith("##"):
            break
        if in_summary and line.strip():
            summary_lines.append(line.strip())
    state["executive_summary"] = " ".join(summary_lines[:3])

    # Remediation steps from MITRE
    state["remediation_steps"] = mitre.get("mitigations", [
        "Isolate affected system immediately",
        "Block source IP at perimeter firewall",
        "Review and rotate credentials",
        "Patch vulnerable services",
        "Conduct forensic analysis",
    ])

    print(f"[Agent] Report generated ({len(report)} chars)")
    return state


def _generate_template_report(state: AgentState) -> str:
    """Fallback report when Ollama is not running."""
    alert  = state["alert"]
    mitre  = state["mitre_technique"]
    intel  = state["threat_intel"]
    cves   = state["cve_matches"][:2]

    cve_list = "\n".join([f"- {c['cve_id']} (CVSS {c['cvss']:.1f}): {c['description'][:80]}..." for c in cves])

    return f"""## Executive Summary
A {state['final_severity'].lower()}-severity {state['threat_class'].replace('_', ' ')} attack was detected from {alert.get('src_ip')} targeting port {alert.get('dst_port')}. The anomaly score of {alert.get('anomaly_score', 0):.3f} indicates significant deviation from baseline network behaviour. Immediate investigation is recommended.

## Technical Analysis
The Isolation Forest anomaly detector flagged this connection with a score of {alert.get('anomaly_score', 0):.3f} (threshold: 0.55). The top contributing features were: {alert.get('top_features', [])}. The source IP originates from {intel.get('country', 'Unknown')} with an AbuseIPDB confidence score of {intel.get('abuse_score', 0)}/100.

## Indicators of Compromise (IOCs)
- Source IP: {alert.get('src_ip')} (Abuse Score: {intel.get('abuse_score', 0)}/100)
- Destination Port: {alert.get('dst_port')}
{cve_list}

## MITRE ATT&CK Mapping
- Technique ID: {mitre.get('id', 'N/A')}
- Technique Name: {mitre.get('name', 'N/A')}
- Tactic: {mitre.get('tactic', 'N/A')}
- Description: {mitre.get('description', 'N/A')}

## Recommended Remediation Steps
1. Block source IP {alert.get('src_ip')} at perimeter firewall immediately
2. Investigate all systems that communicated with this IP in the last 24 hours
3. Review authentication logs on destination systems for successful logins
4. Apply patches for matching CVEs: {', '.join([c['cve_id'] for c in cves])}
5. Enable enhanced logging on affected systems and monitor for follow-up activity

## Risk Assessment
If this {state['threat_class'].replace('_', ' ')} attack is successful, potential impacts include: unauthorized system access, lateral movement to sensitive systems, and potential data exfiltration. Severity: {state['final_severity']}.

---
*Note: Install and run Ollama (ollama pull mistral) for AI-enhanced analysis*"""


# ─── Node: Route by Severity ──────────────────────────────────────────────────

def route_severity(state: AgentState) -> str:
    """
    Conditional edge function — determines next node based on severity.
    Returns the name of the next node.
    """
    if state["should_alert_human"]:
        return "alert_human"
    return "store_report"


# ─── Node: Alert Human ────────────────────────────────────────────────────────

def alert_human_node(state: AgentState) -> AgentState:
    """
    For Critical alerts — print urgent notification.
    In production: send Slack message, email, PagerDuty alert.
    """
    alert = state["alert"]
    print("\n" + "="*60)
    print("🚨 CRITICAL ALERT — HUMAN REVIEW REQUIRED")
    print(f"   Alert ID:  {alert.get('alert_id')}")
    print(f"   Source IP: {alert.get('src_ip')}")
    print(f"   Attack:    {state['threat_class']}")
    print(f"   Score:     {state['severity_score']:.3f}")
    print(f"   Summary:   {state['executive_summary'][:100]}...")
    print("="*60 + "\n")

    state["investigation_done"] = True
    return store_report_node(state)


# ─── Node: Store Report ───────────────────────────────────────────────────────

def store_report_node(state: AgentState) -> AgentState:
    """Save the incident report to SQLite database."""
    _init_db()
    alert = state["alert"]

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT OR REPLACE INTO incidents
            (alert_id, timestamp, src_ip, dst_port, threat_class, severity,
             anomaly_score, severity_score, mitre_id, cve_count, executive_summary,
             full_report, iocs, remediation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.get("alert_id"),
            alert.get("timestamp"),
            alert.get("src_ip"),
            alert.get("dst_port"),
            state["threat_class"],
            state["final_severity"],
            alert.get("anomaly_score"),
            state["severity_score"],
            state["mitre_technique"].get("id", ""),
            len(state["cve_matches"]),
            state["executive_summary"],
            state["incident_report"],
            json.dumps(state["iocs"]),
            json.dumps(state["remediation_steps"]),
        ))
        conn.commit()
        conn.close()
        print(f"[Agent] Report saved to database")
    except Exception as e:
        state["error_log"].append(f"DB save failed: {e}")
        print(f"[Agent] DB save failed: {e}")

    state["investigation_done"] = True
    return state


def _init_db():
    """Create the SQLite incidents table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            alert_id        TEXT PRIMARY KEY,
            timestamp       TEXT,
            src_ip          TEXT,
            dst_port        INTEGER,
            threat_class    TEXT,
            severity        TEXT,
            anomaly_score   REAL,
            severity_score  REAL,
            mitre_id        TEXT,
            cve_count       INTEGER,
            executive_summary TEXT,
            full_report     TEXT,
            iocs            TEXT,
            remediation     TEXT,
            created_at      TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()


# ─── Build the LangGraph ──────────────────────────────────────────────────────

def build_investigation_graph(kb=None):
    """
    Assemble the LangGraph investigation graph.

    Nodes:
        ingest_alert → classify_threat → check_threat_intel →
        query_cve_rag → mitre_mapping → score_severity →
        generate_report → [Critical: alert_human | Other: store_report] → END

    Returns
    -------
    Compiled LangGraph graph ready for .invoke()
    """
    graph = StateGraph(AgentState)

    # Register all nodes
    graph.add_node("ingest_alert",        ingest_alert_node)
    graph.add_node("classify_threat",     classify_threat_node)
    graph.add_node("check_threat_intel",  check_threat_intel_node)
    graph.add_node("query_cve_rag",       lambda s: query_cve_rag_node(s, kb))
    graph.add_node("mitre_mapping",       lambda s: mitre_mapping_node(s, kb))
    graph.add_node("score_severity",      score_severity_node)
    graph.add_node("generate_report",     generate_report_node)
    graph.add_node("alert_human",         alert_human_node)
    graph.add_node("store_report",        store_report_node)

    # Define edges (normal flow)
    graph.set_entry_point("ingest_alert")
    graph.add_edge("ingest_alert",       "classify_threat")
    graph.add_edge("classify_threat",    "check_threat_intel")
    graph.add_edge("check_threat_intel", "query_cve_rag")
    graph.add_edge("query_cve_rag",      "mitre_mapping")
    graph.add_edge("mitre_mapping",      "score_severity")
    graph.add_edge("score_severity",     "generate_report")

    # Conditional edge: Critical → alert_human, else → store_report
    graph.add_conditional_edges(
        "generate_report",
        route_severity,
        {
            "alert_human": "alert_human",
            "store_report": "store_report",
        }
    )

    graph.add_edge("alert_human",  END)
    graph.add_edge("store_report", END)

    return graph.compile()


# ─── High-level investigation function ────────────────────────────────────────

def investigate_alert(alert_dict: dict, kb=None) -> dict:
    """
    Run the full investigation graph on a single alert.

    Parameters
    ----------
    alert_dict : AlertEvent.to_dict() output
    kb         : CVEKnowledgeBase instance (reused across calls)

    Returns
    -------
    Final AgentState dict with incident_report and all findings
    """
    graph = build_investigation_graph(kb)
    initial_state = AgentState(alert=alert_dict)
    result = graph.invoke(initial_state)
    return result
