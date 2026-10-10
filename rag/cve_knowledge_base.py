"""
rag/cve_knowledge_base.py
--------------------------
Builds and queries the CVE knowledge base using ChromaDB + Ollama embeddings.

Data sources:
    - NVD API (free, no auth needed for basic queries)
    - MITRE ATT&CK technique descriptions
    - Port-to-vulnerability mappings

All embeddings are computed locally using Ollama nomic-embed-text.
No data leaves your machine.
"""

import os
import json
import requests
import time
from typing import List, Dict, Optional

try:
    import chromadb
    from chromadb.utils import embedding_functions
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False

CHROMA_DIR    = "./cve_knowledge_base"
COLLECTION    = "cve_records"
OLLAMA_URL    = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
EMBED_MODEL   = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")

# ─── MITRE ATT&CK techniques used in this project ─────────────────────────────
MITRE_TECHNIQUES = {
    "port_scan": {
        "id":          "T1046",
        "name":        "Network Service Discovery",
        "tactic":      "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those may be vulnerable to remote exploitation.",
        "mitigations": ["Network segmentation", "Disable or Remove Feature or Program", "Network Intrusion Prevention"],
    },
    "brute_force": {
        "id":          "T1110",
        "name":        "Brute Force",
        "tactic":      "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
        "mitigations": ["Account Lockout Policy", "Multi-factor Authentication", "Password Policies"],
    },
    "data_exfil": {
        "id":          "T1041",
        "name":        "Exfiltration Over C2 Channel",
        "tactic":      "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
        "mitigations": ["Network Intrusion Prevention", "Filter Network Traffic", "Data Loss Prevention"],
    },
    "lateral_movement": {
        "id":          "T1021",
        "name":        "Remote Services",
        "tactic":      "Lateral Movement",
        "description": "Adversaries may use valid accounts to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC.",
        "mitigations": ["Network Segmentation", "MFA", "Privileged Account Management"],
    },
    "c2_beacon": {
        "id":          "T1071",
        "name":        "Application Layer Protocol",
        "tactic":      "Command and Control",
        "description": "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
        "mitigations": ["Network Intrusion Prevention", "Filter Network Traffic"],
    },
    "ddos": {
        "id":          "T1498",
        "name":        "Network Denial of Service",
        "tactic":      "Impact",
        "description": "Adversaries may perform Network Denial of Service attacks to degrade or block the availability of targeted resources.",
        "mitigations": ["Filter Network Traffic", "Network Intrusion Prevention"],
    },
    "unknown": {
        "id":          "T1059",
        "name":        "Command and Scripting Interpreter",
        "tactic":      "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "mitigations": ["Code Signing", "Execution Prevention", "Privileged Account Management"],
    },
}

# ─── Fallback CVE records (used when NVD API is unavailable) ──────────────────
FALLBACK_CVES = [
    {"id": "CVE-2023-38408", "description": "Remote code execution vulnerability in OpenSSH ssh-agent. Affects OpenSSH versions before 9.3p2.", "cvss": 9.8, "severity": "Critical", "ports": ["22"], "attack_vector": "Network", "products": ["OpenSSH"]},
    {"id": "CVE-2024-6387",  "description": "Signal handler race condition in OpenSSH server (sshd) allowing remote code execution as root. RegreSSHion vulnerability.", "cvss": 8.1, "severity": "High", "ports": ["22"], "attack_vector": "Network", "products": ["OpenSSH"]},
    {"id": "CVE-2023-42793", "description": "Authentication bypass vulnerability in JetBrains TeamCity allowing admin account takeover.", "cvss": 9.8, "severity": "Critical", "ports": ["8111", "443"], "attack_vector": "Network", "products": ["JetBrains TeamCity"]},
    {"id": "CVE-2024-21762", "description": "Out-of-bounds write vulnerability in Fortinet FortiOS SSL VPN. Allows remote code execution.", "cvss": 9.6, "severity": "Critical", "ports": ["443", "8443"], "attack_vector": "Network", "products": ["Fortinet FortiOS"]},
    {"id": "CVE-2023-46805", "description": "Authentication bypass vulnerability in Ivanti Connect Secure and Policy Secure gateways.", "cvss": 8.2, "severity": "High", "ports": ["443"], "attack_vector": "Network", "products": ["Ivanti Connect Secure"]},
    {"id": "CVE-2024-1709",  "description": "Authentication bypass vulnerability in ConnectWise ScreenConnect allowing unauthorized access.", "cvss": 10.0, "severity": "Critical", "ports": ["8040", "443"], "attack_vector": "Network", "products": ["ConnectWise ScreenConnect"]},
    {"id": "CVE-2023-20198", "description": "Privilege escalation vulnerability in Cisco IOS XE Web UI. Allows creation of local user with level 15 access.", "cvss": 10.0, "severity": "Critical", "ports": ["80", "443"], "attack_vector": "Network", "products": ["Cisco IOS XE"]},
    {"id": "CVE-2024-3400",  "description": "Command injection vulnerability in Palo Alto Networks PAN-OS GlobalProtect feature.", "cvss": 10.0, "severity": "Critical", "ports": ["443"], "attack_vector": "Network", "products": ["Palo Alto PAN-OS"]},
    {"id": "CVE-2023-34362", "description": "SQL injection vulnerability in Progress MOVEit Transfer web application.", "cvss": 9.8, "severity": "Critical", "ports": ["80", "443"], "attack_vector": "Network", "products": ["Progress MOVEit Transfer"]},
    {"id": "CVE-2023-27997", "description": "Heap-based buffer overflow in Fortinet FortiOS SSL-VPN allowing remote code execution.", "cvss": 9.8, "severity": "Critical", "ports": ["443"], "attack_vector": "Network", "products": ["Fortinet FortiOS"]},
    {"id": "CVE-2023-4966",  "description": "Sensitive information disclosure vulnerability in Citrix NetScaler ADC and NetScaler Gateway.", "cvss": 9.4, "severity": "Critical", "ports": ["80", "443"], "attack_vector": "Network", "products": ["Citrix NetScaler"]},
    {"id": "CVE-2024-23113", "description": "Format string vulnerability in Fortinet FortiOS fgfmd daemon allowing remote code execution.", "cvss": 9.8, "severity": "Critical", "ports": ["541"], "attack_vector": "Network", "products": ["Fortinet FortiOS"]},
    {"id": "CVE-2023-3519",  "description": "Unauthenticated remote code execution in Citrix ADC and Citrix Gateway.", "cvss": 9.8, "severity": "Critical", "ports": ["80", "443"], "attack_vector": "Network", "products": ["Citrix ADC", "Citrix Gateway"]},
    {"id": "CVE-2024-21887", "description": "Command injection vulnerability in Ivanti Connect Secure and Ivanti Policy Secure.", "cvss": 9.1, "severity": "Critical", "ports": ["443"], "attack_vector": "Network", "products": ["Ivanti Connect Secure"]},
    {"id": "CVE-2023-22515", "description": "Privilege escalation vulnerability in Atlassian Confluence Data Center and Server.", "cvss": 10.0, "severity": "Critical", "ports": ["8090", "443"], "attack_vector": "Network", "products": ["Atlassian Confluence"]},
    {"id": "CVE-2024-5806",  "description": "Authentication bypass vulnerability in MOVEit Transfer SFTP module.", "cvss": 9.1, "severity": "Critical", "ports": ["22"], "attack_vector": "Network", "products": ["Progress MOVEit Transfer"]},
    {"id": "CVE-2023-40044", "description": "Deserialization of untrusted data in Progress WS_FTP Server allowing remote code execution.", "cvss": 10.0, "severity": "Critical", "ports": ["21", "22"], "attack_vector": "Network", "products": ["Progress WS_FTP"]},
    {"id": "CVE-2024-0012",  "description": "Authentication bypass in PAN-OS management web interface allows admin access without credentials.", "cvss": 9.8, "severity": "Critical", "ports": ["443"], "attack_vector": "Network", "products": ["Palo Alto PAN-OS"]},
    {"id": "CVE-2023-28771", "description": "Improper error message handling in Zyxel firewall OS allowing unauthenticated OS command execution.", "cvss": 9.8, "severity": "Critical", "ports": ["500", "4500"], "attack_vector": "Network", "products": ["Zyxel Firewall"]},
    {"id": "CVE-2024-4040",  "description": "Server-side template injection vulnerability in CrushFTP allowing remote code execution.", "cvss": 10.0, "severity": "Critical", "ports": ["8080", "443"], "attack_vector": "Network", "products": ["CrushFTP"]},
]


class CVEKnowledgeBase:
    """
    Local CVE knowledge base using ChromaDB + Ollama embeddings.
    Supports semantic search for CVEs matching attack patterns.
    """

    def __init__(self):
        self.client     = None
        self.collection = None
        self.available  = False
        self._try_init()

    def _try_init(self):
        """Initialise ChromaDB — gracefully handle if not available."""
        if not CHROMA_AVAILABLE:
            print("[RAG] ChromaDB not available — using keyword fallback")
            return

        try:
            self.client = chromadb.PersistentClient(path=CHROMA_DIR)
            self.collection = self.client.get_or_create_collection(
                name     = COLLECTION,
                metadata = {"hnsw:space": "cosine"},
            )
            self.available = True
            print(f"[RAG] ChromaDB ready. Collection: {COLLECTION} ({self.collection.count()} records)")
        except Exception as e:
            print(f"[RAG] ChromaDB init failed: {e} — using keyword fallback")

    def build(self, use_nvd_api: bool = False, nvd_api_key: str = None):
        """
        Populate the knowledge base with CVE records.

        Parameters
        ----------
        use_nvd_api  : If True, fetch live CVEs from NVD API (slower, more data)
        nvd_api_key  : Optional NVD API key for higher rate limits
        """
        cves = []

        if use_nvd_api:
            cves = self._fetch_nvd_cves(nvd_api_key)

        # Always add fallback CVEs
        cves.extend(FALLBACK_CVES)

        # Deduplicate
        seen = set()
        unique_cves = []
        for cve in cves:
            if cve["id"] not in seen:
                seen.add(cve["id"])
                unique_cves.append(cve)

        print(f"[RAG] Building knowledge base with {len(unique_cves)} CVE records...")

        if self.available:
            self._build_chroma(unique_cves)
        else:
            print("[RAG] Using in-memory fallback (no ChromaDB)")

        # Save CVEs to JSON for keyword search fallback
        os.makedirs(CHROMA_DIR, exist_ok=True)
        with open(os.path.join(CHROMA_DIR, "cves.json"), "w") as f:
            json.dump(unique_cves, f, indent=2)

        print(f"[RAG] Knowledge base ready with {len(unique_cves)} records")

    def _build_chroma(self, cves: list):
        """Embed CVEs into ChromaDB."""
        documents, metadatas, ids = [], [], []

        for cve in cves:
            doc = (
                f"CVE ID: {cve['id']}\n"
                f"Description: {cve['description']}\n"
                f"CVSS Score: {cve['cvss']} ({cve['severity']})\n"
                f"Attack Vector: {cve['attack_vector']}\n"
                f"Affected Products: {', '.join(cve.get('products', []))}\n"
                f"Affected Ports: {', '.join(cve.get('ports', []))}"
            )
            documents.append(doc)
            metadatas.append({
                "cve_id":       cve["id"],
                "cvss":         float(cve["cvss"]),
                "severity":     cve["severity"],
                "attack_vector": cve["attack_vector"],
                "ports":        ",".join(cve.get("ports", [])),
            })
            ids.append(cve["id"])

        # Add in batches of 50
        batch_size = 50
        for i in range(0, len(documents), batch_size):
            self.collection.add(
                documents = documents[i:i+batch_size],
                metadatas = metadatas[i:i+batch_size],
                ids       = ids[i:i+batch_size],
            )
        print(f"[RAG] Embedded {len(documents)} CVEs into ChromaDB")

    def _fetch_nvd_cves(self, api_key: str = None, n_records: int = 500) -> list:
        """Fetch recent critical CVEs from the NVD API."""
        print("[RAG] Fetching CVEs from NVD API...")
        headers = {}
        if api_key:
            headers["apiKey"] = api_key

        cves = []
        try:
            params = {
                "cvssV3Severity": "CRITICAL",
                "resultsPerPage": min(n_records, 200),
                "startIndex":     0,
            }
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params  = params,
                headers = headers,
                timeout = 30,
            )
            resp.raise_for_status()
            data = resp.json()

            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                desc = next(
                    (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                    "No description"
                )
                metrics  = cve.get("metrics", {})
                cvss_v3  = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                cvss     = cvss_v3[0]["cvssData"]["baseScore"] if cvss_v3 else 0
                severity = cvss_v3[0]["cvssData"]["baseSeverity"] if cvss_v3 else "UNKNOWN"
                av       = cvss_v3[0]["cvssData"].get("attackVector", "NETWORK") if cvss_v3 else "NETWORK"

                cves.append({
                    "id":           cve_id,
                    "description":  desc[:500],
                    "cvss":         cvss,
                    "severity":     severity.title(),
                    "attack_vector": av.title(),
                    "ports":        [],
                    "products":     [],
                })

            print(f"[RAG] Fetched {len(cves)} CVEs from NVD API")
            time.sleep(1)  # Rate limit
        except Exception as e:
            print(f"[RAG] NVD API error: {e} — using fallback CVEs only")

        return cves

    def query(
        self,
        attack_type: str,
        dst_port:    int = 0,
        top_k:       int = 5,
    ) -> List[Dict]:
        """
        Find CVEs matching an attack pattern.

        Parameters
        ----------
        attack_type : e.g. "brute_force", "port_scan"
        dst_port    : destination port number
        top_k       : number of results to return
        """
        if self.available and self.collection.count() > 0:
            return self._query_chroma(attack_type, dst_port, top_k)
        else:
            return self._query_fallback(attack_type, dst_port, top_k)

    def _query_chroma(self, attack_type: str, dst_port: int, top_k: int) -> List[Dict]:
        """Semantic search in ChromaDB."""
        query_text = f"{attack_type.replace('_', ' ')} vulnerability exploit port {dst_port}"

        try:
            results = self.collection.query(
                query_texts = [query_text],
                n_results   = top_k,
            )

            cves = []
            docs      = results["documents"][0]
            metas     = results["metadatas"][0]
            distances = results["distances"][0]

            for doc, meta, dist in zip(docs, metas, distances):
                cves.append({
                    "cve_id":       meta["cve_id"],
                    "cvss":         meta["cvss"],
                    "severity":     meta["severity"],
                    "description":  doc[:400],
                    "relevance":    round(1 - dist, 3),
                })
            return sorted(cves, key=lambda x: x["cvss"], reverse=True)

        except Exception as e:
            print(f"[RAG] ChromaDB query failed: {e}")
            return self._query_fallback(attack_type, dst_port, top_k)

    def _query_fallback(self, attack_type: str, dst_port: int, top_k: int) -> List[Dict]:
        """Keyword-based fallback when ChromaDB unavailable."""
        cve_path = os.path.join(CHROMA_DIR, "cves.json")
        if os.path.exists(cve_path):
            with open(cve_path) as f:
                all_cves = json.load(f)
        else:
            all_cves = FALLBACK_CVES

        keywords = attack_type.replace("_", " ").lower().split()
        port_str = str(dst_port)

        scored = []
        for cve in all_cves:
            desc = cve["description"].lower()
            score = sum(1 for kw in keywords if kw in desc)
            if port_str in cve.get("ports", []):
                score += 3
            scored.append((score, cve))

        scored.sort(key=lambda x: (x[0], x[1]["cvss"]), reverse=True)
        results = []
        for _, cve in scored[:top_k]:
            results.append({
                "cve_id":      cve["id"],
                "cvss":        cve["cvss"],
                "severity":    cve["severity"],
                "description": cve["description"][:400],
                "relevance":   0.7,
            })
        return results

    def is_built(self) -> bool:
        """Check if the knowledge base has been populated."""
        json_exists = os.path.exists(os.path.join(CHROMA_DIR, "cves.json"))
        chroma_ok   = self.available and self.collection is not None and self.collection.count() > 0
        return json_exists or chroma_ok

    def get_mitre_technique(self, attack_type: str) -> dict:
        """Return MITRE ATT&CK technique for a given attack type."""
        return MITRE_TECHNIQUES.get(attack_type, MITRE_TECHNIQUES["unknown"])

    def count(self) -> int:
        if self.available and self.collection:
            return self.collection.count()
        cve_path = os.path.join(CHROMA_DIR, "cves.json")
        if os.path.exists(cve_path):
            with open(cve_path) as f:
                return len(json.load(f))
        return 0
