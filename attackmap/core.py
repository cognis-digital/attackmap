"""Core engine for ATTACKMAP.

Provides a small embedded slice of the MITRE ATT&CK Enterprise knowledge base
(technique id -> name, tactic, keyword aliases) and pure functions to:
  * resolve free-text findings to ATT&CK technique ids,
  * aggregate findings into a coverage heatmap per tactic,
  * emit an ATT&CK Navigator layer (v4.5 schema) for visualization.

No network, no I/O side effects (except optional file reads via parse_findings).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Sequence

# Canonical ATT&CK Enterprise tactic order (kill-chain ordering).
TACTIC_ORDER: List[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


@dataclass(frozen=True)
class Technique:
    tid: str
    name: str
    tactic: str
    keywords: Sequence[str] = field(default_factory=tuple)


# Embedded ATT&CK slice. Keywords are lowercase substrings used for fuzzy
# resolution of findings. (id, name, tactic, [keywords])
_RAW_TECHNIQUES = [
    ("T1566.001", "Phishing: Spearphishing Attachment", "initial-access",
     ["phishing attachment", "malicious attachment", "spearphishing", "phishing"]),
    ("T1566.002", "Phishing: Spearphishing Link", "initial-access",
     ["phishing link", "malicious link", "credential harvest"]),
    ("T1190", "Exploit Public-Facing Application", "initial-access",
     ["sql injection", "sqli", "rce", "public-facing", "web exploit", "deserialization"]),
    ("T1133", "External Remote Services", "initial-access",
     ["vpn", "rdp exposed", "external remote", "citrix"]),
    ("T1059.001", "Command and Scripting Interpreter: PowerShell", "execution",
     ["powershell", "encodedcommand", "invoke-expression", "iex"]),
    ("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "execution",
     ["cmd.exe", "command shell", "bat script"]),
    ("T1053.005", "Scheduled Task/Job: Scheduled Task", "persistence",
     ["scheduled task", "schtasks", "at.exe"]),
    ("T1547.001", "Boot or Logon Autostart: Registry Run Keys", "persistence",
     ["run key", "registry autostart", "currentversion\\run", "startup folder"]),
    ("T1543.003", "Create or Modify System Process: Windows Service", "persistence",
     ["new service", "windows service", "sc create"]),
    ("T1068", "Exploitation for Privilege Escalation", "privilege-escalation",
     ["privilege escalation", "kernel exploit", "local exploit"]),
    ("T1548.002", "Abuse Elevation Control: Bypass UAC", "privilege-escalation",
     ["uac bypass", "bypass uac", "elevation"]),
    ("T1055", "Process Injection", "defense-evasion",
     ["process injection", "dll injection", "hollowing", "reflective"]),
    ("T1070.004", "Indicator Removal: File Deletion", "defense-evasion",
     ["file deletion", "log deletion", "wevtutil cl", "clear logs"]),
    ("T1112", "Modify Registry", "defense-evasion",
     ["modify registry", "reg add", "registry tamper"]),
    ("T1110", "Brute Force", "credential-access",
     ["brute force", "password spray", "credential stuffing", "failed logins"]),
    ("T1003.001", "OS Credential Dumping: LSASS Memory", "credential-access",
     ["lsass", "mimikatz", "credential dump", "sekurlsa"]),
    ("T1552.001", "Unsecured Credentials: Credentials In Files", "credential-access",
     ["hardcoded credential", "plaintext password", "creds in file", "secrets in file"]),
    ("T1087", "Account Discovery", "discovery",
     ["account discovery", "net user", "enumerate users", "net group"]),
    ("T1046", "Network Service Discovery", "discovery",
     ["port scan", "network scan", "service discovery", "nmap"]),
    ("T1021.001", "Remote Services: Remote Desktop Protocol", "lateral-movement",
     ["rdp", "remote desktop", "3389"]),
    ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "lateral-movement",
     ["smb", "admin share", "psexec", "c$"]),
    ("T1560", "Archive Collected Data", "collection",
     ["archive data", "rar", "7zip staging", "zip exfil prep"]),
    ("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control",
     ["c2", "command and control", "http beacon", "https beacon", "beacon"]),
    ("T1572", "Protocol Tunneling", "command-and-control",
     ["tunnel", "dns tunnel", "protocol tunneling", "ssh tunnel"]),
    ("T1041", "Exfiltration Over C2 Channel", "exfiltration",
     ["exfiltration", "data exfil", "exfil over c2"]),
    ("T1486", "Data Encrypted for Impact", "impact",
     ["ransomware", "data encrypted", "encryption for impact"]),
    ("T1490", "Inhibit System Recovery", "impact",
     ["vssadmin delete", "shadow copy delete", "inhibit recovery", "bcdedit"]),
]

TECHNIQUES: Dict[str, Technique] = {
    tid: Technique(tid, name, tactic, tuple(kw))
    for (tid, name, tactic, kw) in _RAW_TECHNIQUES
}

# Explicit id alias index (uppercase id -> canonical id).
_ID_INDEX = {tid.upper(): tid for tid in TECHNIQUES}
_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


@dataclass
class Finding:
    """A single security finding to be mapped to ATT&CK."""
    name: str
    description: str = ""
    severity: str = "medium"
    technique_id: Optional[str] = None  # explicit override

    def text(self) -> str:
        return f"{self.name}\n{self.description}".lower()


def lookup_technique(tid: str) -> Optional[Technique]:
    """Resolve a technique by id (case-insensitive). Sub->parent fallback."""
    if not tid:
        return None
    key = tid.strip().upper()
    if key in _ID_INDEX:
        return TECHNIQUES[_ID_INDEX[key]]
    # Sub-technique given but only parent known, or vice versa: try parent.
    parent = key.split(".")[0]
    if parent in _ID_INDEX:
        return TECHNIQUES[_ID_INDEX[parent]]
    return None


def resolve_keywords(text: str) -> List[str]:
    """Return technique ids whose embedded ids or keywords appear in text.

    Resolution order: explicit T-ids in text first, then keyword substrings.
    Deterministic ordering (by tactic order then id) so output is stable.
    """
    text_l = text.lower()
    hits = set()
    for m in _TID_RE.findall(text):
        t = lookup_technique(m)
        if t:
            hits.add(t.tid)
    for t in TECHNIQUES.values():
        for kw in t.keywords:
            if kw in text_l:
                hits.add(t.tid)
                break
    return sorted(hits, key=lambda x: (TACTIC_ORDER.index(TECHNIQUES[x].tactic), x))


_SEV_WEIGHT = {"info": 1, "low": 2, "medium": 4, "high": 7, "critical": 10}


def map_findings(findings: Sequence[Finding]) -> Dict:
    """Map findings to ATT&CK techniques.

    Returns a dict with per-finding mappings and an unmapped list.
    """
    mapped: List[Dict] = []
    unmapped: List[Dict] = []
    for f in findings:
        ids: List[str] = []
        if f.technique_id:
            t = lookup_technique(f.technique_id)
            if t:
                ids.append(t.tid)
        if not ids:
            ids = resolve_keywords(f.text())
        if ids:
            mapped.append({
                "finding": f.name,
                "severity": f.severity,
                "techniques": [
                    {"id": tid, "name": TECHNIQUES[tid].name,
                     "tactic": TECHNIQUES[tid].tactic}
                    for tid in ids
                ],
            })
        else:
            unmapped.append({"finding": f.name, "severity": f.severity})
    return {"mapped": mapped, "unmapped": unmapped}


def coverage_heatmap(findings: Sequence[Finding]) -> Dict:
    """Aggregate a per-tactic and per-technique heatmap with weighted scores.

    Score for a technique = sum of severity weights of findings hitting it.
    """
    tech_scores: Dict[str, int] = {}
    tech_counts: Dict[str, int] = {}
    result = map_findings(findings)
    sev_by_finding = {m["finding"]: m["severity"] for m in result["mapped"]}
    for m in result["mapped"]:
        w = _SEV_WEIGHT.get(sev_by_finding.get(m["finding"], "medium"), 4)
        for t in m["techniques"]:
            tech_scores[t["id"]] = tech_scores.get(t["id"], 0) + w
            tech_counts[t["id"]] = tech_counts.get(t["id"], 0) + 1

    tactics: Dict[str, Dict] = {}
    for tactic in TACTIC_ORDER:
        techs = []
        for tid, t in TECHNIQUES.items():
            if t.tactic == tactic and tid in tech_scores:
                techs.append({
                    "id": tid,
                    "name": t.name,
                    "score": tech_scores[tid],
                    "count": tech_counts[tid],
                })
        techs.sort(key=lambda x: (-x["score"], x["id"]))
        tactics[tactic] = {
            "techniques": techs,
            "hit_techniques": len(techs),
            "total_score": sum(x["score"] for x in techs),
        }
    return {
        "tactics": tactics,
        "total_techniques_hit": len(tech_scores),
        "tactics_covered": sum(1 for v in tactics.values() if v["hit_techniques"]),
        "total_tactics": len(TACTIC_ORDER),
    }


def navigator_layer(findings: Sequence[Finding], name: str = "ATTACKMAP layer") -> Dict:
    """Emit an ATT&CK Navigator layer (v4.5) for the mapped techniques."""
    heat = coverage_heatmap(findings)
    techs = []
    max_score = 1
    for tactic in TACTIC_ORDER:
        for t in heat["tactics"][tactic]["techniques"]:
            max_score = max(max_score, t["score"])
    for tactic in TACTIC_ORDER:
        for t in heat["tactics"][tactic]["techniques"]:
            techs.append({
                "techniqueID": t["id"],
                "tactic": tactic,
                "score": t["score"],
                "comment": f"{t['count']} finding(s)",
                "enabled": True,
            })
    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Generated by attackmap (defensive coverage mapping).",
        "gradient": {
            "colors": ["#ffffff", "#ff6666"],
            "minValue": 0,
            "maxValue": max_score,
        },
        "techniques": techs,
    }


def parse_findings(path: Optional[str] = None, raw: Optional[str] = None) -> List[Finding]:
    """Parse findings from a JSON file/string.

    Accepts either a list of objects or {"findings": [...]}. Each object may use
    keys: name/title, description/desc, severity, technique_id/technique.
    """
    if raw is None:
        if path is None:
            raise ValueError("parse_findings requires path or raw")
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    data = json.loads(raw)
    if isinstance(data, dict):
        data = data.get("findings", [])
    if not isinstance(data, list):
        raise ValueError("findings input must be a JSON list or {findings:[...]}")
    out: List[Finding] = []
    for item in data:
        if not isinstance(item, dict):
            raise ValueError("each finding must be a JSON object")
        name = item.get("name") or item.get("title")
        if not name:
            raise ValueError("finding missing 'name'/'title'")
        out.append(Finding(
            name=str(name),
            description=str(item.get("description") or item.get("desc") or ""),
            severity=str(item.get("severity") or "medium").lower(),
            technique_id=item.get("technique_id") or item.get("technique"),
        ))
    return out
