"""ATTACKMAP core engine.

Map free-text security findings to MITRE ATT&CK (Enterprise) technique IDs,
then render a tactic-by-tactic coverage heatmap and export an ATT&CK Navigator
layer. Standard library only, zero install, no network. Defensive /
detection-engineering use.

The module ships a real, substantial bundled catalog: the 14 Enterprise
tactics plus a curated set of ~70 techniques and sub-techniques, each carrying
keyword/phrase/regex detection rules and a short description. Findings (alert
text, detection names, threat-report sentences) are tokenised and scored
against those rules to produce ranked technique matches with evidence and
confidence.

Nothing here is a stub: CATALOG is real data, the matcher is a real weighted
keyword/phrase/regex engine, the heatmap is computed from live matches, and
``navigator_layer`` emits a JSON layer that loads directly in the public
MITRE ATT&CK Navigator.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

TOOL_NAME = "attackmap"
TOOL_VERSION = "2.0.0"

# ATT&CK Enterprise matrix version this catalog tracks (for the Navigator layer).
ATTACK_VERSION = "15"
ATTACK_DOMAIN = "enterprise-attack"

# ---------------------------------------------------------------------------
# Bundled ATT&CK catalog
# ---------------------------------------------------------------------------
# Tactics keyed by short id -> (TAxxxx, display name).
TACTICS: dict[str, tuple[str, str]] = {
    "recon": ("TA0043", "Reconnaissance"),
    "resource-dev": ("TA0042", "Resource Development"),
    "initial-access": ("TA0001", "Initial Access"),
    "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"),
    "privilege-escalation": ("TA0004", "Privilege Escalation"),
    "defense-evasion": ("TA0005", "Defense Evasion"),
    "credential-access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
    "lateral-movement": ("TA0008", "Lateral Movement"),
    "collection": ("TA0009", "Collection"),
    "command-and-control": ("TA0011", "Command and Control"),
    "exfiltration": ("TA0010", "Exfiltration"),
    "impact": ("TA0040", "Impact"),
}

# Canonical tactic ordering = the ATT&CK kill-chain left-to-right.
TACTIC_ORDER: list[str] = list(TACTICS.keys())


@dataclass(frozen=True)
class Technique:
    """A single (sub-)technique with detection rules.

    keywords : single tokens / short phrases (weight 1 token, weight 2 phrase)
    regexes  : patterns matched against the raw text (weight 3 each)
    desc     : one-line human description (shown in lookup / Navigator)
    """

    tid: str
    name: str
    tactics: tuple[str, ...]
    keywords: tuple[str, ...]
    regexes: tuple[str, ...] = ()
    desc: str = ""

    @property
    def is_subtechnique(self) -> bool:
        return "." in self.tid

    @property
    def parent_id(self) -> str:
        return self.tid.split(".", 1)[0] if self.is_subtechnique else self.tid


def _t(tid, name, tactics, keywords, regexes=(), desc=""):
    return Technique(tid, name, tuple(tactics), tuple(keywords),
                     tuple(regexes), desc)


# A curated-but-real slice of Enterprise ATT&CK. Each technique carries real
# detection language drawn from how these show up in alerts and reports.
CATALOG: tuple[Technique, ...] = (
    # -- Reconnaissance --
    _t("T1595", "Active Scanning", ["recon"],
       ["port scan", "scanning", "nmap", "masscan", "vulnerability scan"],
       [r"\bnmap\b", r"\bmasscan\b"],
       "Adversary probes target infrastructure with network/vuln scans."),
    _t("T1592", "Gather Victim Host Information", ["recon"],
       ["fingerprint", "host enumeration", "banner grab"],
       desc="Collects information about victim hosts (hardware, software)."),
    _t("T1589", "Gather Victim Identity Information", ["recon"],
       ["email harvest", "credential dump database", "breached credentials"],
       desc="Collects identity data (emails, names, leaked credentials)."),
    _t("T1598", "Phishing for Information", ["recon"],
       ["phishing for information", "survey lure", "credential phishing recon"],
       desc="Sends phishing to elicit information rather than execute code."),

    # -- Resource Development --
    _t("T1583", "Acquire Infrastructure", ["resource-dev"],
       ["registered domain", "bulletproof hosting", "vps purchase"],
       desc="Buys/leases domains, servers, or hosting to stage operations."),
    _t("T1588.002", "Obtain Capabilities: Tool", ["resource-dev"],
       ["cobalt strike", "mimikatz download", "metasploit", "tooling"],
       desc="Acquires offensive tooling (commercial or open-source)."),
    _t("T1587.001", "Develop Capabilities: Malware", ["resource-dev"],
       ["custom malware", "bespoke implant", "compiled loader"],
       desc="Builds custom malware/implants for the campaign."),

    # -- Initial Access --
    _t("T1566", "Phishing", ["initial-access"],
       ["phishing", "phish", "spearphish", "malicious email", "lure"],
       [r"\bphish\w*\b"],
       "Delivers malicious content via email to gain access."),
    _t("T1566.001", "Phishing: Spearphishing Attachment", ["initial-access"],
       ["malicious attachment", "weaponized document", "macro document",
        "spearphishing attachment"],
       desc="Targeted email carrying a malicious attachment."),
    _t("T1566.002", "Phishing: Spearphishing Link", ["initial-access"],
       ["phishing link", "credential harvesting page", "spearphishing link"],
       desc="Targeted email carrying a malicious link."),
    _t("T1190", "Exploit Public-Facing Application", ["initial-access"],
       ["exploit", "web shell upload", "sql injection", "rce on web",
        "public-facing", "log4j", "proxyshell", "deserialization"],
       [r"\bCVE-\d{4}-\d{4,7}\b", r"\blog4j\b", r"\bproxyshell\b"],
       "Exploits an internet-facing app to gain a foothold."),
    _t("T1133", "External Remote Services", ["initial-access", "persistence"],
       ["vpn login", "rdp from internet", "exposed rdp", "remote service",
        "citrix gateway"],
       desc="Abuses externally exposed remote services (VPN, RDP, Citrix)."),
    _t("T1078", "Valid Accounts", ["initial-access", "persistence",
                                    "privilege-escalation", "defense-evasion"],
       ["valid account", "compromised credentials", "stolen credentials",
        "legitimate account", "account misuse"],
       desc="Uses legitimate credentials for access and stealth."),
    _t("T1195", "Supply Chain Compromise", ["initial-access"],
       ["supply chain", "trojanized update", "compromised dependency",
        "poisoned package"],
       desc="Compromises software/hardware before it reaches the victim."),
    _t("T1199", "Trusted Relationship", ["initial-access"],
       ["trusted relationship", "third-party access", "msp compromise"],
       desc="Abuses a trusted third party's access into the environment."),

    # -- Execution --
    _t("T1059", "Command and Scripting Interpreter", ["execution"],
       ["command interpreter", "script execution", "shell command"],
       desc="Executes commands/scripts via an interpreter."),
    _t("T1059.001", "PowerShell", ["execution"],
       ["powershell", "encodedcommand", "invoke-expression", "iex ",
        "downloadstring"],
       [r"powershell(\.exe)?", r"-enc(odedcommand)?\b",
        r"\bIEX\b", r"DownloadString"],
       "Abuses PowerShell for execution and download-and-run."),
    _t("T1059.003", "Windows Command Shell", ["execution"],
       ["cmd.exe", "command prompt", "batch script"],
       [r"\bcmd(\.exe)?\b"],
       "Uses cmd.exe / batch for execution."),
    _t("T1059.004", "Unix Shell", ["execution"],
       ["bash", "/bin/sh", "reverse shell", "sh -c"],
       [r"/bin/(ba)?sh\b", r"bash -i"],
       "Uses a Unix shell, often for a reverse shell."),
    _t("T1059.006", "Python", ["execution"],
       ["python -c", "python script execution", "py2exe loader"],
       [r"python[\d.]* -c"],
       "Uses Python for execution/tooling."),
    _t("T1204", "User Execution", ["execution"],
       ["user opened", "user clicked", "double-click", "ran the file"],
       desc="Relies on a user opening/running malicious content."),
    _t("T1053.005", "Scheduled Task/Job: Scheduled Task", ["execution",
                                                            "persistence",
                                                            "privilege-escalation"],
       ["scheduled task", "schtasks", "task scheduler"],
       [r"\bschtasks\b"],
       "Creates a scheduled task for execution/persistence."),
    _t("T1047", "Windows Management Instrumentation", ["execution"],
       ["wmi", "wmic", "win32_process", "wmiexec"],
       [r"\bwmic?\b", r"Win32_Process"],
       "Uses WMI to execute commands locally or remotely."),
    _t("T1569.002", "System Services: Service Execution", ["execution"],
       ["service execution", "psexec service", "started service to run"],
       desc="Executes a payload by running a Windows service."),

    # -- Persistence / Privilege Escalation --
    _t("T1547.001", "Boot/Logon Autostart: Registry Run Keys", ["persistence",
                                                                 "privilege-escalation"],
       ["run key", "registry autostart", "currentversion\\run", "startup folder"],
       [r"\\CurrentVersion\\Run"],
       "Persists via Run keys / Startup folder."),
    _t("T1543.003", "Create/Modify System Process: Windows Service",
       ["persistence", "privilege-escalation"],
       ["new service", "service install", "sc create", "malicious service"],
       [r"\bsc\.exe create\b", r"\bsc create\b"],
       "Installs/modifies a Windows service for persistence."),
    _t("T1136", "Create Account", ["persistence"],
       ["create account", "net user /add", "new local user", "rogue account"],
       [r"net user .*\b/add\b"],
       "Creates an account to maintain access."),
    _t("T1505.003", "Server Software Component: Web Shell", ["persistence"],
       ["web shell", "aspx shell", "china chopper", "jsp webshell"],
       [r"\bweb ?shell\b"],
       "Plants a web shell on a server for persistent access."),
    _t("T1548.002", "Abuse Elevation Control: Bypass UAC", ["privilege-escalation",
                                                            "defense-evasion"],
       ["uac bypass", "bypass uac", "elevation"],
       desc="Bypasses User Account Control to elevate."),
    _t("T1068", "Exploitation for Privilege Escalation", ["privilege-escalation"],
       ["privilege escalation exploit", "kernel exploit", "local privilege escalation",
        "token elevation"],
       desc="Exploits a vulnerability to gain higher privileges."),
    _t("T1078.004", "Valid Accounts: Cloud Accounts",
       ["initial-access", "persistence", "privilege-escalation", "defense-evasion"],
       ["cloud account", "azure ad account abuse", "iam user abuse",
        "stolen oauth token"],
       desc="Abuses cloud/IdP accounts for access and escalation."),

    # -- Defense Evasion --
    _t("T1070.001", "Indicator Removal: Clear Windows Event Logs",
       ["defense-evasion"],
       ["cleared event log", "wevtutil cl", "clear security log", "log cleared"],
       [r"wevtutil\s+cl\b"],
       "Clears Windows event logs to remove traces."),
    _t("T1070.004", "Indicator Removal: File Deletion", ["defense-evasion"],
       ["deleted artifacts", "anti-forensic", "self-delete", "wipe files"],
       desc="Deletes files/artifacts to hide activity."),
    _t("T1027", "Obfuscated Files or Information", ["defense-evasion"],
       ["obfuscated", "base64 encoded payload", "packed binary", "encoded blob"],
       [r"base64", r"FromBase64String"],
       "Obfuscates/encodes files or commands to evade detection."),
    _t("T1562.001", "Impair Defenses: Disable or Modify Tools", ["defense-evasion"],
       ["disabled antivirus", "disable defender", "stopped edr", "tamper protection",
        "set-mppreference"],
       [r"Set-MpPreference", r"disable\w* (defender|antivirus|edr)"],
       "Disables/tampers with security tooling (AV/EDR)."),
    _t("T1055", "Process Injection", ["defense-evasion", "privilege-escalation"],
       ["process injection", "dll injection", "reflective load", "hollowing",
        "writeprocessmemory"],
       [r"WriteProcessMemory", r"CreateRemoteThread"],
       "Injects code into another process to evade defenses."),
    _t("T1218", "System Binary Proxy Execution", ["defense-evasion"],
       ["lolbin", "rundll32", "regsvr32", "mshta", "living off the land"],
       [r"\brundll32\b", r"\bregsvr32\b", r"\bmshta\b"],
       "Proxies execution through trusted signed binaries (LOLBins)."),
    _t("T1140", "Deobfuscate/Decode Files or Information", ["defense-evasion"],
       ["decoded payload", "certutil decode", "xor decode", "deobfuscate"],
       [r"certutil .*-decode"],
       "Decodes obfuscated payloads at runtime."),
    _t("T1036", "Masquerading", ["defense-evasion"],
       ["masquerading", "renamed binary", "svchost in temp",
        "legitimate-looking name"],
       desc="Disguises malicious artifacts as legitimate ones."),

    # -- Credential Access --
    _t("T1003", "OS Credential Dumping", ["credential-access"],
       ["credential dump", "dump credentials", "dumped hashes"],
       desc="Dumps credentials from the operating system."),
    _t("T1003.001", "OS Credential Dumping: LSASS Memory", ["credential-access"],
       ["lsass", "lsass dump", "mimikatz", "sekurlsa", "comsvcs minidump"],
       [r"\blsass(\.exe)?\b", r"\bmimikatz\b", r"sekurlsa"],
       "Extracts credentials from LSASS process memory."),
    _t("T1003.003", "OS Credential Dumping: NTDS", ["credential-access"],
       ["ntds.dit", "ntdsutil", "dcsync", "domain hash dump"],
       [r"ntds\.dit", r"\bdcsync\b"],
       "Extracts the AD domain hash database (NTDS.dit / DCSync)."),
    _t("T1110", "Brute Force", ["credential-access"],
       ["brute force", "password spray", "credential stuffing",
        "repeated failed logins", "failed login attempts"],
       [r"password spray", r"brute[- ]?force"],
       "Guesses credentials via spraying/stuffing/brute force."),
    _t("T1558.003", "Steal/Forge Kerberos Tickets: Kerberoasting",
       ["credential-access"],
       ["kerberoast", "kerberoasting", "spn request", "ticket roasting"],
       desc="Requests service tickets to crack service-account passwords."),
    _t("T1552.001", "Unsecured Credentials: Credentials In Files",
       ["credential-access"],
       ["hardcoded password", "credentials in file", "aws keys in repo",
        "plaintext password", "secrets in config"],
       desc="Finds credentials stored insecurely in files."),
    _t("T1555", "Credentials from Password Stores", ["credential-access"],
       ["browser password", "credential manager dump", "keychain dump",
        "password vault"],
       desc="Steals credentials from password stores/managers."),

    # -- Discovery --
    _t("T1087", "Account Discovery", ["discovery"],
       ["account enumeration", "net user", "net group", "enumerate users"],
       [r"\bnet (user|group|localgroup)\b"],
       "Enumerates accounts in the environment."),
    _t("T1018", "Remote System Discovery", ["discovery"],
       ["network enumeration", "ping sweep", "host discovery", "net view"],
       desc="Discovers other hosts on the network."),
    _t("T1083", "File and Directory Discovery", ["discovery"],
       ["file enumeration", "directory listing", "dir /s", "find sensitive files"],
       desc="Enumerates files and directories."),
    _t("T1482", "Domain Trust Discovery", ["discovery"],
       ["domain trust", "nltest", "trust enumeration", "bloodhound"],
       [r"\bnltest\b", r"\bbloodhound\b"],
       "Maps AD domain trusts (often via BloodHound)."),
    _t("T1057", "Process Discovery", ["discovery"],
       ["process listing", "tasklist", "ps -ef", "enumerate processes"],
       [r"\btasklist\b"],
       "Enumerates running processes."),
    _t("T1518.001", "Software Discovery: Security Software Discovery",
       ["discovery"],
       ["enumerate antivirus", "detect edr", "security product discovery"],
       desc="Identifies installed security products."),

    # -- Lateral Movement --
    _t("T1021.001", "Remote Services: RDP", ["lateral-movement"],
       ["rdp", "remote desktop", "lateral rdp", "mstsc"],
       [r"\brdp\b", r"\bmstsc\b"],
       "Moves laterally over RDP."),
    _t("T1021.002", "Remote Services: SMB/Windows Admin Shares",
       ["lateral-movement"],
       ["smb lateral", "admin share", "psexec", "c$ share", "wmiexec"],
       [r"\bpsexec\b", r"\badmin\$", r"\bc\$\b"],
       "Moves laterally over SMB admin shares (PsExec)."),
    _t("T1021.006", "Remote Services: WinRM", ["lateral-movement"],
       ["winrm", "powershell remoting", "enter-pssession", "evil-winrm"],
       [r"\bwinrm\b", r"Enter-PSSession"],
       "Moves laterally over WinRM/PowerShell remoting."),
    _t("T1570", "Lateral Tool Transfer", ["lateral-movement"],
       ["copied tool to host", "tool transfer", "staged binary on remote"],
       desc="Transfers tools between hosts during lateral movement."),

    # -- Collection --
    _t("T1560", "Archive Collected Data", ["collection"],
       ["archived data", "rar archive", "7zip staging", "zip exfil staging"],
       [r"\b\w+\.(rar|7z|zip)\b"],
       "Compresses/encrypts collected data prior to exfil."),
    _t("T1005", "Data from Local System", ["collection"],
       ["collected files", "data staging", "harvested documents"],
       desc="Collects data from the local system."),
    _t("T1114", "Email Collection", ["collection"],
       ["mailbox export", "email harvesting", "pst export", "ediscovery abuse"],
       desc="Collects email from local or remote mailboxes."),
    _t("T1056.001", "Input Capture: Keylogging", ["collection",
                                                  "credential-access"],
       ["keylogger", "keystroke capture", "key logging"],
       desc="Captures keystrokes."),

    # -- Command and Control --
    _t("T1071.001", "Application Layer Protocol: Web Protocols",
       ["command-and-control"],
       ["c2 over http", "http beacon", "https beaconing", "command and control",
        "beacon", "user-agent anomaly"],
       [r"\bbeacon\w*\b", r"\bc2\b"],
       "C2 over HTTP/S (beaconing)."),
    _t("T1071.004", "Application Layer Protocol: DNS", ["command-and-control",
                                                        "exfiltration"],
       ["dns tunneling", "dns exfil", "txt record c2", "dns beacon"],
       [r"dns tunnel\w*"],
       "C2 / exfil over DNS."),
    _t("T1105", "Ingress Tool Transfer", ["command-and-control"],
       ["downloaded payload", "certutil download", "bitsadmin", "wget payload",
        "curl payload"],
       [r"\bcertutil\b", r"\bbitsadmin\b"],
       "Downloads tools/payloads into the environment."),
    _t("T1572", "Protocol Tunneling", ["command-and-control"],
       ["protocol tunneling", "ssh tunnel", "reverse tunnel", "ngrok"],
       [r"\bngrok\b"],
       "Tunnels traffic to obscure C2."),
    _t("T1090", "Proxy", ["command-and-control"],
       ["socks proxy", "relay proxy", "tor exit", "proxy chain"],
       desc="Routes traffic through a proxy/relay."),

    # -- Exfiltration --
    _t("T1041", "Exfiltration Over C2 Channel", ["exfiltration"],
       ["exfiltration over c2", "data exfil over beacon"],
       desc="Exfiltrates data over the existing C2 channel."),
    _t("T1567.002", "Exfiltration to Cloud Storage", ["exfiltration"],
       ["upload to dropbox", "mega upload", "s3 exfil", "cloud storage exfil",
        "data uploaded to"],
       desc="Exfiltrates to cloud storage (Dropbox/Mega/S3)."),
    _t("T1048", "Exfiltration Over Alternative Protocol", ["exfiltration"],
       ["ftp exfil", "exfil over smtp", "icmp exfil", "alternative protocol"],
       desc="Exfiltrates over a non-C2 protocol (FTP/SMTP/ICMP)."),

    # -- Impact --
    _t("T1486", "Data Encrypted for Impact", ["impact"],
       ["ransomware", "files encrypted", "ransom note", "encryption of files",
        ".locked extension", "readme_to_decrypt"],
       [r"ransom\w*", r"\.locked\b"],
       "Encrypts data to disrupt the victim (ransomware)."),
    _t("T1490", "Inhibit System Recovery", ["impact"],
       ["deleted shadow copies", "vssadmin delete", "disabled recovery",
        "bcdedit recovery"],
       [r"vssadmin\s+delete", r"\bbcdedit\b"],
       "Removes backups/shadow copies to block recovery."),
    _t("T1489", "Service Stop", ["impact"],
       ["stopped service", "killed database service", "service stop"],
       desc="Stops services to enable impact or disrupt operations."),
    _t("T1485", "Data Destruction", ["impact"],
       ["wiper", "data destruction", "overwrote files", "disk wipe"],
       desc="Destroys/overwrites data (wiper)."),
    _t("T1496", "Resource Hijacking", ["impact"],
       ["cryptomining", "coin miner", "xmrig", "resource hijack"],
       [r"\bxmrig\b"],
       "Hijacks resources (e.g. cryptomining)."),
)

# Fast lookup by technique id.
BY_ID: dict[str, Technique] = {t.tid: t for t in CATALOG}


# ---------------------------------------------------------------------------
# Matching engine
# ---------------------------------------------------------------------------
_WORD_RE = re.compile(r"[a-z0-9][a-z0-9._/\\$-]*")
_KEYWORD_WEIGHT = 1
_PHRASE_WEIGHT = 2
_REGEX_WEIGHT = 3


@dataclass
class TechniqueMatch:
    technique: Technique
    score: int
    evidence: list[str] = field(default_factory=list)

    @property
    def confidence(self) -> str:
        if self.score >= 5:
            return "high"
        if self.score >= 3:
            return "medium"
        return "low"

    def as_dict(self) -> dict:
        return {
            "id": self.technique.tid,
            "name": self.technique.name,
            "tactics": list(self.technique.tactics),
            "score": self.score,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }


@dataclass
class Finding:
    """One input finding mapped to zero or more techniques."""

    text: str
    matches: list[TechniqueMatch] = field(default_factory=list)

    @property
    def mapped(self) -> bool:
        return bool(self.matches)

    @property
    def top(self) -> TechniqueMatch | None:
        return self.matches[0] if self.matches else None

    def as_dict(self) -> dict:
        return {
            "finding": self.text,
            "techniques": [m.as_dict() for m in self.matches],
        }


@dataclass
class MapResult:
    findings: list[Finding] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def mapped_findings(self) -> int:
        return sum(1 for f in self.findings if f.mapped)

    def unique_techniques(self) -> dict[str, TechniqueMatch]:
        """Best match per technique id across all findings."""
        best: dict[str, TechniqueMatch] = {}
        for f in self.findings:
            for m in f.matches:
                cur = best.get(m.technique.tid)
                if cur is None or m.score > cur.score:
                    best[m.technique.tid] = m
        return best

    def tactic_coverage(self) -> dict[str, dict]:
        """Per-tactic coverage from the matched techniques."""
        uniq = self.unique_techniques()
        cov: dict[str, dict] = {}
        for short in TACTIC_ORDER:
            tid, name = TACTICS[short]
            hits = [m for m in uniq.values() if short in m.technique.tactics]
            total = sum(1 for t in CATALOG if short in t.tactics)
            cov[short] = {
                "tactic_id": tid,
                "name": name,
                "techniques_in_catalog": total,
                "techniques_observed": len(hits),
                "observed_ids": sorted(m.technique.tid for m in hits),
                "max_confidence": _max_conf(hits),
            }
        return cov

    def as_dict(self) -> dict:
        uniq = self.unique_techniques()
        return {
            "total_findings": self.total_findings,
            "mapped_findings": self.mapped_findings,
            "unmapped_findings": self.total_findings - self.mapped_findings,
            "unique_techniques": len(uniq),
            "technique_ids": sorted(uniq),
            "tactics_touched": sorted(
                s for s, c in self.tactic_coverage().items()
                if c["techniques_observed"]
            ),
            "findings": [f.as_dict() for f in self.findings],
            "coverage": self.tactic_coverage(),
        }


def _max_conf(matches: Iterable[TechniqueMatch]) -> str | None:
    rank = {"low": 1, "medium": 2, "high": 3}
    best = None
    best_r = 0
    for m in matches:
        if rank[m.confidence] > best_r:
            best_r = rank[m.confidence]
            best = m.confidence
    return best


def _tokenize(text: str) -> set[str]:
    return set(_WORD_RE.findall(text.lower()))


def map_text(text: str, *, min_score: int = 1) -> Finding:
    """Map a single free-text finding to ATT&CK techniques."""
    low = text.lower()
    tokens = _tokenize(text)
    matches: list[TechniqueMatch] = []

    for tech in CATALOG:
        score = 0
        evidence: list[str] = []

        for kw in tech.keywords:
            k = kw.lower()
            if " " in k:
                if k in low:
                    score += _PHRASE_WEIGHT
                    evidence.append(f"phrase:{kw}")
            elif k in tokens or k in low:
                score += _KEYWORD_WEIGHT
                evidence.append(f"kw:{kw}")

        for pat in tech.regexes:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                score += _REGEX_WEIGHT
                evidence.append(f"re:{m.group(0).strip()}")

        if score >= min_score:
            matches.append(TechniqueMatch(tech, score, evidence))

    matches.sort(key=lambda m: (-m.score, m.technique.tid))
    return Finding(text=text.strip(), matches=matches)


def map_findings(lines: Iterable[str], *, min_score: int = 1) -> MapResult:
    """Map an iterable of finding lines. Blank/comment lines are ignored."""
    result = MapResult()
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        result.findings.append(map_text(line, min_score=min_score))
    return result


def map_files(paths: Iterable[str], *, min_score: int = 1) -> MapResult:
    lines: list[str] = []
    for path in paths:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines.extend(fh.readlines())
    return map_findings(lines, min_score=min_score)


def lookup(query: str) -> list[Technique]:
    """Find techniques by id (exact/prefix) or name/keyword substring."""
    q = query.strip().lower()
    out: list[Technique] = []
    for t in CATALOG:
        if (t.tid.lower() == q
                or t.tid.lower().startswith(q)
                or q in t.name.lower()
                or q in t.desc.lower()
                or any(q in kw.lower() for kw in t.keywords)):
            out.append(t)
    return out


def heatmap_rows(result: MapResult) -> list[dict]:
    """Tactic rows for the coverage heatmap, in kill-chain order."""
    cov = result.tactic_coverage()
    return [{"short": s, **cov[s]} for s in TACTIC_ORDER]


# ---------------------------------------------------------------------------
# Gap analysis + ATT&CK Navigator export
# ---------------------------------------------------------------------------
def gap_analysis(result: MapResult) -> dict:
    """Compare observed techniques against the bundled catalog.

    Returns coverage percentages plus the catalog techniques NOT observed,
    grouped by tactic -- i.e. the detection/visibility gaps.
    """
    uniq = result.unique_techniques()
    observed_ids = set(uniq)
    catalog_ids = {t.tid for t in CATALOG}
    missing = sorted(catalog_ids - observed_ids)

    by_tactic_missing: dict[str, list[str]] = {}
    for short in TACTIC_ORDER:
        gaps = sorted(
            t.tid for t in CATALOG
            if short in t.tactics and t.tid not in observed_ids
        )
        if gaps:
            by_tactic_missing[short] = gaps

    pct = round(100.0 * len(observed_ids) / len(catalog_ids), 1) if catalog_ids else 0.0
    tactics_touched = sum(
        1 for c in result.tactic_coverage().values()
        if c["techniques_observed"]
    )
    return {
        "catalog_size": len(catalog_ids),
        "techniques_observed": len(observed_ids),
        "techniques_missing": len(missing),
        "coverage_pct": pct,
        "tactics_touched": tactics_touched,
        "tactics_total": len(TACTIC_ORDER),
        "observed_ids": sorted(observed_ids),
        "missing_ids": missing,
        "missing_by_tactic": by_tactic_missing,
    }


# Navigator score color ramp (low->high) and confidence->score mapping.
_CONF_SCORE = {"low": 33, "medium": 66, "high": 100}


def navigator_layer(result: MapResult, *, name: str = "attackmap layer",
                    description: str = "") -> dict:
    """Build a MITRE ATT&CK Navigator layer (v4.5) from observed techniques.

    The JSON it returns loads directly in the public ATT&CK Navigator: each
    observed technique gets a per-tactic entry with a 0-100 score driven by
    match confidence, a color, and an evidence comment.
    """
    uniq = result.unique_techniques()
    techniques: list[dict] = []
    for tid, m in sorted(uniq.items()):
        score = _CONF_SCORE[m.confidence]
        comment = "; ".join(m.evidence[:8])
        for short in m.technique.tactics:
            tactic_slug = TACTICS[short][1].lower().replace(" ", "-")
            techniques.append({
                "techniqueID": tid,
                "tactic": tactic_slug,
                "score": score,
                "color": "",
                "comment": comment,
                "enabled": True,
                "metadata": [
                    {"name": "confidence", "value": m.confidence},
                    {"name": "match_score", "value": str(m.score)},
                ],
            })

    return {
        "name": name,
        "versions": {"layer": "4.5", "attack": ATTACK_VERSION,
                     "navigator": "4.9.1"},
        "domain": ATTACK_DOMAIN,
        "description": description or "Generated by attackmap from findings.",
        "sorting": 3,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe766", "#ffaf66", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "low confidence", "color": "#ffe766"},
            {"label": "medium confidence", "color": "#ffaf66"},
            {"label": "high confidence", "color": "#ff6666"},
        ],
        "metadata": [
            {"name": "tool", "value": f"{TOOL_NAME} {TOOL_VERSION}"},
            {"name": "techniques_observed", "value": str(len(uniq))},
        ],
        "showTacticRowBackground": True,
        "hideDisabled": False,
    }
