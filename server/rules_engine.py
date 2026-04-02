"""
Cibervault Detection Rules Engine
- Built-in MITRE ATT&CK mapped rules
- Custom rule support with DB persistence
- Severity scoring
- Alert correlation (brute force, lateral movement chains)
"""

import json
import re
from datetime import datetime, timezone
from typing import Optional

# ── Built-in detection rules ─────────────────────────────────────────────────
# Format: id, name, event_types, conditions_fn, severity, mitre_id, tactic, score

BUILTIN_RULES = [
    # ── Authentication ────────────────────────────────────────────────────────
    {
        "rule_id": "CV-001",
        "name": "Multiple failed login attempts",
        "description": "5+ failed logins in 2 minutes - possible brute force",
        "event_types": ["auth_failure"],
        "severity": "high",
        "mitre_id": "T1110.001",
        "mitre_tactic": "Credential Access",
        "base_score": 72,
        "enabled": True,
        "builtin": True,
        "threshold": 5,
        "window_sec": 120,
        "correlation": True,
    },
    {
        "rule_id": "CV-002",
        "name": "Login after multiple failures",
        "description": "Successful login following repeated failures - possible credential stuffing",
        "event_types": ["auth_success", "auth_failure"],
        "severity": "critical",
        "mitre_id": "T1110.003",
        "mitre_tactic": "Credential Access",
        "base_score": 88,
        "enabled": True,
        "builtin": True,
    },
    {
        "rule_id": "CV-003",
        "name": "Login with explicit credentials",
        "description": "RunAs or pass-the-hash indicator (Event 4648)",
        "event_types": ["auth_explicit"],
        "severity": "high",
        "mitre_id": "T1550.002",
        "mitre_tactic": "Lateral Movement",
        "base_score": 70,
        "enabled": True,
        "builtin": True,
    },
    {
        "rule_id": "CV-004",
        "name": "Security audit log cleared",
        "description": "Attacker covering tracks - audit log was cleared (Event 1102)",
        "event_types": ["audit_clear"],
        "severity": "critical",
        "mitre_id": "T1070.001",
        "mitre_tactic": "Defense Evasion",
        "base_score": 95,
        "enabled": True,
        "builtin": True,
    },
    # ── Persistence ───────────────────────────────────────────────────────────
    {
        "rule_id": "CV-010",
        "name": "New scheduled task created",
        "description": "Scheduled task persistence mechanism (Event 4698)",
        "event_types": ["task_create"],
        "severity": "medium",
        "mitre_id": "T1053.005",
        "mitre_tactic": "Persistence",
        "base_score": 55,
        "enabled": True,
        "builtin": True,
    },
    {
        "rule_id": "CV-011",
        "name": "New service installed",
        "description": "New Windows service - common malware persistence (Event 7045)",
        "event_types": ["service_install"],
        "severity": "high",
        "mitre_id": "T1543.003",
        "mitre_tactic": "Persistence",
        "base_score": 68,
        "enabled": True,
        "builtin": True,
    },
    {
        "rule_id": "CV-012",
        "name": "Registry Run key modification",
        "description": "New entry in autorun registry key",
        "event_types": ["registry_add", "registry_modify"],
        "severity": "high",
        "mitre_id": "T1547.001",
        "mitre_tactic": "Persistence",
        "base_score": 72,
        "enabled": True,
        "builtin": True,
    },
    {
        "rule_id": "CV-013",
        "name": "New user account created",
        "description": "Local user account created - possible backdoor (Event 4720)",
        "event_types": ["user_create"],
        "severity": "high",
        "mitre_id": "T1136.001",
        "mitre_tactic": "Persistence",
        "base_score": 75,
        "enabled": True,
        "builtin": True,
    },
    # ── Execution ─────────────────────────────────────────────────────────────
    {
        "rule_id": "CV-020",
        "name": "PowerShell encoded command",
        "description": "Obfuscated PowerShell via -EncodedCommand - common malware evasion",
        "event_types": ["process_create", "process_tree", "win_event"],
        "severity": "high",
        "mitre_id": "T1059.001",
        "mitre_tactic": "Execution",
        "base_score": 78,
        "enabled": True,
        "builtin": True,
        "match_field": "cmdline",
        "match_pattern": r"-enc|-encodedcommand|-e [A-Za-z0-9+/]{20}",
    },
    {
        "rule_id": "CV-021",
        "name": "Suspicious parent-child process",
        "description": "Office/browser spawning shell - possible code injection or macro",
        "event_types": ["process_tree"],
        "severity": "critical",
        "mitre_id": "T1059.003",
        "mitre_tactic": "Execution",
        "base_score": 90,
        "enabled": True,
        "builtin": True,
    },
    {
        "rule_id": "CV-022",
        "name": "Living-off-the-land binary (LOLBin)",
        "description": "certutil, mshta, regsvr32, or installutil executing suspicious action",
        "event_types": ["process_create", "process_tree"],
        "severity": "high",
        "mitre_id": "T1218",
        "mitre_tactic": "Defense Evasion",
        "base_score": 75,
        "enabled": True,
        "builtin": True,
        "match_field": "process_name",
        "match_pattern": r"certutil|mshta|regsvr32|installutil|msbuild|cmstp",
    },
    {
        "rule_id": "CV-023",
        "name": "Mimikatz or credential dumper detected",
        "description": "Known credential dumping tool running on endpoint",
        "event_types": ["process_create", "process_tree"],
        "severity": "critical",
        "mitre_id": "T1003.001",
        "mitre_tactic": "Credential Access",
        "base_score": 98,
        "enabled": True,
        "builtin": True,
        "match_field": "process_name",
        "match_pattern": r"mimikatz|procdump|wce|gsecdump|pwdump|lsadump",
    },
    # ── Discovery ─────────────────────────────────────────────────────────────
    {
        "rule_id": "CV-030",
        "name": "User/group enumeration",
        "description": "Attacker mapping AD users and groups (Event 4798/4799)",
        "event_types": ["user_enum", "group_enum"],
        "severity": "medium",
        "mitre_id": "T1087.001",
        "mitre_tactic": "Discovery",
        "base_score": 48,
        "enabled": True,
        "builtin": True,
    },
    {
        "rule_id": "CV-031",
        "name": "Suspicious port scan or network sweep",
        "description": "Connections to many distinct hosts/ports in short window",
        "event_types": ["network_connect"],
        "severity": "medium",
        "mitre_id": "T1046",
        "mitre_tactic": "Discovery",
        "base_score": 55,
        "enabled": True,
        "builtin": True,
        "threshold": 20,
        "window_sec": 60,
        "correlation": True,
    },
    # ── Defense Evasion ───────────────────────────────────────────────────────
    {
        "rule_id": "CV-040",
        "name": "File integrity violation",
        "description": "Critical system file modified",
        "event_types": ["fim_change", "fim_delete"],
        "severity": "critical",
        "mitre_id": "T1565.001",
        "mitre_tactic": "Impact",
        "base_score": 88,
        "enabled": True,
        "builtin": True,
    },
    # ── Network threats ───────────────────────────────────────────────────────
    {
        "rule_id": "CV-050",
        "name": "Connection to known C2 port",
        "description": "Outbound connection to common C2/RAT port",
        "event_types": ["network_connect"],
        "severity": "critical",
        "mitre_id": "T1071.001",
        "mitre_tactic": "Command and Control",
        "base_score": 90,
        "enabled": True,
        "builtin": True,
        "match_field": "dst_port",
        "match_pattern": r"^(4444|1337|31337|8888|9999|6666|5555|1234|12345|54321|65535)$",
    },
    {
        "rule_id": "CV-051",
        "name": "DNS over non-standard port",
        "description": "DNS traffic not on port 53 - possible DNS tunneling",
        "event_types": ["sysmon_dns"],
        "match_field": "cmdline",
        "match_pattern": r"\.(tk|ml|ga|cf|gq|xyz|top|pw|club|work|date|download|racing|stream)$",
        "severity": "medium",
        "mitre_id": "T1071.004",
        "mitre_tactic": "Command and Control",
        "base_score": 55,
        "enabled": True,
        "builtin": True,
    },
    # ── Windows-specific ─────────────────────────────────────────────────────
    {
        "rule_id": "CV-060",
        "name": "whoami or system discovery",
        "description": "Attacker enumerating system identity",
        "event_types": ["process_create", "process_tree"],
        "severity": "low",
        "mitre_id": "T1033",
        "mitre_tactic": "Discovery",
        "base_score": 30,
        "enabled": True,
        "builtin": True,
        "match_field": "process_name",
        "match_pattern": r"^whoami",
    },
    {
        "rule_id": "CV-061",
        "name": "net user or localgroup command",
        "description": "User/group manipulation via net command",
        "event_types": ["process_create", "process_tree"],
        "severity": "medium",
        "mitre_id": "T1069",
        "mitre_tactic": "Discovery",
        "base_score": 50,
        "enabled": True,
        "builtin": True,
        "match_field": "cmdline",
        "match_pattern": r"net\s+(user|localgroup|accounts|group)",
    },
    {
        "rule_id": "CV-062",
        "name": "Privilege escalation attempt",
        "description": "Successful sudo/runas elevation to root/SYSTEM",
        "event_types": ["auth_success"],
        "severity": "high",
        "mitre_id": "T1548",
        "mitre_tactic": "Privilege Escalation",
        "base_score": 70,
        "enabled": True,
        "builtin": True,
    },
    # ── Inventory alerts ─────────────────────────────────────────────────────
    {
        "rule_id": "CV-070",
        "name": "Member added to admin group",
        "description": "User added to Administrators or Domain Admins (Event 4732)",
        "event_types": ["group_add"],
        "severity": "critical",
        "mitre_id": "T1098.001",
        "mitre_tactic": "Privilege Escalation",
        "base_score": 92,
        "enabled": True,
        "builtin": True,
    },
]

# Severity to numeric level (like Wazuh)
SEVERITY_LEVEL = {
    "info":     3,
    "low":      5,
    "medium":   8,
    "high":     12,
    "critical": 15,
}

C2_PORTS = {4444,1337,31337,8888,9999,6666,5555,1234,12345,54321,65535,3000,9001,6667,2222}

LOLBINS = {"certutil","mshta","regsvr32","installutil","msbuild","cmstp",
           "wmic","runscripthelper","syncappvpublishingserver","appsyncpublishingserver"}

CREDENTIAL_TOOLS = {"mimikatz","procdump","wce","gsecdump","pwdump","ntdsutil",
                     "lsadump","fgdump","cachedump","quarks-pwdump","meterpreter"}

OFFICE_APPS = {"winword.exe","excel.exe","outlook.exe","powerpnt.exe",
               "acrord32.exe","foxit.exe","wps.exe"}

SHELLS = {"cmd.exe","powershell.exe","wscript.exe","cscript.exe","bash.exe"}

def match_event(event: dict, rules: list) -> list:
    """
    Apply rules to a single event. Returns list of matched rule dicts.
    Each matched rule has 'final_score' added.
    """
    matched = []
    etype  = event.get("event_type", "")
    proc   = event.get("process", {})
    winev  = event.get("win_event", {})
    net    = event.get("network", {})
    reg    = event.get("registry", {})
    fim    = event.get("fim", {})
    inv    = event.get("inventory", {})

    pname   = (proc.get("name") or winev.get("process") or "").lower()
    cmdline = (proc.get("cmdline") or winev.get("cmdline") or winev.get("message") or "").lower()
    ppname  = (proc.get("parent_name") or "").lower()
    user    = (proc.get("user") or winev.get("user") or event.get("auth", {}).get("user") or "").lower()
    dst_port = int(net.get("dst_port", 0) or net.get("port", 0) or 0)
    dst_ip  = net.get("dst_ip", "") or net.get("remote_address", "")
    mitre   = event.get("mitre_technique", "")

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        rule_etypes = rule.get("event_types", [])
        if rule_etypes and etype not in rule_etypes:
            continue

        triggered = False
        rule_id = rule.get("rule_id","")

        # ── Per-rule logic ───────────────────────────────────────────────────
        if rule_id == "CV-001":  # Brute force - handled by correlation engine
            triggered = (etype == "auth_failure")

        elif rule_id == "CV-002":  # Login after failures - correlation
            triggered = (etype in ("auth_success","auth_failure"))

        elif rule_id == "CV-003":
            triggered = (etype == "auth_explicit")

        elif rule_id == "CV-004":
            triggered = (etype == "audit_clear")

        elif rule_id == "CV-010":
            triggered = (etype == "task_create")

        elif rule_id == "CV-011":
            triggered = (etype == "service_install")

        elif rule_id == "CV-012":
            triggered = (etype in ("registry_add","registry_modify"))

        elif rule_id == "CV-013":
            triggered = (etype == "user_create")

        elif rule_id == "CV-020":
            pattern = rule.get("match_pattern","")
            triggered = bool(re.search(pattern, cmdline, re.I)) if pattern else False

        elif rule_id == "CV-021":
            parent = ppname.replace("\\","").lower()
            child  = pname.replace("\\","").lower()
            parent_match = any(o in parent for o in [o.rstrip('.exe') for o in OFFICE_APPS])
            child_match  = any(s in child  for s in [s.rstrip('.exe') for s in SHELLS])
            triggered = parent_match and child_match

        elif rule_id == "CV-022":
            triggered = any(lb in pname for lb in LOLBINS)

        elif rule_id == "CV-023":
            triggered = any(ct in pname for ct in CREDENTIAL_TOOLS) or \
                        any(ct in cmdline for ct in CREDENTIAL_TOOLS)

        elif rule_id == "CV-030":
            triggered = (etype in ("user_enum","group_enum"))

        elif rule_id == "CV-031":  # Port scan - correlation
            triggered = (etype == "network_connect")

        elif rule_id == "CV-040":
            triggered = (etype in ("fim_change","fim_delete"))

        elif rule_id == "CV-050":
            triggered = (dst_port in C2_PORTS)

        elif rule_id == "CV-060":
            triggered = ("whoami" in pname or "whoami" in cmdline)

        elif rule_id == "CV-061":
            pattern = rule.get("match_pattern","")
            triggered = bool(re.search(pattern, cmdline, re.I)) if pattern else False

        elif rule_id == "CV-062":
            triggered = (etype == "auth_success" and
                         ("system" in user or "root" in user or "administrator" in user))

        elif rule_id == "CV-070":
            triggered = (etype == "group_add")

        else:
            # Custom rule - use pattern matching
            pattern = rule.get("match_pattern","")
            match_field = rule.get("match_field", "cmdline")
            if pattern:
                field_val = {
                    "cmdline":      cmdline,
                    "process_name": pname,
                    "user":         user,
                    "dst_ip":       dst_ip,
                    "dst_port":     str(dst_port),
                    "path":         fim.get("path","").lower(),
                    "key":          reg.get("key","").lower(),
                    "message":      winev.get("message","").lower(),
                }.get(match_field, cmdline)
                triggered = bool(re.search(pattern, field_val, re.I))
            elif rule_etypes:
                # No pattern = only fire on already-suspicious events
                # prevents flooding on high-volume event types
                # High-volume event types: only fire if event is pre-marked suspicious
                # AND the rule has no pattern (pattern rules handle their own matching)
                high_volume = {"network_connect","process_create","auth_success",
                               "auth_logoff","net_connection","syslog",
                               "session_open","session_close","resource_usage"}
                if etype in high_volume:
                    # Without a pattern, only fire if agent already flagged suspicious
                    # AND rule requires it (prevents spam from benign connections)
                    triggered = (etype in rule_etypes) and event.get("is_suspicious", False) and rule.get("enabled", True)
                    # Extra: for network_connect, require score >= 60 from rule
                    if triggered and etype == "network_connect":
                        triggered = rule.get("base_score", 0) >= 70
                else:
                    triggered = (etype in rule_etypes)

        if triggered:
            score = _compute_score(event, rule)
            matched.append({**rule, "final_score": score,
                             "rule_level": SEVERITY_LEVEL.get(rule.get("severity","low"), 5)})

    return matched


def _compute_score(event: dict, rule: dict) -> int:
    """Compute final risk score for a matched event."""
    base = rule.get("base_score", 50)

    # Boost for SYSTEM/root user
    user = (event.get("process", {}).get("user") or
            event.get("auth", {}).get("user") or "").lower()
    if "system" in user or "root" in user:
        base = min(100, int(base * 1.15))

    # Boost for suspicious parent chain
    if event.get("process", {}).get("parent_name",""):
        ppn = event["process"]["parent_name"].lower()
        if any(o.rstrip(".exe") in ppn for o in OFFICE_APPS):
            base = min(100, int(base * 1.2))

    return min(100, base)


# ── Correlation Engine ────────────────────────────────────────────────────────
class CorrelationEngine:
    """
    Tracks event windows to detect patterns like brute force,
    lateral movement, and C2 communication chains.
    """
    def __init__(self):
        self._auth_failures: dict = {}   # agent_id -> list of timestamps
        self._net_dests: dict     = {}   # agent_id -> set of (ip,port) in window
        self._success_after_fail: dict = {}  # agent_id -> list of fail timestamps

    def process(self, agent_id: str, event: dict, now: datetime) -> Optional[dict]:
        """Check if event triggers a correlation alert. Returns correlated alert or None."""
        etype = event.get("event_type","")
        ts    = now.timestamp()

        if etype == "auth_failure":
            if agent_id not in self._auth_failures:
                self._auth_failures[agent_id] = []
            self._success_after_fail.setdefault(agent_id, []).append(ts)
            self._auth_failures[agent_id].append(ts)
            # Clean window
            self._auth_failures[agent_id] = [t for t in self._auth_failures[agent_id] if ts-t <= 120]
            if len(self._auth_failures[agent_id]) >= 5:
                self._auth_failures[agent_id] = []  # reset after alert
                return {
                    "rule_id": "CV-001",
                    "name": "Brute force attack detected",
                    "description": f"5+ failed logins in 2 minutes",
                    "severity": "high",
                    "mitre_id": "T1110.001",
                    "mitre_tactic": "Credential Access",
                    "final_score": 82,
                    "rule_level": 12,
                    "correlated": True,
                }

        elif etype == "auth_success":
            fails = self._success_after_fail.get(agent_id, [])
            recent_fails = [t for t in fails if ts-t <= 300]  # 5 min window
            if len(recent_fails) >= 3:
                self._success_after_fail[agent_id] = []
                return {
                    "rule_id": "CV-002",
                    "name": "Login succeeded after multiple failures",
                    "description": f"Success after {len(recent_fails)} failures - possible credential stuffing",
                    "severity": "critical",
                    "mitre_id": "T1110.003",
                    "mitre_tactic": "Credential Access",
                    "final_score": 92,
                    "rule_level": 15,
                    "correlated": True,
                }

        elif etype == "network_connect":
            net = event.get("network", {})
            dst = (net.get("dst_ip",""), str(net.get("dst_port",0)))
            self._net_dests.setdefault(agent_id, {"ts": ts, "dests": set()})
            if ts - self._net_dests[agent_id]["ts"] > 60:
                self._net_dests[agent_id] = {"ts": ts, "dests": set()}
            self._net_dests[agent_id]["dests"].add(dst)
            if len(self._net_dests[agent_id]["dests"]) >= 20:
                self._net_dests[agent_id] = {"ts": ts, "dests": set()}
                return {
                    "rule_id": "CV-031",
                    "name": "Network scan detected",
                    "description": "20+ unique destinations in 60 seconds",
                    "severity": "medium",
                    "mitre_id": "T1046",
                    "mitre_tactic": "Discovery",
                    "final_score": 60,
                    "rule_level": 8,
                    "correlated": True,
                }
        return None


# Singleton correlation engine
_correlation_engine = CorrelationEngine()


def run_rules(agent_id: str, event: dict, custom_rules: list = None) -> list:
    """
    Run all rules (builtin + custom) against an event.
    Returns list of alert dicts.
    """
    all_rules = BUILTIN_RULES + (custom_rules or [])
    matched = match_event(event, all_rules)

    # Check correlation engine
    now = datetime.now(timezone.utc)
    corr = _correlation_engine.process(agent_id, event, now)
    if corr:
        # Don't duplicate if already matched by individual rule
        if not any(m.get("rule_id") == corr.get("rule_id") for m in matched):
            matched.append(corr)

    return matched


def get_builtin_rules() -> list:
    return BUILTIN_RULES


def severity_to_level(severity: str) -> int:
    return SEVERITY_LEVEL.get(severity, 5)
