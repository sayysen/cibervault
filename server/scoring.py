"""
Cibervault EDR — Incident Scoring Engine

Based on industry research:
- Splunk RBA: accumulates risk per entity, reduces false positives by 90%
- Elastic Security: aggregated alert score + asset criticality contribution
- CrowdStrike UEBA: AI-powered scores with MITRE ATT&CK tactic weighting
- MIT CISS: severity × criticality weighting formula

Final score = min(100, base × mitre_weight × asset_weight × freq_boost × fp_dampener)
"""

from __future__ import annotations
import json
from datetime import datetime, timedelta
from typing import Optional
import aiosqlite
from database import DB


# ─── Base scores by detection severity ───────────────────────────────────────

SEVERITY_BASE: dict[str, float] = {
    "critical": 90.0,
    "high":     70.0,
    "medium":   45.0,
    "low":      20.0,
    "info":      5.0,
}

# ─── MITRE ATT&CK tactic weights (kill chain position) ───────────────────────
# Later stages = higher weight. Based on MITRE ATT&CK kill chain progression.
# Source: Risk-Based MITRE TTP Scoring research (ACM 2025)

MITRE_TACTIC_WEIGHTS: dict[str, float] = {
    # Early kill chain — lower weights
    "reconnaissance":         0.50,
    "resource-development":   0.55,
    "initial-access":         0.70,
    "execution":              0.80,
    "persistence":            0.85,
    "privilege-escalation":   0.90,
    "defense-evasion":        0.85,
    "credential-access":      0.90,
    "discovery":              0.65,
    # Late kill chain — high weights (most dangerous)
    "lateral-movement":       1.10,
    "collection":             0.95,
    "command-and-control":    1.20,
    "exfiltration":           1.30,
    "impact":                 1.40,
    # Default if tactic unknown
    "unknown":                1.00,
}

# Map common MITRE technique IDs to their tactic
TECHNIQUE_TO_TACTIC: dict[str, str] = {
    "T1059": "execution",          "T1059.001": "execution",
    "T1059.003": "execution",
    "T1027": "defense-evasion",
    "T1041": "exfiltration",
    "T1003": "credential-access",  "T1003.001": "credential-access",
    "T1053": "persistence",        "T1053.003": "persistence",
    "T1053.005": "persistence",
    "T1078": "initial-access",
    "T1090": "command-and-control",
    "T1105": "command-and-control",
    "T1558": "credential-access",  "T1558.003": "credential-access",
    "T1566": "initial-access",     "T1566.001": "initial-access",
    "T1082": "discovery",
    "T1046": "discovery",
    "T1021": "lateral-movement",
    "T1040": "credential-access",
    "T1110": "credential-access",
    "T1486": "impact",
    "T1490": "impact",
    "T1547": "persistence",
}

# ─── Asset criticality weights ────────────────────────────────────────────────
# Based on Fidelis/Elastic asset criticality model

ASSET_CRITICALITY: dict[str, float] = {
    "critical":   1.40,  # Domain controllers, primary servers
    "high":       1.25,  # Secondary servers, VPN gateways
    "medium":     1.10,  # Servers (web, DB, etc.)
    "low":        1.00,  # Standard workstations
    "minimal":    0.80,  # Test/dev machines
}

# Hostnames that suggest high criticality assets
CRITICAL_HOSTNAME_PATTERNS = ["dc", "ad", "domain", "ctrl"]
HIGH_HOSTNAME_PATTERNS      = ["srv", "server", "vpn", "gw", "gateway", "db", "sql"]
MEDIUM_HOSTNAME_PATTERNS    = ["web", "app", "api", "mail", "lnx"]


def infer_asset_criticality(hostname: str) -> str:
    """Infer asset criticality from hostname patterns."""
    h = hostname.lower()
    for p in CRITICAL_HOSTNAME_PATTERNS:
        if p in h: return "critical"
    for p in HIGH_HOSTNAME_PATTERNS:
        if p in h: return "high"
    for p in MEDIUM_HOSTNAME_PATTERNS:
        if p in h: return "medium"
    return "low"


def infer_mitre_tactic(event: dict) -> str:
    """Infer MITRE tactic from event data."""
    # Check explicit MITRE field
    mitre = event.get("mitre_technique") or event.get("mitre") or ""
    if mitre:
        for tech, tactic in TECHNIQUE_TO_TACTIC.items():
            if mitre.startswith(tech):
                return tactic

    # Infer from event type + process data
    ev_type = event.get("event_type", "")
    process = event.get("process", {})
    cmdline = (process.get("cmdline") or "").lower()
    procname = (process.get("name") or "").lower()
    network = event.get("network", {})

    if ev_type in ("cron_create", "service_create", "scheduled_task_create", "registry_persistence"):
        return "persistence"
    if ev_type == "privilege_escalation":
        return "privilege-escalation"
    if ev_type in ("file_create", "file_modify") and "/tmp" in (event.get("file", {}).get("path") or ""):
        return "defense-evasion"
    if ev_type in ("auth_failure", "auth_success") and event.get("auth", {}).get("source_ip"):
        return "credential-access"
    if ev_type == "network_connect":
        dst_port = network.get("dst_port", 0)
        if dst_port in (443, 80, 8080, 8443):
            return "command-and-control"
        return "lateral-movement"
    if "powershell" in procname or "cmd" in procname:
        if any(x in cmdline for x in ["-enc", "invoke-expression", "downloadstring"]):
            return "execution"
        if any(x in cmdline for x in ["whoami", "ipconfig", "net user", "nltest"]):
            return "discovery"
        if any(x in cmdline for x in ["vssadmin", "bcdedit", "wbadmin"]):
            return "impact"

    return "unknown"


# ─── Core scoring function ────────────────────────────────────────────────────

async def score_incident(
    event: dict,
    agent_id: str,
    hostname: str,
    base_severity: str,
    fp_exclusions: list[dict],
) -> dict:
    """
    Compute a 0-100 risk score for an event using the multi-factor model.
    Returns a scoring breakdown dict.
    """
    # ── Step 1: Base score from detection severity
    base = SEVERITY_BASE.get(base_severity, 20.0)

    # ── Step 2: MITRE tactic weight
    tactic       = infer_mitre_tactic(event)
    mitre_weight = MITRE_TACTIC_WEIGHTS.get(tactic, 1.0)

    # ── Step 3: Asset criticality
    criticality_label  = infer_asset_criticality(hostname)
    asset_weight       = ASSET_CRITICALITY.get(criticality_label, 1.0)

    # ── Step 4: Frequency boost — how many similar events for this host in last hour?
    freq_count   = await count_recent_events(agent_id, event.get("event_type", ""), hours=1)
    freq_boost   = min(1.0 + (freq_count - 1) * 0.10, 1.5)

    # ── Step 5: False positive dampener
    fp_match = check_fp_exclusion(event, fp_exclusions)
    fp_weight = 0.0 if fp_match else 1.0

    # ── Compute final score
    raw   = base * mitre_weight * asset_weight * freq_boost * fp_weight
    score = round(min(100.0, raw), 1)

    # ── Map score to severity band
    severity_band = score_to_severity(score)

    return {
        "score":              score,
        "severity_band":      severity_band,
        "suppressed_by_fp":   bool(fp_match),
        "fp_rule":            fp_match,
        "breakdown": {
            "base_score":         base,
            "mitre_tactic":       tactic,
            "mitre_weight":       mitre_weight,
            "asset_criticality":  criticality_label,
            "asset_weight":       asset_weight,
            "frequency_count":    freq_count,
            "frequency_boost":    freq_boost,
            "fp_dampener":        fp_weight,
        }
    }


def score_to_severity(score: float) -> str:
    if score >= 80: return "critical"
    if score >= 60: return "high"
    if score >= 40: return "medium"
    if score >= 20: return "low"
    return "info"


# ─── Frequency counter ────────────────────────────────────────────────────────

async def count_recent_events(agent_id: str, event_type: str, hours: int = 1) -> int:
    cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    async with aiosqlite.connect(DB) as db:
        cur = await db.execute("""
            SELECT COUNT(*) FROM events
            WHERE agent_id=? AND event_type=? AND created_at > ?
        """, (agent_id, event_type, cutoff))
        row = await cur.fetchone()
    return row[0] if row else 1


# ─── False positive exclusion check ──────────────────────────────────────────

def check_fp_exclusion(event: dict, exclusions: list[dict]) -> Optional[str]:
    """
    Check if an event matches any FP exclusion rule.
    Returns the exclusion rule name if matched, else None.
    """
    process  = event.get("process", {})
    hostname = event.get("host", {}).get("hostname", "")
    procname = (process.get("name") or "").lower()
    cmdline  = (process.get("cmdline") or "").lower()
    ev_type  = event.get("event_type", "")

    for excl in exclusions:
        # Match criteria (all specified fields must match)
        matches = True

        if excl.get("hostname") and excl["hostname"].lower() not in hostname.lower():
            matches = False
        if excl.get("process_name") and excl["process_name"].lower() not in procname:
            matches = False
        if excl.get("cmdline_contains") and excl["cmdline_contains"].lower() not in cmdline:
            matches = False
        if excl.get("event_type") and excl["event_type"] != ev_type:
            matches = False

        if matches:
            return excl.get("name", "unnamed-exclusion")

    return None


# ─── Load FP exclusions from DB ───────────────────────────────────────────────

async def load_fp_exclusions() -> list[dict]:
    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM fp_exclusions WHERE active=1 ORDER BY created_at DESC"
        )
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


# ─── Scoreboard aggregation ───────────────────────────────────────────────────

async def get_scoreboard(limit: int = 20) -> list[dict]:
    """
    Returns top incidents ranked by risk score.
    Includes score breakdown for transparency.
    """
    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("""
            SELECT
                e.event_id, e.hostname, e.event_type, e.event_time,
                e.severity, e.risk_score, e.score_breakdown,
                e.is_fp, e.fp_verdict,
                a.os, a.ip_address, a.group_name
            FROM events e
            LEFT JOIN agents a ON e.agent_id = a.agent_id
            WHERE e.is_suspicious = 1
            ORDER BY e.risk_score DESC
            LIMIT ?
        """, (limit,))
        rows = await cur.fetchall()

    result = []
    for r in rows:
        row = dict(r)
        if row.get("score_breakdown"):
            try:
                row["score_breakdown"] = json.loads(row["score_breakdown"])
            except Exception:
                pass
        result.append(row)
    return result


async def get_score_distribution() -> dict:
    """Returns count of incidents per severity band."""
    async with aiosqlite.connect(DB) as db:
        cur = await db.execute("""
            SELECT
                SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN risk_score >= 60 AND risk_score < 80 THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN risk_score >= 40 AND risk_score < 60 THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN risk_score >= 20 AND risk_score < 40 THEN 1 ELSE 0 END) as low,
                SUM(CASE WHEN risk_score < 20 THEN 1 ELSE 0 END) as info,
                AVG(risk_score) as avg_score,
                COUNT(*) as total
            FROM events WHERE is_suspicious=1
        """)
        row = await cur.fetchone()
    if row:
        return {
            "critical": row[0] or 0, "high": row[1] or 0,
            "medium": row[2] or 0,   "low":  row[3] or 0,
            "info":   row[4] or 0,   "avg_score": round(row[5] or 0, 1),
            "total":  row[6] or 0,
        }
    return {}
