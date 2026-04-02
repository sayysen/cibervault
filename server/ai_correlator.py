"""
Cibervault AI Alert Correlator
Groups related alerts into incidents using time-window clustering,
MITRE kill chain progression, and AI-powered summarization.

Features:
- Heuristic pre-clustering (time, IP, host, kill chain)
- AI summarization of each incident cluster
- Kill chain stage tracking
- Automatic severity escalation for correlated incidents
- Incident lifecycle management
"""

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from collections import defaultdict

import aiosqlite

log = logging.getLogger("correlator")

# ── Kill Chain ordering for progression detection ─────────────────────────────
KILL_CHAIN_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access",
    "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
]
KILL_CHAIN_INDEX = {t: i for i, t in enumerate(KILL_CHAIN_ORDER)}


# ── DB Schema ─────────────────────────────────────────────────────────────────

async def init_correlator_db(db_path: str):
    """Create correlation tables."""
    async with aiosqlite.connect(db_path) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS correlated_incidents (
                incident_id    TEXT PRIMARY KEY,
                title          TEXT NOT NULL,
                summary        TEXT DEFAULT '',
                severity       TEXT DEFAULT 'high',
                status         TEXT DEFAULT 'open',
                kill_chain_stages TEXT DEFAULT '[]',
                affected_hosts TEXT DEFAULT '[]',
                source_ips     TEXT DEFAULT '[]',
                mitre_techniques TEXT DEFAULT '[]',
                event_ids      TEXT DEFAULT '[]',
                event_count    INTEGER DEFAULT 0,
                first_seen     TEXT,
                last_seen      TEXT,
                ai_analysis    TEXT DEFAULT '',
                priority       TEXT DEFAULT 'P2',
                assigned_to    TEXT DEFAULT '',
                created_at     TEXT,
                updated_at     TEXT
            )
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_corr_status ON correlated_incidents(status)
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_corr_severity ON correlated_incidents(severity)
        """)
        await db.commit()
    log.info("Correlator DB initialized")


# ── Correlation Engine ────────────────────────────────────────────────────────

async def correlate_alerts(db_path: str, window_hours: int = 4, min_cluster: int = 2) -> list:
    """
    Run correlation on recent uncorrelated suspicious events.
    Groups by: source IP, hostname, MITRE tactic progression, time proximity.
    Returns list of new incidents created.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()

    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row

        # Get already-correlated event IDs
        cur = await db.execute("SELECT event_ids FROM correlated_incidents WHERE status != 'closed'")
        existing_ids = set()
        for row in await cur.fetchall():
            try:
                ids = json.loads(row["event_ids"])
                existing_ids.update(ids)
            except:
                pass

        # Fetch recent suspicious events
        cur = await db.execute("""
            SELECT event_id, agent_id, event_type, hostname, severity,
                   risk_score, source_ip, mitre_id, mitre_tactic,
                   rule_name, event_time, payload
            FROM events
            WHERE is_suspicious=1 AND event_time >= ?
            ORDER BY event_time ASC
        """, (cutoff,))
        events = [dict(r) for r in await cur.fetchall()]

    # Filter out already-correlated events
    events = [e for e in events if e["event_id"] not in existing_ids]

    if len(events) < min_cluster:
        return []

    # ── Phase 1: Heuristic Clustering ───────────────────────────────────
    clusters = _cluster_events(events)

    # Filter clusters below minimum size
    clusters = [c for c in clusters if len(c) >= min_cluster]

    if not clusters:
        return []

    # ── Phase 2: Create incidents ───────────────────────────────────────
    new_incidents = []
    now = datetime.now(timezone.utc).isoformat()

    for cluster in clusters:
        incident_id = f"INC-{str(uuid.uuid4())[:8].upper()}"

        hosts = list(set(e.get("hostname", "") for e in cluster if e.get("hostname")))
        ips = list(set(e.get("source_ip", "") for e in cluster if e.get("source_ip")))
        mitres = list(set(e.get("mitre_id", "") for e in cluster if e.get("mitre_id")))
        tactics = list(set(e.get("mitre_tactic", "") for e in cluster if e.get("mitre_tactic")))
        event_ids = [e["event_id"] for e in cluster]
        severities = [e.get("severity", "info") for e in cluster]

        # Escalate severity based on cluster analysis
        incident_sev = _escalate_severity(severities, tactics)
        priority = _calc_priority(incident_sev, len(cluster), tactics)

        times = [e.get("event_time", "") for e in cluster if e.get("event_time")]
        first_seen = min(times) if times else now
        last_seen = max(times) if times else now

        # Generate title from cluster characteristics
        title = _generate_title(cluster, tactics, hosts)

        incident = {
            "incident_id": incident_id,
            "title": title,
            "summary": "",
            "severity": incident_sev,
            "status": "open",
            "kill_chain_stages": tactics,
            "affected_hosts": hosts,
            "source_ips": ips,
            "mitre_techniques": mitres,
            "event_ids": event_ids,
            "event_count": len(cluster),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "priority": priority,
        }

        async with aiosqlite.connect(db_path) as db:
            await db.execute("""
                INSERT INTO correlated_incidents
                (incident_id, title, summary, severity, status, kill_chain_stages,
                 affected_hosts, source_ips, mitre_techniques, event_ids, event_count,
                 first_seen, last_seen, priority, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                incident_id, title, "",
                incident_sev, "open",
                json.dumps(tactics), json.dumps(hosts),
                json.dumps(ips), json.dumps(mitres),
                json.dumps(event_ids), len(cluster),
                first_seen, last_seen, priority, now, now,
            ))
            await db.commit()

        new_incidents.append(incident)
        log.info(f"Correlated incident created: {incident_id} — {title} ({len(cluster)} events)")

    return new_incidents


def _cluster_events(events: list) -> list:
    """
    Cluster events using multi-dimensional grouping:
    1. Same source IP within time window → group
    2. Same hostname within time window → group
    3. Kill chain progression on same host → group
    """
    clusters = []
    used = set()

    # Pass 1: Group by source IP (same attacker)
    ip_groups = defaultdict(list)
    for e in events:
        ip = e.get("source_ip", "")
        if ip and ip not in ("", "127.0.0.1", "::1", "-"):
            ip_groups[ip].append(e)

    for ip, group in ip_groups.items():
        if len(group) >= 2:
            ids = {e["event_id"] for e in group}
            if not ids & used:
                clusters.append(group)
                used |= ids

    # Pass 2: Group by hostname + time proximity (same target)
    host_groups = defaultdict(list)
    for e in events:
        if e["event_id"] in used:
            continue
        host = e.get("hostname", "")
        if host:
            host_groups[host].append(e)

    for host, group in host_groups.items():
        if len(group) >= 2:
            # Sub-cluster by time proximity (30 min windows)
            time_clusters = _time_cluster(group, window_minutes=30)
            for tc in time_clusters:
                if len(tc) >= 2:
                    ids = {e["event_id"] for e in tc}
                    if not ids & used:
                        clusters.append(tc)
                        used |= ids

    # Pass 3: Kill chain progression (multi-stage attacks)
    remaining = [e for e in events if e["event_id"] not in used]
    if len(remaining) >= 2:
        chain_clusters = _detect_kill_chain(remaining)
        for cc in chain_clusters:
            ids = {e["event_id"] for e in cc}
            if not ids & used:
                clusters.append(cc)
                used |= ids

    return clusters


def _time_cluster(events: list, window_minutes: int = 30) -> list:
    """Sub-cluster events into time windows."""
    if not events:
        return []

    sorted_events = sorted(events, key=lambda e: e.get("event_time", ""))
    clusters = []
    current = [sorted_events[0]]

    for e in sorted_events[1:]:
        try:
            prev_time = datetime.fromisoformat(current[-1].get("event_time", "").replace("Z", "+00:00"))
            curr_time = datetime.fromisoformat(e.get("event_time", "").replace("Z", "+00:00"))
            if (curr_time - prev_time).total_seconds() <= window_minutes * 60:
                current.append(e)
            else:
                clusters.append(current)
                current = [e]
        except:
            current.append(e)

    if current:
        clusters.append(current)

    return clusters


def _detect_kill_chain(events: list) -> list:
    """Detect multi-stage kill chain progressions."""
    clusters = []

    # Group by host
    host_events = defaultdict(list)
    for e in events:
        host = e.get("hostname", "unknown")
        host_events[host].append(e)

    for host, group in host_events.items():
        # Check if events span multiple kill chain stages
        stages = set()
        for e in group:
            tactic = e.get("mitre_tactic", "")
            if tactic and tactic in KILL_CHAIN_INDEX:
                stages.add(tactic)

        # If 2+ different kill chain stages → likely related attack
        if len(stages) >= 2:
            clusters.append(group)

    return clusters


def _escalate_severity(severities: list, tactics: list) -> str:
    """Escalate severity based on cluster analysis."""
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    max_sev = max(sev_order.get(s, 0) for s in severities)

    # Escalate if multiple kill chain stages detected
    n_stages = len(set(tactics))
    if n_stages >= 3:
        max_sev = min(max_sev + 1, 4)
    elif n_stages >= 2:
        max_sev = min(max_sev, 4)  # Keep or maintain

    rev = {v: k for k, v in sev_order.items()}
    return rev.get(max_sev, "high")


def _calc_priority(severity: str, event_count: int, tactics: list) -> str:
    """Calculate incident priority."""
    if severity == "critical" and event_count >= 5:
        return "P1"
    if severity == "critical" or (severity == "high" and len(tactics) >= 3):
        return "P2"
    if severity == "high":
        return "P3"
    return "P4"


def _generate_title(cluster: list, tactics: list, hosts: list) -> str:
    """Generate a descriptive incident title."""
    etypes = list(set(e.get("event_type", "") for e in cluster))
    host_str = hosts[0] if len(hosts) == 1 else f"{len(hosts)} hosts"

    if "auth_failure" in etypes and len(cluster) >= 5:
        return f"Brute Force Attack on {host_str}"
    if any(t in tactics for t in ["Lateral Movement"]):
        return f"Lateral Movement Detected on {host_str}"
    if any(t in tactics for t in ["Execution", "Defense Evasion"]):
        return f"Suspicious Execution Chain on {host_str}"
    if any(t in tactics for t in ["Command and Control"]):
        return f"C2 Communication from {host_str}"
    if any(t in tactics for t in ["Credential Access"]):
        return f"Credential Theft Attempt on {host_str}"
    if any(t in tactics for t in ["Exfiltration"]):
        return f"Data Exfiltration from {host_str}"
    if len(tactics) >= 2:
        return f"Multi-Stage Attack on {host_str} ({len(cluster)} events)"

    return f"Correlated Incident on {host_str} ({len(cluster)} alerts)"


# ── AI Enrichment ─────────────────────────────────────────────────────────────

async def ai_enrich_incident(db_path: str, incident_id: str, call_llm_fn) -> dict:
    """Use AI to analyze and summarize a correlated incident."""
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row

        cur = await db.execute("SELECT * FROM correlated_incidents WHERE incident_id=?", (incident_id,))
        incident = await cur.fetchone()
        if not incident:
            return {"error": "Incident not found"}
        incident = dict(incident)

        # Fetch related events
        event_ids = json.loads(incident.get("event_ids", "[]"))
        events = []
        for eid in event_ids[:20]:  # Limit to 20 for context size
            cur2 = await db.execute("SELECT * FROM events WHERE event_id=?", (eid,))
            row = await cur2.fetchone()
            if row:
                events.append(dict(row))

    if not events:
        return {"error": "No events found for incident"}

    # Build timeline for AI
    timeline = []
    for ev in sorted(events, key=lambda x: x.get("event_time", "")):
        timeline.append({
            "time": ev.get("event_time", "")[:19],
            "type": ev.get("event_type", ""),
            "host": ev.get("hostname", ""),
            "severity": ev.get("severity", ""),
            "source_ip": ev.get("source_ip", ""),
            "mitre": ev.get("mitre_id", ""),
            "tactic": ev.get("mitre_tactic", ""),
            "rule": ev.get("rule_name", "")[:60],
        })

    system = """You are a SOC incident analyst reviewing a correlated security incident.
Analyze the event cluster and provide:
1. A concise narrative of what happened (2-3 sentences)
2. The likely attack goal
3. Confidence level (high/medium/low) that this is a true positive
4. Recommended immediate actions (3-5 bullet points)
5. IOCs to watch for

Respond ONLY with JSON:
{
  "narrative": "...",
  "attack_goal": "...",
  "confidence": "high|medium|low",
  "true_positive_likelihood": "85%",
  "recommended_actions": ["action1", "action2", "action3"],
  "iocs": ["ioc1", "ioc2"],
  "risk_score": 75
}"""

    prompt = f"""Analyze this correlated incident:

Title: {incident.get('title', '')}
Priority: {incident.get('priority', 'P2')}
Affected: {', '.join(json.loads(incident.get('affected_hosts', '[]')))}
Kill Chain Stages: {', '.join(json.loads(incident.get('kill_chain_stages', '[]')))}
Event Count: {incident.get('event_count', 0)}

Event Timeline:
{json.dumps(timeline, indent=1)}

Provide your analysis as JSON:"""

    try:
        result = await call_llm_fn(prompt, system, max_tokens=800)

        # Parse JSON from response
        import re
        parsed = {}
        try:
            parsed = json.loads(result)
        except:
            m = re.search(r'\{.*\}', result, re.DOTALL)
            if m:
                try:
                    parsed = json.loads(m.group())
                except:
                    pass

        summary = parsed.get("narrative", result[:500])

        # Update incident with AI analysis
        async with aiosqlite.connect(db_path) as db:
            await db.execute("""
                UPDATE correlated_incidents
                SET summary=?, ai_analysis=?, updated_at=?
                WHERE incident_id=?
            """, (
                summary,
                json.dumps(parsed),
                datetime.now(timezone.utc).isoformat(),
                incident_id,
            ))
            await db.commit()

        return {"incident_id": incident_id, "analysis": parsed, "summary": summary}

    except Exception as e:
        log.error(f"AI enrichment failed for {incident_id}: {e}")
        return {"error": str(e)}
