from user_auth import get_current_user
"""
Cibervault EDR — Chart & Visualization API Endpoints
Add these routes to main.py (see UPGRADE_GUIDE.md)
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from collections import defaultdict

import aiosqlite
from fastapi import APIRouter, Depends, Query

log = logging.getLogger("cibervault")

# You'll wire DB and get_current_user when integrating into main.py
# For now these are placeholders — see UPGRADE_GUIDE.md
router = APIRouter(prefix="/api/v1/charts", tags=["charts"])


def _get_db_path():
    import os
    return os.environ.get("DB_PATH", "/opt/cibervault/data/cibervault.db")


# ── 1. Severity Distribution (Donut Chart) ──────────────────────────────────
@router.get("/severity-distribution")
async def severity_distribution(
    hours: int = Query(24, ge=1, le=720),
    current_user: dict = Depends(get_current_user)  # Replace with get_current_user
):
    """Severity breakdown for donut chart."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    async with aiosqlite.connect(_get_db_path()) as db:
        cur = await db.execute("""
            SELECT severity, COUNT(*) as cnt
            FROM events
            WHERE is_suspicious = 1 AND event_time >= ?
            GROUP BY severity
            ORDER BY cnt DESC
        """, (cutoff,))
        rows = await cur.fetchall()

    result = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for sev, cnt in rows:
        if sev in result:
            result[sev] = cnt
    return {"hours": hours, "distribution": result, "total": sum(result.values())}


# ── 2. Event Trend (Line Chart) ─────────────────────────────────────────────
@router.get("/event-trend")
async def event_trend(
    hours: int = Query(24, ge=1, le=720),
    bucket_minutes: int = Query(60, ge=5, le=1440),
    current_user: dict = Depends(get_current_user)
):
    """Time-series event counts bucketed by interval."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    async with aiosqlite.connect(_get_db_path()) as db:
        cur = await db.execute("""
            SELECT event_time, event_type, severity, is_suspicious
            FROM events
            WHERE event_time >= ?
            ORDER BY event_time ASC
        """, (cutoff,))
        rows = await cur.fetchall()

    # Bucket events
    buckets = defaultdict(lambda: {"total": 0, "suspicious": 0, "critical": 0, "high": 0, "medium": 0, "low": 0})
    for etime, etype, sev, is_susp in rows:
        try:
            dt = datetime.fromisoformat(etime.replace("Z", "+00:00"))
        except Exception:
            continue
        # Round down to bucket
        mins = dt.minute - (dt.minute % bucket_minutes)
        bucket_key = dt.replace(minute=mins, second=0, microsecond=0).isoformat()
        buckets[bucket_key]["total"] += 1
        if is_susp:
            buckets[bucket_key]["suspicious"] += 1
        if sev in buckets[bucket_key]:
            buckets[bucket_key][sev] += 1

    # Fill gaps
    series = []
    if buckets:
        sorted_keys = sorted(buckets.keys())
        series = [{"time": k, **buckets[k]} for k in sorted_keys]

    return {"hours": hours, "bucket_minutes": bucket_minutes, "series": series}


# ── 3. MITRE ATT&CK Heatmap ─────────────────────────────────────────────────
@router.get("/mitre-heatmap")
async def mitre_heatmap(
    hours: int = Query(168, ge=1, le=2160),
    current_user: dict = Depends(get_current_user)
):
    """MITRE tactic/technique frequency for heatmap visualization."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    async with aiosqlite.connect(_get_db_path()) as db:
        cur = await db.execute("""
            SELECT mitre_id, mitre_tactic, severity, COUNT(*) as cnt,
                   MAX(risk_score) as max_score
            FROM events
            WHERE is_suspicious = 1
              AND mitre_id IS NOT NULL AND mitre_id != ''
              AND event_time >= ?
            GROUP BY mitre_id, mitre_tactic
            ORDER BY cnt DESC
        """, (cutoff,))
        rows = await cur.fetchall()

    techniques = []
    tactics_count = defaultdict(int)
    for mid, tactic, sev, cnt, max_score in rows:
        techniques.append({
            "technique_id": mid,
            "tactic": tactic or "Unknown",
            "count": cnt,
            "max_score": max_score or 0,
            "severity": sev or "medium"
        })
        tactics_count[tactic or "Unknown"] += cnt

    # Standard MITRE tactic order
    TACTIC_ORDER = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact"
    ]
    tactics_sorted = []
    for t in TACTIC_ORDER:
        tactics_sorted.append({"tactic": t, "count": tactics_count.get(t, 0)})
    # Add any tactics not in standard order
    for t, c in tactics_count.items():
        if t not in TACTIC_ORDER:
            tactics_sorted.append({"tactic": t, "count": c})

    return {"hours": hours, "techniques": techniques, "tactics": tactics_sorted}


# ── 4. Top Hosts (Bar Chart) ────────────────────────────────────────────────
@router.get("/top-hosts")
async def top_hosts(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(10, ge=1, le=50),
    current_user: dict = Depends(get_current_user)
):
    """Most active hosts by alert count."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    async with aiosqlite.connect(_get_db_path()) as db:
        cur = await db.execute("""
            SELECT hostname, COUNT(*) as cnt,
                   SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as crit,
                   SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high,
                   SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END) as med,
                   MAX(risk_score) as max_score
            FROM events
            WHERE is_suspicious = 1 AND event_time >= ?
            GROUP BY hostname
            ORDER BY cnt DESC
            LIMIT ?
        """, (cutoff, limit))
        rows = await cur.fetchall()

    hosts = []
    for hostname, cnt, crit, high, med, max_score in rows:
        hosts.append({
            "hostname": hostname or "unknown",
            "total": cnt,
            "critical": crit or 0,
            "high": high or 0,
            "medium": med or 0,
            "max_score": max_score or 0,
        })
    return {"hours": hours, "hosts": hosts}


# ── 5. Event Type Breakdown (Horizontal Bar) ────────────────────────────────
@router.get("/event-types")
async def event_types_breakdown(
    hours: int = Query(24, ge=1, le=720),
    current_user: dict = Depends(get_current_user)
):
    """Event type frequency breakdown."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    async with aiosqlite.connect(_get_db_path()) as db:
        cur = await db.execute("""
            SELECT event_type, COUNT(*) as cnt,
                   SUM(CASE WHEN is_suspicious=1 THEN 1 ELSE 0 END) as suspicious
            FROM events
            WHERE event_time >= ?
            GROUP BY event_type
            ORDER BY cnt DESC
            LIMIT 15
        """, (cutoff,))
        rows = await cur.fetchall()

    types = [{"type": t, "total": c, "suspicious": s} for t, c, s in rows]
    return {"hours": hours, "types": types}


# ── 6. Process Tree for Event ────────────────────────────────────────────────
@router.get("/process-tree/{event_id}")
async def process_tree(
    event_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Build a process tree for an event — pulls related events by agent+process chain."""
    async with aiosqlite.connect(_get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        # Get the event
        cur = await db.execute("SELECT * FROM events WHERE event_id=?", (event_id,))
        event = await cur.fetchone()
        if not event:
            return {"error": "Event not found"}
        event = dict(event)

        payload = {}
        try:
            payload = json.loads(event.get("payload", "{}"))
        except Exception:
            pass

        proc = payload.get("process", payload.get("win_event", {}))
        agent_id = event.get("agent_id", "")

        # Fetch related process events from same agent in ±5 min window
        etime = event.get("event_time", "")
        try:
            evt = datetime.fromisoformat(etime.replace("Z", "+00:00"))
            t_start = (evt - timedelta(minutes=5)).isoformat()
            t_end = (evt + timedelta(minutes=5)).isoformat()
        except Exception:
            t_start = ""
            t_end = ""

        cur2 = await db.execute("""
            SELECT event_id, event_type, event_time, hostname, severity,
                   risk_score, payload, mitre_id, rule_name
            FROM events
            WHERE agent_id = ?
              AND event_type IN ('process_create','wazuh_alert')
              AND event_time BETWEEN ? AND ?
            ORDER BY event_time ASC
            LIMIT 50
        """, (agent_id, t_start, t_end))
        related = [dict(r) for r in await cur2.fetchall()]

    # Build tree nodes
    nodes = []
    edges = []
    seen_pids = {}

    def _add_process(p, ev_data, is_root=False):
        pid = str(p.get("pid", ""))
        ppid = str(p.get("ppid", p.get("parent_pid", "")))
        name = p.get("name", p.get("process_name", "unknown"))
        node = {
            "id": pid or f"node-{len(nodes)}",
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "cmdline": p.get("cmdline", p.get("command_line", "")),
            "user": p.get("user", p.get("user_name", "")),
            "sha256": p.get("sha256", ""),
            "path": p.get("path", p.get("image", "")),
            "time": ev_data.get("event_time", ""),
            "severity": ev_data.get("severity", "info"),
            "risk_score": ev_data.get("risk_score", 0),
            "mitre_id": ev_data.get("mitre_id", ""),
            "rule_name": ev_data.get("rule_name", ""),
            "is_root": is_root,
            "event_id": ev_data.get("event_id", ""),
        }
        if pid not in seen_pids:
            seen_pids[pid] = True
            nodes.append(node)
        if ppid and ppid != pid:
            edges.append({"from": ppid, "to": pid})
        return node

    # Add root event process
    if proc:
        _add_process(proc, event, is_root=True)

    # Add related processes
    for rel in related:
        try:
            rp = json.loads(rel.get("payload", "{}"))
        except Exception:
            rp = {}
        rproc = rp.get("process", rp.get("win_event", {}))
        if rproc and rproc.get("pid"):
            _add_process(rproc, rel)

    # Add parent node if not seen
    if proc and proc.get("ppid") or proc.get("parent_pid"):
        ppid = str(proc.get("ppid", proc.get("parent_pid", "")))
        if ppid and ppid not in seen_pids:
            nodes.append({
                "id": ppid, "pid": ppid, "ppid": "",
                "name": proc.get("parent_name", "parent"),
                "cmdline": "", "user": "", "sha256": "",
                "path": "", "time": "", "severity": "info",
                "risk_score": 0, "mitre_id": "", "rule_name": "",
                "is_root": False, "event_id": "",
            })

    return {
        "event_id": event_id,
        "hostname": event.get("hostname", ""),
        "nodes": nodes,
        "edges": edges,
        "timerange": {"start": t_start, "end": t_end},
    }


# ── 7. Attack Timeline ──────────────────────────────────────────────────────
@router.get("/attack-timeline")
async def attack_timeline(
    agent_id: str = Query(None),
    hours: int = Query(24, ge=1, le=720),
    current_user: dict = Depends(get_current_user)
):
    """Chronological attack timeline with kill-chain phases."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    query = """
        SELECT event_id, agent_id, event_type, event_time, hostname,
               severity, risk_score, mitre_id, mitre_tactic, rule_name,
               source_ip, payload
        FROM events
        WHERE is_suspicious = 1 AND event_time >= ?
    """
    params = [cutoff]
    if agent_id:
        query += " AND agent_id = ?"
        params.append(agent_id)
    query += " ORDER BY event_time ASC LIMIT 200"

    async with aiosqlite.connect(_get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(query, params)
        events = [dict(r) for r in await cur.fetchall()]

    # Group by kill-chain phase
    TACTIC_PHASE = {
        "Reconnaissance": 1, "Resource Development": 2, "Initial Access": 3,
        "Execution": 4, "Persistence": 5, "Privilege Escalation": 6,
        "Defense Evasion": 7, "Credential Access": 8, "Discovery": 9,
        "Lateral Movement": 10, "Collection": 11, "Command and Control": 12,
        "Exfiltration": 13, "Impact": 14,
    }

    timeline = []
    for ev in events:
        payload = {}
        try:
            payload = json.loads(ev.get("payload", "{}"))
        except Exception:
            pass

        tactic = ev.get("mitre_tactic", "Unknown")
        timeline.append({
            "event_id": ev["event_id"],
            "time": ev["event_time"],
            "hostname": ev.get("hostname", ""),
            "event_type": ev.get("event_type", ""),
            "severity": ev.get("severity", "info"),
            "risk_score": ev.get("risk_score", 0),
            "mitre_id": ev.get("mitre_id", ""),
            "tactic": tactic,
            "phase": TACTIC_PHASE.get(tactic, 0),
            "rule_name": ev.get("rule_name", ""),
            "source_ip": ev.get("source_ip", ""),
            "description": payload.get("description", payload.get("message",
                           payload.get("rule_desc", ev.get("rule_name", "")))),
        })

    return {"hours": hours, "agent_id": agent_id, "events": timeline}


# ── 8. Dashboard Summary Stats ──────────────────────────────────────────────
@router.get("/summary")
async def dashboard_summary(
    current_user: dict = Depends(get_current_user)
):
    """Comprehensive dashboard stats in a single call."""
    now = datetime.now(timezone.utc)
    h24 = (now - timedelta(hours=24)).isoformat()
    h1 = (now - timedelta(hours=1)).isoformat()

    async with aiosqlite.connect(_get_db_path()) as db:
        # Total events 24h
        cur = await db.execute(
            "SELECT COUNT(*) FROM events WHERE event_time >= ?", (h24,))
        total_24h = (await cur.fetchone())[0]

        # Suspicious 24h
        cur = await db.execute(
            "SELECT COUNT(*) FROM events WHERE is_suspicious=1 AND event_time >= ?", (h24,))
        suspicious_24h = (await cur.fetchone())[0]

        # Critical/High 24h
        cur = await db.execute("""
            SELECT COUNT(*) FROM events
            WHERE is_suspicious=1 AND severity IN ('critical','high') AND event_time >= ?
        """, (h24,))
        crithigh_24h = (await cur.fetchone())[0]

        # Events last hour
        cur = await db.execute(
            "SELECT COUNT(*) FROM events WHERE event_time >= ?", (h1,))
        events_1h = (await cur.fetchone())[0]

        # Online agents
        threshold = (now - timedelta(seconds=150)).isoformat()
        cur = await db.execute(
            "SELECT COUNT(*) FROM agents WHERE last_seen >= ?", (threshold,))
        agents_online = (await cur.fetchone())[0]

        # Total agents
        cur = await db.execute("SELECT COUNT(*) FROM agents")
        agents_total = (await cur.fetchone())[0]

        # Unresolved alerts
        cur = await db.execute(
            "SELECT COUNT(*) FROM events WHERE is_suspicious=1 AND fp_verdict IS NULL")
        unresolved = (await cur.fetchone())[0]

        # Mean risk score (suspicious, 24h)
        cur = await db.execute("""
            SELECT AVG(risk_score) FROM events
            WHERE is_suspicious=1 AND event_time >= ? AND risk_score > 0
        """, (h24,))
        avg_risk = (await cur.fetchone())[0] or 0

        # Top tactic 24h
        cur = await db.execute("""
            SELECT mitre_tactic, COUNT(*) as c FROM events
            WHERE is_suspicious=1 AND mitre_tactic IS NOT NULL
              AND mitre_tactic != '' AND event_time >= ?
            GROUP BY mitre_tactic ORDER BY c DESC LIMIT 1
        """, (h24,))
        top_tactic_row = await cur.fetchone()
        top_tactic = top_tactic_row[0] if top_tactic_row else "N/A"

    return {
        "total_events_24h": total_24h,
        "suspicious_24h": suspicious_24h,
        "critical_high_24h": crithigh_24h,
        "events_last_hour": events_1h,
        "agents_online": agents_online,
        "agents_total": agents_total,
        "unresolved_alerts": unresolved,
        "avg_risk_score": round(avg_risk, 1),
        "top_tactic": top_tactic,
        "timestamp": now.isoformat(),
    }


# ── 9. Command History (Active Response) ────────────────────────────────────
@router.get("/command-history")
async def command_history(
    agent_id: str = Query(None),
    limit: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user)
):
    """Full command history with results for active response panel."""
    query = """
        SELECT command_id, agent_id, command_type, parameters,
               status, result, issued_by, issued_at, completed_at
        FROM commands
    """
    params = []
    if agent_id:
        query += " WHERE agent_id = ?"
        params.append(agent_id)
    query += " ORDER BY issued_at DESC LIMIT ?"
    params.append(limit)

    async with aiosqlite.connect(_get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(query, params)
        rows = [dict(r) for r in await cur.fetchall()]

    # Parse JSON fields
    for r in rows:
        for field in ("parameters", "result"):
            if isinstance(r.get(field), str):
                try:
                    r[field] = json.loads(r[field])
                except Exception:
                    pass
    return {"commands": rows, "total": len(rows)}
