"""
Cibervault Phase 4 — Entity Resolution + Unified Timeline

1. Entity Resolution — maps the same user across SSH, Wazuh, Windows agent, sudo,
   PAM, Active Directory into one unified identity. Resolves:
   - Same username on different hosts (ict@rc-siem = ict@TEAM-LIL)
   - Service accounts vs human accounts
   - IP-to-user correlation (which IPs belong to which user)

2. Unified Timeline — single chronological view of ALL activity for a resolved entity
   across every data source: Wazuh alerts, agent events, auth logs, UEBA anomalies,
   SOAR actions, process trees, file changes, network connections.

3. Entity Risk Profile — aggregated risk score, behavioral summary, asset access map

Add to main.py:
    from entity_resolution import router as entity_router, init_entity_resolution
    app.include_router(entity_router)
    # In startup: await init_entity_resolution(DB)
"""

import json
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone, timedelta

import aiosqlite
from fastapi import APIRouter, HTTPException, Request, Query

log = logging.getLogger("cibervault")

router = APIRouter(tags=["entity"])

_DB_PATH = ""


def init_entity_resolution(db_path: str):
    global _DB_PATH
    _DB_PATH = db_path


async def _ensure_entity_tables():
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS entities (
                entity_id       TEXT PRIMARY KEY,
                display_name    TEXT NOT NULL,
                entity_type     TEXT DEFAULT 'user',
                usernames       TEXT DEFAULT '[]',
                hostnames       TEXT DEFAULT '[]',
                ip_addresses    TEXT DEFAULT '[]',
                source_systems  TEXT DEFAULT '[]',
                first_seen      TEXT,
                last_seen       TEXT,
                total_events    INTEGER DEFAULT 0,
                risk_score      INTEGER DEFAULT 0,
                risk_level      TEXT DEFAULT 'low',
                is_service      INTEGER DEFAULT 0,
                is_admin        INTEGER DEFAULT 0,
                tags            TEXT DEFAULT '[]',
                notes           TEXT DEFAULT '',
                created_at      TEXT,
                updated_at      TEXT
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_entity_type ON entities(entity_type)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_entity_risk ON entities(risk_score DESC)")
        await db.commit()


# ══════════════════════════════════════════════════════════════════════════════
#  ENTITY RESOLUTION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

SERVICE_ACCOUNTS = {
    "system", "local service", "network service", "root", "daemon",
    "nobody", "www-data", "sshd", "systemd-network", "systemd-resolve",
    "messagebus", "syslog", "uuidd", "_apt", "wazuh", "ossec",
    "cibervault", "mysql", "postgres", "redis", "nginx", "apache",
}

ADMIN_INDICATORS = {"sudo", "wheel", "admin", "root", "administrator", "domain admins"}


@router.post("/api/v1/entities/resolve")
async def resolve_entities(request: Request):
    """Scan all events and resolve users into unified entities."""
    await _ensure_entity_tables()

    body = await request.json() if request.headers.get("content-type") == "application/json" else {}
    days = body.get("days", 30)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Gather all user references from events
        cur = await db.execute("""
            SELECT event_type, hostname, source_ip, event_time, payload,
                   severity, risk_score, mitre_id, mitre_tactic, rule_name
            FROM events
            WHERE event_time >= ?
            ORDER BY event_time ASC
        """, (cutoff,))
        events = [dict(r) for r in await cur.fetchall()]

    # Build user-host-IP mapping
    user_map = defaultdict(lambda: {
        "usernames": set(),
        "hostnames": set(),
        "ips": set(),
        "sources": set(),
        "events": 0,
        "first_seen": "",
        "last_seen": "",
        "max_risk": 0,
        "severities": defaultdict(int),
        "event_types": defaultdict(int),
        "mitre_tactics": set(),
        "is_admin": False,
        "sudo_count": 0,
    })

    for ev in events:
        user = _extract_user(ev)
        if not user:
            continue

        # Normalize username
        user_lower = user.lower().strip()
        if user_lower in SERVICE_ACCOUNTS:
            continue

        # Use lowercase username as the resolution key
        entity = user_map[user_lower]
        entity["usernames"].add(user_lower)

        host = ev.get("hostname", "")
        if host:
            entity["hostnames"].add(host)

        ip = ""
        try:
            p = json.loads(ev.get("payload", "{}"))
            ip = p.get("source_ip", p.get("src_ip", ""))
        except:
            pass
        if ev.get("source_ip"):
            ip = ev["source_ip"]
        if ip and ip not in ("", "127.0.0.1", "::1", "-"):
            entity["ips"].add(ip)

        # Track source system
        etype = ev.get("event_type", "")
        if etype.startswith("wazuh"):
            entity["sources"].add("wazuh")
        elif etype in ("auth_success", "auth_failure", "sudo_exec", "su_success", "su_failure", "session_start"):
            entity["sources"].add("linux_agent")
        elif etype in ("process_create", "process_tree"):
            entity["sources"].add("windows_agent" if "TEAM" in host.upper() else "linux_agent")
        else:
            entity["sources"].add("siem")

        entity["events"] += 1
        entity["event_types"][etype] += 1

        t = ev.get("event_time", "")
        if t:
            if not entity["first_seen"] or t < entity["first_seen"]:
                entity["first_seen"] = t
            if not entity["last_seen"] or t > entity["last_seen"]:
                entity["last_seen"] = t

        risk = ev.get("risk_score", 0)
        if isinstance(risk, (int, float)) and risk > entity["max_risk"]:
            entity["max_risk"] = int(risk)

        sev = ev.get("severity", "info")
        entity["severities"][sev] += 1

        tactic = ev.get("mitre_tactic", "")
        if tactic:
            entity["mitre_tactics"].add(tactic)

        # Admin detection
        if etype in ("sudo_exec", "su_success"):
            entity["is_admin"] = True
            entity["sudo_count"] += 1

    # Also check for IP-based correlation (same IP → multiple users = possible shared account or lateral movement)
    ip_to_users = defaultdict(set)
    for user, data in user_map.items():
        for ip in data["ips"]:
            ip_to_users[ip].add(user)

    # Merge users who share IPs and hostnames (likely same person)
    merged = _merge_related_users(user_map, ip_to_users)

    # Store resolved entities
    now = datetime.now(timezone.utc).isoformat()
    created = 0

    async with aiosqlite.connect(_DB_PATH) as db:
        # Clear old entities
        await db.execute("DELETE FROM entities")

        for entity_key, data in merged.items():
            entity_id = f"ENT-{hash(entity_key) % 100000:05d}"
            display_name = entity_key
            entity_type = "user"

            # Calculate composite risk
            risk = _calculate_entity_risk(data)
            risk_level = "critical" if risk >= 75 else "high" if risk >= 50 else "medium" if risk >= 25 else "low"

            is_service = 1 if entity_key in SERVICE_ACCOUNTS else 0
            is_admin = 1 if data["is_admin"] else 0

            tags = []
            if is_admin:
                tags.append("admin")
            if len(data["hostnames"]) > 1:
                tags.append("multi-host")
            if len(data["ips"]) > 3:
                tags.append("many-ips")
            if data["severities"].get("critical", 0) > 0:
                tags.append("critical-alerts")
            if data["sudo_count"] > 10:
                tags.append("heavy-sudo")

            await db.execute("""
                INSERT OR REPLACE INTO entities
                (entity_id, display_name, entity_type, usernames, hostnames, ip_addresses,
                 source_systems, first_seen, last_seen, total_events, risk_score, risk_level,
                 is_service, is_admin, tags, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                entity_id, display_name, entity_type,
                json.dumps(sorted(data["usernames"])),
                json.dumps(sorted(data["hostnames"])),
                json.dumps(sorted(data["ips"])),
                json.dumps(sorted(data["sources"])),
                data["first_seen"], data["last_seen"],
                data["events"], risk, risk_level,
                is_service, is_admin,
                json.dumps(tags), now, now,
            ))
            created += 1

        await db.commit()

    log.info(f"Entity resolution: {created} entities from {len(events)} events")
    return {"entities_resolved": created, "events_scanned": len(events), "days": days}


def _merge_related_users(user_map: dict, ip_to_users: dict) -> dict:
    """Merge users who are clearly the same person."""
    # For now, keep users separate — merge only obvious duplicates
    # (same name different case is already handled by lowering)
    return user_map


def _calculate_entity_risk(data: dict) -> int:
    """Calculate composite risk score for an entity."""
    risk = 0

    # Base risk from event severity
    risk += min(data["severities"].get("critical", 0) * 15, 40)
    risk += min(data["severities"].get("high", 0) * 5, 20)
    risk += min(data["severities"].get("medium", 0) * 1, 10)

    # Multi-host access
    if len(data["hostnames"]) >= 3:
        risk += 10
    elif len(data["hostnames"]) >= 2:
        risk += 5

    # Many IPs
    if len(data["ips"]) >= 5:
        risk += 10

    # MITRE tactic coverage (more stages = more concerning)
    risk += min(len(data["mitre_tactics"]) * 3, 15)

    # High event volume
    if data["events"] > 1000:
        risk += 5

    return min(risk, 100)


def _extract_user(ev: dict) -> str:
    """Extract username from event."""
    try:
        p = json.loads(ev.get("payload", "{}"))
    except:
        p = {}

    user = (p.get("user") or p.get("User") or
            p.get("win_event", {}).get("user", "") or
            p.get("auth", {}).get("user", "") or
            p.get("data", {}).get("srcuser", "") or
            p.get("data", {}).get("dstuser", "") or "")

    if isinstance(user, str):
        user = user.lower().strip()

    if user in ("", "system", "local service", "network service", "-", "(unknown)"):
        return ""
    return user


# ══════════════════════════════════════════════════════════════════════════════
#  ENTITY LISTING & DETAIL
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/api/v1/entities")
async def list_entities(entity_type: str = "", risk_level: str = "", limit: int = 50):
    """List all resolved entities."""
    await _ensure_entity_tables()
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        query = "SELECT * FROM entities WHERE 1=1"
        params = []
        if entity_type:
            query += " AND entity_type=?"
            params.append(entity_type)
        if risk_level:
            query += " AND risk_level=?"
            params.append(risk_level)
        query += " ORDER BY risk_score DESC, total_events DESC LIMIT ?"
        params.append(limit)

        cur = await db.execute(query, params)
        entities = []
        for r in await cur.fetchall():
            e = dict(r)
            for f in ("usernames", "hostnames", "ip_addresses", "source_systems", "tags"):
                try:
                    e[f] = json.loads(e.get(f, "[]"))
                except:
                    e[f] = []
            entities.append(e)

    return {"entities": entities, "total": len(entities)}


@router.get("/api/v1/entities/{entity_name}")
async def get_entity_detail(entity_name: str):
    """Get full entity profile with recent activity."""
    await _ensure_entity_tables()

    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        cur = await db.execute(
            "SELECT * FROM entities WHERE display_name=? OR entity_id=?",
            (entity_name.lower(), entity_name)
        )
        entity = await cur.fetchone()
        if not entity:
            raise HTTPException(404, f"Entity '{entity_name}' not found")
        entity = dict(entity)
        for f in ("usernames", "hostnames", "ip_addresses", "source_systems", "tags"):
            try:
                entity[f] = json.loads(entity.get(f, "[]"))
            except:
                entity[f] = []

    return {"entity": entity}


@router.patch("/api/v1/entities/{entity_name}")
async def update_entity(entity_name: str, request: Request):
    """Update entity notes, tags, or type."""
    body = await request.json()
    now = datetime.now(timezone.utc).isoformat()

    updates = []
    params = []
    for field in ("notes", "entity_type"):
        if field in body:
            updates.append(f"{field}=?")
            params.append(body[field])
    if "tags" in body:
        updates.append("tags=?")
        params.append(json.dumps(body["tags"]))

    if not updates:
        raise HTTPException(400, "No fields to update")

    updates.append("updated_at=?")
    params.append(now)
    params.append(entity_name.lower())

    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            f"UPDATE entities SET {','.join(updates)} WHERE display_name=?", params
        )
        await db.commit()

    return {"status": "updated"}


# ══════════════════════════════════════════════════════════════════════════════
#  UNIFIED TIMELINE
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/api/v1/entities/{entity_name}/timeline")
async def entity_timeline(entity_name: str, hours: int = 24, limit: int = 200):
    """Unified timeline of ALL activity for an entity across all data sources."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    entity_name = entity_name.lower()

    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Get entity's IPs for broader matching
        cur = await db.execute(
            "SELECT ip_addresses FROM entities WHERE display_name=?", (entity_name,)
        )
        row = await cur.fetchone()
        entity_ips = []
        if row:
            try:
                entity_ips = json.loads(row["ip_addresses"])
            except:
                pass

        # Build query — search by username in payload AND by source IPs
        conditions = ["(payload LIKE ? OR payload LIKE ?)"]
        params = [f'%"{entity_name}"%', f'%{entity_name}%']

        for ip in entity_ips[:5]:
            conditions.append("source_ip=?")
            params.append(ip)

        where = " OR ".join(conditions)

        cur = await db.execute(f"""
            SELECT event_id, event_type, hostname, severity, risk_score,
                   source_ip, mitre_id, mitre_tactic, rule_name, event_time,
                   payload, is_suspicious
            FROM events
            WHERE event_time >= ? AND ({where})
            ORDER BY event_time DESC LIMIT ?
        """, [cutoff] + params + [limit])
        events = [dict(r) for r in await cur.fetchall()]

        # Also get SOAR actions related to entity IPs
        soar_events = []
        if entity_ips:
            for ip in entity_ips[:5]:
                cur = await db.execute("""
                    SELECT action_id, action_type, hostname, trigger_summary,
                           status, created_at, rule_name
                    FROM soar_actions
                    WHERE trigger_summary LIKE ? AND created_at >= ?
                    ORDER BY created_at DESC LIMIT 10
                """, (f'%{ip}%', cutoff))
                for r in await cur.fetchall():
                    soar_events.append({
                        "event_type": f"soar_{dict(r)['action_type']}",
                        "hostname": dict(r).get("hostname", ""),
                        "severity": "info",
                        "event_time": dict(r)["created_at"],
                        "description": f"SOAR: {dict(r)['rule_name']} → {dict(r)['action_type']} [{dict(r)['status']}]",
                        "source": "soar",
                    })

        # Get correlated incidents involving this entity
        incident_events = []
        try:
            cur = await db.execute("""
                SELECT incident_id, title, severity, status, created_at, event_count
                FROM correlated_incidents
                WHERE (affected_hosts LIKE ? OR source_ips LIKE ?)
                AND created_at >= ?
                ORDER BY created_at DESC LIMIT 10
            """, (f'%{entity_name}%', f'%{entity_name}%', cutoff))
            for r in await cur.fetchall():
                incident_events.append({
                    "event_type": "correlated_incident",
                    "hostname": "",
                    "severity": dict(r)["severity"],
                    "event_time": dict(r)["created_at"],
                    "description": f"Incident: {dict(r)['title']} ({dict(r)['event_count']} events) [{dict(r)['status']}]",
                    "source": "correlation",
                    "incident_id": dict(r)["incident_id"],
                })
        except:
            pass

    # Build unified timeline
    timeline = []

    for ev in events:
        try:
            payload = json.loads(ev.get("payload", "{}"))
        except:
            payload = {}

        # Determine source system
        etype = ev["event_type"]
        if etype.startswith("wazuh"):
            source = "wazuh"
            icon = "W"
        elif etype in ("auth_success", "auth_failure", "sudo_exec", "session_start", "session_end",
                       "su_success", "su_failure", "pam_failure", "brute_force_detected",
                       "user_created", "user_modified", "password_changed", "group_add"):
            source = "auth"
            icon = "A"
        elif etype in ("process_create", "process_tree"):
            source = "process"
            icon = "P"
        elif etype in ("file_modify", "file_create", "file_delete"):
            source = "fim"
            icon = "F"
        elif etype in ("network_connection", "new_listener"):
            source = "network"
            icon = "N"
        elif etype == "inventory":
            source = "inventory"
            icon = "I"
        else:
            source = "other"
            icon = "E"

        # Build description
        desc = payload.get("description", "")
        if not desc:
            desc = ev.get("rule_name", etype)
            if etype == "auth_success":
                desc = f"Login from {payload.get('source_ip', '?')} ({payload.get('method', '')})"
            elif etype == "auth_failure":
                desc = f"Failed login from {payload.get('source_ip', '?')}"
            elif etype == "sudo_exec":
                desc = f"sudo: {payload.get('command', '')[:100]}"
            elif etype == "process_create":
                desc = f"Process: {payload.get('name', '')} — {payload.get('cmdline', '')[:80]}"
            elif etype in ("file_modify", "file_create", "file_delete"):
                desc = f"File {etype.split('_')[1]}: {payload.get('path', '')}"
            elif etype == "network_connection":
                desc = f"Connection: {payload.get('process','')} → {payload.get('dest_ip','')}:{payload.get('dest_port','')}"

        timeline.append({
            "time": ev["event_time"],
            "type": etype,
            "source": source,
            "icon": icon,
            "hostname": ev.get("hostname", ""),
            "severity": ev.get("severity", "info"),
            "risk_score": ev.get("risk_score", 0),
            "description": desc[:200],
            "mitre_id": ev.get("mitre_id", ""),
            "mitre_tactic": ev.get("mitre_tactic", ""),
            "source_ip": ev.get("source_ip", ""),
            "is_suspicious": ev.get("is_suspicious", False),
            "event_id": ev.get("event_id", ""),
        })

    # Add SOAR and incident events
    for se in soar_events:
        timeline.append({
            "time": se["event_time"],
            "type": se["event_type"],
            "source": "soar",
            "icon": "S",
            "hostname": se.get("hostname", ""),
            "severity": "info",
            "risk_score": 0,
            "description": se["description"],
            "is_suspicious": False,
        })

    for ie in incident_events:
        timeline.append({
            "time": ie["event_time"],
            "type": "incident",
            "source": "correlation",
            "icon": "!",
            "hostname": "",
            "severity": ie["severity"],
            "risk_score": 80,
            "description": ie["description"],
            "is_suspicious": True,
        })

    # Sort by time descending
    timeline.sort(key=lambda t: t["time"], reverse=True)

    # Summary stats
    sources = defaultdict(int)
    severities = defaultdict(int)
    hosts = set()
    for t in timeline:
        sources[t["source"]] += 1
        severities[t["severity"]] += 1
        if t["hostname"]:
            hosts.add(t["hostname"])

    return {
        "entity": entity_name,
        "timeline": timeline[:limit],
        "total_events": len(timeline),
        "hours": hours,
        "summary": {
            "by_source": dict(sources),
            "by_severity": dict(severities),
            "hosts": sorted(hosts),
        }
    }


# ══════════════════════════════════════════════════════════════════════════════
#  ENTITY SUMMARY / DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/api/v1/entities/summary/stats")
async def entity_summary():
    """Entity resolution dashboard stats."""
    await _ensure_entity_tables()

    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        cur = await db.execute("SELECT COUNT(*) FROM entities")
        total = (await cur.fetchone())[0]

        cur = await db.execute("SELECT COUNT(*) FROM entities WHERE is_admin=1")
        admins = (await cur.fetchone())[0]

        cur = await db.execute("SELECT COUNT(*) FROM entities WHERE risk_level IN ('critical','high')")
        high_risk = (await cur.fetchone())[0]

        cur = await db.execute("""
            SELECT COUNT(DISTINCT json_each.value) FROM entities, json_each(entities.hostnames)
        """)
        try:
            unique_hosts = (await cur.fetchone())[0]
        except:
            unique_hosts = 0

        cur = await db.execute("""
            SELECT COUNT(DISTINCT json_each.value) FROM entities, json_each(entities.source_systems)
        """)
        try:
            unique_sources = (await cur.fetchone())[0]
        except:
            unique_sources = 0

        # Top risk entities
        cur = await db.execute("""
            SELECT display_name, risk_score, risk_level, total_events, hostnames, tags, is_admin
            FROM entities ORDER BY risk_score DESC LIMIT 5
        """)
        top_risk = []
        for r in await cur.fetchall():
            e = dict(r)
            try:
                e["hostnames"] = json.loads(e.get("hostnames", "[]"))
                e["tags"] = json.loads(e.get("tags", "[]"))
            except:
                pass
            top_risk.append(e)

        # Multi-host users (potential lateral movement)
        cur = await db.execute("""
            SELECT display_name, hostnames, risk_score FROM entities
            WHERE json_array_length(hostnames) >= 2
            ORDER BY risk_score DESC LIMIT 5
        """)
        multi_host = []
        for r in await cur.fetchall():
            e = dict(r)
            try:
                e["hostnames"] = json.loads(e.get("hostnames", "[]"))
            except:
                pass
            multi_host.append(e)

    return {
        "total_entities": total,
        "admin_entities": admins,
        "high_risk_entities": high_risk,
        "unique_hosts": unique_hosts,
        "data_sources": unique_sources,
        "top_risk": top_risk,
        "multi_host_users": multi_host,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  AI ENTITY INVESTIGATION
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/api/v1/entities/{entity_name}/ai-investigate")
async def ai_investigate_entity(entity_name: str, request: Request):
    """AI-powered comprehensive entity investigation using unified timeline."""
    entity_name = entity_name.lower()

    # Get entity profile
    try:
        detail = await get_entity_detail(entity_name)
        entity = detail["entity"]
    except:
        entity = {"display_name": entity_name, "total_events": 0}

    # Get timeline
    timeline_data = await entity_timeline(entity_name, hours=48, limit=50)
    timeline = timeline_data["timeline"]
    summary = timeline_data["summary"]

    if not timeline:
        return {"entity": entity_name, "analysis": {"verdict": "no_data", "summary": "No activity found"}}

    # Build context for AI
    timeline_text = ""
    for i, t in enumerate(timeline[:30]):
        susp = " [!SUSPICIOUS]" if t.get("is_suspicious") else ""
        timeline_text += f"{t['time'][:19]} [{t['source'].upper()}] [{t['severity']}] {t['hostname']}: {t['description']}{susp}\n"

    from ai_analyst import call_llm

    system = """You are a senior threat analyst investigating a unified entity profile.
You have access to the complete timeline across all data sources: auth logs, Wazuh SIEM,
endpoint agents, file integrity, network connections, SOAR actions, and correlated incidents.

Analyze the entity's behavior pattern and provide:
- Overall threat assessment
- Activity narrative (what this entity has been doing)
- Key risk indicators
- Whether this looks like a legitimate user, compromised account, or attacker

Respond ONLY with JSON:
{
  "verdict": "legitimate|compromised|suspicious|attacker|service_account",
  "confidence": "high|medium|low",
  "risk_score": 0-100,
  "summary": "2-3 sentence overview",
  "activity_narrative": "What this entity has been doing across all systems",
  "risk_indicators": ["indicator1", "indicator2"],
  "benign_indicators": ["indicator1"],
  "data_sources_seen": ["source1", "source2"],
  "recommended_actions": ["action1", "action2"],
  "notable_findings": ["finding1", "finding2"]
}"""

    prompt = f"""Investigate entity: {entity_name}

ENTITY PROFILE:
- Total events: {entity.get('total_events', 0)}
- Risk score: {entity.get('risk_score', 0)} ({entity.get('risk_level', '?')})
- Hosts: {entity.get('hostnames', [])}
- IPs: {entity.get('ip_addresses', [])}
- Data sources: {entity.get('source_systems', [])}
- Admin: {entity.get('is_admin', False)}
- Tags: {entity.get('tags', [])}
- First seen: {entity.get('first_seen', '?')}
- Last seen: {entity.get('last_seen', '?')}

ACTIVITY SUMMARY (last 48h):
- By source: {summary.get('by_source', {})}
- By severity: {summary.get('by_severity', {})}
- Active hosts: {summary.get('hosts', [])}

UNIFIED TIMELINE ({len(timeline)} events):
{timeline_text}

Provide comprehensive threat assessment as JSON:"""

    try:
        result = await call_llm(prompt, system, max_tokens=600, task="analyze")
        parsed = {}
        try:
            parsed = json.loads(result)
        except:
            import re as re_mod
            m = re_mod.search(r'\{.*\}', result, re_mod.DOTALL)
            if m:
                try:
                    parsed = json.loads(m.group())
                except:
                    pass

        if not parsed.get("verdict"):
            parsed = {"verdict": "needs_review", "summary": result[:300], "risk_score": 50}

        return {
            "entity": entity_name,
            "analysis": parsed,
            "profile": {
                "total_events": entity.get("total_events", 0),
                "risk_score": entity.get("risk_score", 0),
                "hostnames": entity.get("hostnames", []),
                "ip_addresses": entity.get("ip_addresses", []),
                "data_sources": entity.get("source_systems", []),
            },
            "timeline_events": len(timeline),
        }
    except Exception as e:
        return {"entity": entity_name, "error": str(e)}
