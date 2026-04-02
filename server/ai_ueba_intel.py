"""
Cibervault AI-UEBA Intelligence Layer (Phase 3)

1. Session Reconstruction — link auth → commands → file access into coherent sessions
2. Lateral Movement Detection — user on host A → same user on host B = chain
3. Data Exfiltration Scoring — large outbound, unusual destinations, data staging
4. Enhanced AI Investigation — feeds reconstructed sessions to AI for deep analysis

Add to main.py:
    from ai_ueba_intel import router as ueba_intel_router, init_ueba_intel
    app.include_router(ueba_intel_router)
    # In startup: init_ueba_intel(DB)
"""

import json
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone, timedelta

import aiosqlite
from fastapi import APIRouter, HTTPException, Request

log = logging.getLogger("cibervault")

router = APIRouter(tags=["ueba-intel"])

_DB_PATH = ""

def init_ueba_intel(db_path: str):
    global _DB_PATH
    _DB_PATH = db_path


# ══════════════════════════════════════════════════════════════════════════════
#  1. SESSION RECONSTRUCTION
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/api/v1/ueba/intel/sessions")
async def get_sessions(hours: int = 24, username: str = ""):
    """Reconstruct user sessions from event data.
    Links: auth_success → sudo_exec → process_create → file_modify → session_end
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Get auth events
        query = """
            SELECT event_id, event_type, hostname, source_ip, event_time, payload, severity, risk_score
            FROM events
            WHERE event_type IN ('auth_success','auth_failure','sudo_exec','su_success',
                                 'session_start','session_end','process_create','file_modify',
                                 'file_create','file_delete','network_connection')
            AND event_time >= ?
        """
        params = [cutoff]
        if username:
            query += " AND (payload LIKE ? OR payload LIKE ?)"
            params.extend([f'%"{username}"%', f'%{username}%'])
        query += " ORDER BY event_time ASC"

        cur = await db.execute(query, params)
        events = [dict(r) for r in await cur.fetchall()]

    # Build sessions
    sessions = _reconstruct_sessions(events)

    # Filter by username if specified
    if username:
        sessions = [s for s in sessions if s.get("user", "").lower() == username.lower()]

    return {
        "sessions": sessions,
        "total": len(sessions),
        "hours": hours,
    }


def _reconstruct_sessions(events: list) -> list:
    """Group events into user sessions."""
    # Group by (user, host, source_ip) with time gaps
    user_events = defaultdict(list)

    for ev in events:
        user = _extract_user_from_event(ev)
        if not user:
            continue
        host = ev.get("hostname", "")
        key = f"{user}@{host}"
        user_events[key].append(ev)

    sessions = []
    SESSION_GAP = 1800  # 30 min gap = new session

    for key, evts in user_events.items():
        user, host = key.split("@", 1)
        current_session = None

        for ev in evts:
            try:
                ev_time = datetime.fromisoformat(ev["event_time"].replace("Z", "+00:00"))
            except:
                continue

            if current_session is None or (ev_time - current_session["_last_time"]).total_seconds() > SESSION_GAP:
                # Start new session
                if current_session:
                    _finalize_session(current_session)
                    sessions.append(current_session)

                src_ip = ""
                try:
                    p = json.loads(ev.get("payload", "{}"))
                    src_ip = p.get("source_ip", ev.get("source_ip", ""))
                except:
                    pass

                current_session = {
                    "user": user,
                    "hostname": host,
                    "source_ip": src_ip,
                    "start_time": ev["event_time"],
                    "end_time": ev["event_time"],
                    "events": [],
                    "commands": [],
                    "files_accessed": [],
                    "network_connections": [],
                    "auth_events": [],
                    "risk_score": 0,
                    "max_severity": "info",
                    "suspicious_count": 0,
                    "_last_time": ev_time,
                }

            # Add to current session
            current_session["end_time"] = ev["event_time"]
            current_session["_last_time"] = ev_time
            current_session["events"].append({
                "type": ev["event_type"],
                "time": ev["event_time"][:19],
                "severity": ev.get("severity", "info"),
            })

            # Track risk
            risk = ev.get("risk_score", 0)
            if risk > current_session["risk_score"]:
                current_session["risk_score"] = risk
            sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            if sev_order.get(ev.get("severity", ""), 0) > sev_order.get(current_session["max_severity"], 0):
                current_session["max_severity"] = ev.get("severity", "info")

            # Categorize events
            try:
                payload = json.loads(ev.get("payload", "{}"))
            except:
                payload = {}

            etype = ev["event_type"]
            if etype in ("auth_success", "auth_failure"):
                current_session["auth_events"].append({
                    "type": etype, "ip": payload.get("source_ip", ""),
                    "method": payload.get("method", ""),
                })
            elif etype == "sudo_exec":
                cmd = payload.get("command", "")[:200]
                current_session["commands"].append(cmd)
            elif etype == "process_create":
                cmd = payload.get("cmdline", "")[:200]
                if cmd and not cmd.startswith("["):
                    current_session["commands"].append(cmd)
                if payload.get("suspicious_reason"):
                    current_session["suspicious_count"] += 1
            elif etype in ("file_modify", "file_create", "file_delete"):
                current_session["files_accessed"].append({
                    "path": payload.get("path", "")[:200],
                    "action": etype.replace("file_", ""),
                })
            elif etype == "network_connection":
                current_session["network_connections"].append({
                    "dest": f"{payload.get('dest_ip', '')}:{payload.get('dest_port', '')}",
                    "process": payload.get("process", ""),
                })

        if current_session:
            _finalize_session(current_session)
            sessions.append(current_session)

    # Sort by risk
    sessions.sort(key=lambda s: s["risk_score"], reverse=True)
    return sessions


def _finalize_session(session: dict):
    """Calculate session summary metrics."""
    session.pop("_last_time", None)
    try:
        start = datetime.fromisoformat(session["start_time"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(session["end_time"].replace("Z", "+00:00"))
        session["duration_minutes"] = round((end - start).total_seconds() / 60, 1)
    except:
        session["duration_minutes"] = 0
    session["event_count"] = len(session["events"])
    session["command_count"] = len(session["commands"])
    session["file_count"] = len(session["files_accessed"])


def _extract_user_from_event(ev: dict) -> str:
    try:
        p = json.loads(ev.get("payload", "{}"))
    except:
        p = {}
    user = (p.get("user") or p.get("User") or
            p.get("auth", {}).get("user", "") or "").lower().strip()
    if user in ("", "system", "local service", "network service", "-"):
        return ""
    return user


# ══════════════════════════════════════════════════════════════════════════════
#  2. LATERAL MOVEMENT DETECTION
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/api/v1/ueba/intel/lateral-movement")
async def detect_lateral_movement(hours: int = 24):
    """Detect potential lateral movement: same user/IP accessing multiple hosts."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Get auth successes across hosts
        cur = await db.execute("""
            SELECT event_type, hostname, source_ip, event_time, payload
            FROM events
            WHERE event_type IN ('auth_success', 'auth_explicit', 'su_success')
            AND event_time >= ?
            ORDER BY event_time ASC
        """, (cutoff,))
        auth_events = [dict(r) for r in await cur.fetchall()]

    # Track user→host and IP→host mappings
    user_hosts = defaultdict(lambda: defaultdict(list))  # user → {host: [times]}
    ip_hosts = defaultdict(lambda: defaultdict(list))    # ip → {host: [times]}

    for ev in auth_events:
        user = _extract_user_from_event(ev)
        host = ev.get("hostname", "")
        try:
            p = json.loads(ev.get("payload", "{}"))
            src_ip = p.get("source_ip", "")
        except:
            src_ip = ""

        if user and host:
            user_hosts[user][host].append(ev["event_time"])
        if src_ip and host and src_ip not in ("127.0.0.1", "::1", ""):
            ip_hosts[src_ip][host].append(ev["event_time"])

    chains = []

    # Detect user-based lateral movement (same user on 2+ hosts)
    for user, hosts in user_hosts.items():
        if len(hosts) >= 2:
            host_list = []
            for host, times in sorted(hosts.items(), key=lambda x: min(x[1])):
                host_list.append({
                    "hostname": host,
                    "first_access": min(times),
                    "access_count": len(times),
                })

            # Calculate time between first access on consecutive hosts
            hops = []
            for i in range(1, len(host_list)):
                try:
                    t1 = datetime.fromisoformat(host_list[i-1]["first_access"].replace("Z", "+00:00"))
                    t2 = datetime.fromisoformat(host_list[i]["first_access"].replace("Z", "+00:00"))
                    gap_min = (t2 - t1).total_seconds() / 60
                    hops.append({
                        "from": host_list[i-1]["hostname"],
                        "to": host_list[i]["hostname"],
                        "gap_minutes": round(gap_min, 1),
                    })
                except:
                    pass

            risk = min(95, 40 + len(hosts) * 15 + sum(1 for h in hops if h["gap_minutes"] < 30) * 10)

            chains.append({
                "type": "user_lateral",
                "user": user,
                "hosts": host_list,
                "hops": hops,
                "host_count": len(hosts),
                "risk_score": risk,
                "description": f"User '{user}' accessed {len(hosts)} hosts in {hours}h",
                "mitre_id": "T1021",
                "mitre_tactic": "Lateral Movement",
            })

    # Detect IP-based lateral movement (same IP accessing 2+ hosts)
    for ip, hosts in ip_hosts.items():
        if len(hosts) >= 2:
            host_list = []
            for host, times in sorted(hosts.items(), key=lambda x: min(x[1])):
                host_list.append({
                    "hostname": host,
                    "first_access": min(times),
                    "access_count": len(times),
                })

            risk = min(90, 35 + len(hosts) * 12)
            chains.append({
                "type": "ip_lateral",
                "source_ip": ip,
                "hosts": host_list,
                "host_count": len(hosts),
                "risk_score": risk,
                "description": f"IP {ip} accessed {len(hosts)} hosts in {hours}h",
                "mitre_id": "T1021",
                "mitre_tactic": "Lateral Movement",
            })

    chains.sort(key=lambda c: c["risk_score"], reverse=True)
    return {"chains": chains, "total": len(chains), "hours": hours}


# ══════════════════════════════════════════════════════════════════════════════
#  3. DATA EXFILTRATION SCORING
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/api/v1/ueba/intel/exfiltration")
async def detect_exfiltration(hours: int = 24):
    """Score potential data exfiltration: unusual outbound, mass file access, data staging."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Network connections
        cur = await db.execute("""
            SELECT hostname, source_ip, event_time, payload
            FROM events
            WHERE event_type IN ('network_connection', 'network_connect')
            AND event_time >= ?
        """, (cutoff,))
        net_events = [dict(r) for r in await cur.fetchall()]

        # File access events
        cur = await db.execute("""
            SELECT hostname, event_time, payload, event_type
            FROM events
            WHERE event_type IN ('file_modify', 'file_create', 'file_delete', 'fim_change')
            AND event_time >= ?
        """, (cutoff,))
        file_events = [dict(r) for r in await cur.fetchall()]

        # Mass data commands (archive, compress, copy)
        cur = await db.execute("""
            SELECT hostname, event_time, payload
            FROM events
            WHERE event_type IN ('process_create', 'sudo_exec')
            AND event_time >= ?
            AND (payload LIKE '%tar %' OR payload LIKE '%zip %' OR payload LIKE '%scp %'
                 OR payload LIKE '%rsync%' OR payload LIKE '%curl%upload%'
                 OR payload LIKE '%wget%post%' OR payload LIKE '%base64%')
        """, (cutoff,))
        staging_events = [dict(r) for r in await cur.fetchall()]

    indicators = []

    # Analyze outbound connections
    dest_counts = defaultdict(int)
    for ev in net_events:
        try:
            p = json.loads(ev.get("payload", "{}"))
            dest = p.get("dest_ip", "")
            if dest and dest not in ("127.0.0.1", "::1"):
                dest_counts[dest] += 1
        except:
            pass

    # Flag high-frequency outbound destinations
    for dest, count in dest_counts.items():
        if count >= 20:
            indicators.append({
                "type": "high_freq_outbound",
                "target": dest,
                "count": count,
                "risk_score": min(80, 30 + count),
                "description": f"{count} connections to {dest}",
                "mitre_id": "T1041",
            })

    # Mass file access
    host_file_counts = defaultdict(int)
    for ev in file_events:
        host_file_counts[ev.get("hostname", "")] += 1

    for host, count in host_file_counts.items():
        if count >= 50:
            indicators.append({
                "type": "mass_file_access",
                "hostname": host,
                "count": count,
                "risk_score": min(85, 40 + count // 2),
                "description": f"{count} file operations on {host}",
                "mitre_id": "T1119",
            })

    # Data staging
    for ev in staging_events:
        try:
            p = json.loads(ev.get("payload", "{}"))
            cmd = p.get("cmdline", p.get("command", ""))[:200]
            indicators.append({
                "type": "data_staging",
                "hostname": ev.get("hostname", ""),
                "command": cmd,
                "risk_score": 70,
                "description": f"Data staging: {cmd[:80]}",
                "mitre_id": "T1074",
            })
        except:
            pass

    indicators.sort(key=lambda i: i["risk_score"], reverse=True)

    overall_risk = max([i["risk_score"] for i in indicators]) if indicators else 0

    return {
        "indicators": indicators,
        "total": len(indicators),
        "overall_risk": overall_risk,
        "hours": hours,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  4. AI-POWERED SESSION INVESTIGATION
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/api/v1/ueba/intel/ai-investigate-session")
async def ai_investigate_session(request: Request):
    """AI analyzes a reconstructed session for compromise indicators."""
    body = await request.json()
    username = body.get("username", "")
    hours = body.get("hours", 24)

    if not username:
        raise HTTPException(400, "username required")

    # Get sessions for this user
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("""
            SELECT event_type, hostname, source_ip, event_time, payload, severity, risk_score
            FROM events
            WHERE event_time >= ?
            AND (payload LIKE ? OR payload LIKE ?)
            ORDER BY event_time ASC LIMIT 100
        """, (cutoff, f'%"{username}"%', f'%{username}%'))
        events = [dict(r) for r in await cur.fetchall()]

    sessions = _reconstruct_sessions(events)
    user_sessions = [s for s in sessions if s.get("user", "").lower() == username.lower()]

    if not user_sessions:
        return {"username": username, "analysis": {"verdict": "no_sessions", "summary": "No sessions found"}}

    # Build session summaries for AI
    session_text = ""
    for i, sess in enumerate(user_sessions[:5]):
        session_text += f"\nSession {i+1}: {sess['start_time'][:19]} to {sess['end_time'][:19]} ({sess['duration_minutes']}min)\n"
        session_text += f"  Host: {sess['hostname']}, IP: {sess.get('source_ip','?')}\n"
        session_text += f"  Events: {sess['event_count']}, Risk: {sess['risk_score']}, Severity: {sess['max_severity']}\n"
        if sess['commands']:
            session_text += f"  Commands ({len(sess['commands'])}): {'; '.join(sess['commands'][:5])}\n"
        if sess['files_accessed']:
            session_text += f"  Files ({len(sess['files_accessed'])}): {'; '.join(f['path'] for f in sess['files_accessed'][:5])}\n"
        if sess['network_connections']:
            session_text += f"  Net ({len(sess['network_connections'])}): {'; '.join(c['dest'] for c in sess['network_connections'][:5])}\n"
        if sess['suspicious_count']:
            session_text += f"  SUSPICIOUS EVENTS: {sess['suspicious_count']}\n"

    # Check lateral movement
    lat_data = await detect_lateral_movement(hours)
    user_chains = [c for c in lat_data["chains"] if c.get("user") == username]
    if user_chains:
        session_text += f"\nLATERAL MOVEMENT: accessed {user_chains[0]['host_count']} hosts\n"

    from ai_analyst import call_llm

    system = """You are a senior SOC analyst investigating a user's session activity.
Analyze the reconstructed sessions and determine if this is normal admin activity or signs of compromise.
Focus on: command sequences, file access patterns, network connections, timing, and any lateral movement.

Respond ONLY with JSON:
{
  "verdict": "compromised|suspicious|legitimate|needs_review",
  "confidence": "high|medium|low",
  "risk_score": 0-100,
  "summary": "2-3 sentence analysis",
  "attack_narrative": "If suspicious — what is the attacker doing step by step?",
  "indicators_of_compromise": ["ioc1", "ioc2"],
  "benign_explanations": ["explanation1"],
  "recommended_actions": ["action1", "action2"],
  "session_highlights": ["notable finding 1", "notable finding 2"]
}"""

    prompt = f"""Investigate user sessions for: {username}

{session_text}

Analyze: Is this normal behavior or signs of compromise? What story do these sessions tell?
JSON only:"""

    try:
        result = await call_llm(prompt, system, max_tokens=600, task="analyze")
        import re as re_mod
        parsed = {}
        try:
            parsed = json.loads(result)
        except:
            m = re_mod.search(r'\{.*\}', result, re_mod.DOTALL)
            if m:
                try:
                    parsed = json.loads(m.group())
                except:
                    pass

        if not parsed.get("verdict"):
            parsed = {"verdict": "needs_review", "summary": result[:300], "risk_score": 50}

        return {
            "username": username,
            "analysis": parsed,
            "sessions_analyzed": len(user_sessions),
            "total_events": sum(s["event_count"] for s in user_sessions),
            "lateral_movement": bool(user_chains),
        }
    except Exception as e:
        return {"username": username, "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
#  5. INTEL DASHBOARD SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/api/v1/ueba/intel/summary")
async def intel_summary(hours: int = 24):
    """Overview of all intelligence findings."""
    sessions_data = await get_sessions(hours=hours)
    lateral_data = await detect_lateral_movement(hours=hours)
    exfil_data = await detect_exfiltration(hours=hours)

    risky_sessions = [s for s in sessions_data["sessions"] if s["risk_score"] >= 50]

    return {
        "hours": hours,
        "total_sessions": sessions_data["total"],
        "risky_sessions": len(risky_sessions),
        "lateral_chains": lateral_data["total"],
        "exfiltration_indicators": exfil_data["total"],
        "exfiltration_risk": exfil_data["overall_risk"],
        "top_risky_sessions": [{
            "user": s["user"], "hostname": s["hostname"],
            "risk_score": s["risk_score"], "severity": s["max_severity"],
            "events": s["event_count"], "commands": s["command_count"],
            "duration": s["duration_minutes"],
        } for s in risky_sessions[:5]],
        "lateral_movement": [{
            "type": c["type"],
            "user": c.get("user", c.get("source_ip", "")),
            "hosts": c["host_count"],
            "risk": c["risk_score"],
        } for c in lateral_data["chains"][:5]],
    }
