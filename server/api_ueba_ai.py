"""
Cibervault AI-UEBA API Routes v2
Added: Alert timeline, heatmap data, user detail with IPs, MITRE techniques, new user detection
"""

import json
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict

import aiosqlite
from fastapi import APIRouter, HTTPException, Request

log = logging.getLogger("cibervault")

router = APIRouter(tags=["ai-ueba"])

_DB_PATH = ""


def init_ueba_ai(db_path: str):
    global _DB_PATH
    _DB_PATH = db_path


async def _ensure_baselines():
    from ai_ueba import get_baseline
    bl = get_baseline()
    if not bl._profiles:
        await bl.build_from_db(_DB_PATH, days=30)
    return bl


# ══════════════════════════════════════════════════════════════════════════════
#  EXISTING ENDPOINTS (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/api/v1/ueba/ai/rebuild-baselines")
async def rebuild_baselines(request: Request):
    body = await request.json() if request.headers.get("content-type") == "application/json" else {}
    days = body.get("days", 30)
    from ai_ueba import get_baseline
    bl = get_baseline()
    count = await bl.build_from_db(_DB_PATH, days=days)
    return {"status": "ok", "profiles_built": count, "days_analyzed": days}


@router.get("/api/v1/ueba/ai/profiles")
async def get_ai_profiles():
    bl = await _ensure_baselines()
    profiles = bl.get_all_profiles()
    enriched = []
    for p in profiles:
        if p.get("has_baseline") is False:
            continue
        enriched.append({
            "user": p.get("user", ""),
            "total_events": p.get("total_events", 0),
            "login_count": p.get("login_count", 0),
            "fail_ratio": round(p.get("fail_ratio", 0), 3),
            "known_ips": p.get("known_ips", []),
            "ip_count": p.get("ip_count", 0),
            "common_hours": p.get("common_hours", []),
            "common_days": p.get("common_days", []),
            "off_hours_pct": round(p.get("off_hours_pct", 0), 3),
            "daily_avg": round(p.get("daily_avg", 0), 1),
            "daily_std": round(p.get("daily_std", 0), 1),
            "process_diversity": p.get("process_diversity", 0),
            "tactics_seen": p.get("tactics_seen", {}),
            "severity_profile": p.get("severity_profile", {}),
            "common_processes": p.get("common_processes", [])[:10],
        })
    enriched.sort(key=lambda x: x.get("total_events", 0), reverse=True)
    return {"profiles": enriched, "total": len(enriched)}


@router.get("/api/v1/ueba/ai/profile/{username}")
async def get_ai_profile(username: str):
    bl = await _ensure_baselines()
    profile = bl.get_profile(username)
    if not profile or profile.get("has_baseline") is False:
        raise HTTPException(404, f"No baseline for user '{username}'")
    peers = bl.get_peer_group(username)
    peer_dev = bl.detect_peer_deviation(username)
    return {"profile": profile, "peers": peers, "peer_deviation": peer_dev}


@router.post("/api/v1/ueba/ai/score-alert")
async def score_alert_ai(request: Request):
    body = await request.json()
    alert = body.get("alert", {})
    if not alert:
        raise HTTPException(400, "alert data required")
    bl = await _ensure_baselines()
    from ai_ueba import ai_score_alert
    from ai_analyst import call_llm
    result = await ai_score_alert(alert, bl, call_llm)
    return result


@router.post("/api/v1/ueba/ai/score-batch")
async def score_batch_ai(request: Request):
    body = await request.json()
    limit = body.get("limit", 5)
    bl = await _ensure_baselines()
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("""
            SELECT event_id, event_type, hostname, severity, risk_score,
                   mitre_id, mitre_tactic, rule_name, rule_id, payload, event_time
            FROM events WHERE rule_id LIKE 'UEBA%'
            ORDER BY event_time DESC LIMIT ?
        """, (limit,))
        alerts = [dict(r) for r in await cur.fetchall()]
    if not alerts:
        return {"scored": [], "message": "No UEBA alerts found"}
    from ai_ueba import ai_score_alert
    from ai_analyst import call_llm
    scored = []
    for alert in alerts[:3]:
        try:
            payload = json.loads(alert.get("payload", "{}"))
            alert_data = {
                "ueba_type": (alert.get("rule_id") or "").replace("UEBA-", "").lower(),
                "description": alert.get("rule_name", ""),
                "user": payload.get("user", alert.get("hostname", "")),
                "hostname": alert.get("hostname", ""),
                "severity": alert.get("severity", "medium"),
                "risk_score": alert.get("risk_score", 50),
                "mitre_id": alert.get("mitre_id", ""),
                "mitre_tactic": alert.get("mitre_tactic", ""),
            }
            result = await ai_score_alert(alert_data, bl, call_llm)
            result["event_id"] = alert["event_id"]
            result["event_time"] = alert["event_time"]
            scored.append(result)
        except Exception as e:
            log.error(f"Batch scoring error: {e}")
    return {"scored": scored}


@router.post("/api/v1/ueba/ai/investigate")
async def investigate_user_ai(request: Request):
    body = await request.json()
    username = body.get("username", "").strip().lower()
    if not username:
        raise HTTPException(400, "username required")
    bl = await _ensure_baselines()
    from ai_ueba import investigate_user
    from ai_analyst import call_llm
    result = await investigate_user(_DB_PATH, username, bl, call_llm)
    return result


@router.get("/api/v1/ueba/ai/peers/{username}")
async def get_peer_group(username: str):
    bl = await _ensure_baselines()
    peers = bl.get_peer_group(username)
    deviation = bl.detect_peer_deviation(username)
    return {"username": username, "peers": peers, "deviation": deviation}


@router.post("/api/v1/ueba/ai/score-activity")
async def score_activity(request: Request):
    body = await request.json()
    username = body.get("username", "").strip().lower()
    activity = body.get("activity", {})
    if not username:
        raise HTTPException(400, "username required")
    bl = await _ensure_baselines()
    result = bl.score_activity(username, activity)
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  NEW ENDPOINTS v2
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/api/v1/ueba/ai/summary")
async def ueba_ai_summary():
    """Enhanced summary with new user detection."""
    bl = await _ensure_baselines()
    profiles = bl.get_all_profiles()

    user_profiles = [p for p in profiles if not p.get("user", "").startswith("host:")]
    host_profiles = [p for p in profiles if p.get("user", "").startswith("host:")]

    # High risk users with IPs and MITRE
    high_risk = []
    for p in user_profiles:
        off_hours = p.get("off_hours_pct", 0)
        fail_ratio = p.get("fail_ratio", 0)
        ip_count = p.get("ip_count", 0)
        tactics = list(p.get("tactics_seen", {}).keys())
        criticals = p.get("severity_profile", {}).get("critical", 0)

        risk_score = (off_hours * 30) + (fail_ratio * 40) + (min(ip_count, 10) * 2) + (min(len(tactics), 5) * 4) + (min(criticals, 5) * 3)

        if risk_score > 15:
            high_risk.append({
                "user": p["user"],
                "risk_score": round(risk_score, 1),
                "reason": ("high fail ratio" if fail_ratio > 0.3 else
                          "off-hours activity" if off_hours > 0.2 else
                          "many IPs" if ip_count > 5 else
                          "MITRE tactics" if len(tactics) >= 3 else "elevated risk"),
                "ips": p.get("known_ips", [])[:5],
                "ip_count": ip_count,
                "mitre_tactics": tactics[:5],
                "login_count": p.get("login_count", 0),
                "fail_ratio": round(fail_ratio, 2),
            })

    high_risk.sort(key=lambda x: x["risk_score"], reverse=True)

    # Detect new users (appeared in last 24h with few events)
    new_users = []
    for p in user_profiles:
        if p.get("total_events", 0) <= 5 and p.get("login_count", 0) <= 3:
            new_users.append({
                "user": p["user"],
                "events": p.get("total_events", 0),
                "ips": p.get("known_ips", []),
            })

    # Get last login times from DB
    last_logins = {}
    try:
        async with aiosqlite.connect(_DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("""
                SELECT payload, event_time, source_ip FROM events
                WHERE event_type='auth_success'
                ORDER BY event_time DESC LIMIT 50
            """)
            for row in await cur.fetchall():
                try:
                    p = json.loads(row["payload"] or "{}")
                    user = (p.get("user") or p.get("auth", {}).get("user", "") or "").lower().strip()
                    if user and user not in last_logins:
                        last_logins[user] = {
                            "time": row["event_time"],
                            "ip": row.get("source_ip", ""),
                        }
                except:
                    pass
    except:
        pass

    # Attach last login to high risk users
    for hr in high_risk:
        ll = last_logins.get(hr["user"], {})
        hr["last_login"] = ll.get("time", "")
        hr["last_ip"] = ll.get("ip", "")

    return {
        "total_profiles": len(profiles),
        "user_profiles": len(user_profiles),
        "host_profiles": len(host_profiles),
        "high_risk_users": high_risk[:10],
        "new_users": new_users[:10],
        "baseline_built": len(profiles) > 0,
        "total_events_analyzed": sum(p.get("total_events", 0) for p in profiles),
    }


@router.get("/api/v1/ueba/ai/user/{username}/timeline")
async def user_alert_timeline(username: str, limit: int = 30):
    """Get chronological alert timeline for a specific user."""
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        # Search in events where user appears in payload
        cur = await db.execute("""
            SELECT event_id, event_type, hostname, severity, risk_score,
                   mitre_id, mitre_tactic, rule_name, source_ip, event_time, payload
            FROM events
            WHERE is_suspicious=1
            AND (payload LIKE ? OR payload LIKE ?)
            ORDER BY event_time DESC LIMIT ?
        """, (f'%"{username}"%', f'%{username}%', limit))
        events = [dict(r) for r in await cur.fetchall()]

    timeline = []
    for ev in events:
        timeline.append({
            "event_id": ev["event_id"],
            "event_type": ev["event_type"],
            "hostname": ev.get("hostname", ""),
            "severity": ev.get("severity", "info"),
            "risk_score": ev.get("risk_score", 0),
            "mitre_id": ev.get("mitre_id", ""),
            "mitre_tactic": ev.get("mitre_tactic", ""),
            "rule_name": ev.get("rule_name", ""),
            "source_ip": ev.get("source_ip", ""),
            "event_time": ev.get("event_time", ""),
        })

    return {"username": username, "timeline": timeline, "total": len(timeline)}


@router.get("/api/v1/ueba/ai/user/{username}/heatmap")
async def user_login_heatmap(username: str):
    """Get login activity heatmap data (hour x day-of-week)."""
    bl = await _ensure_baselines()
    profile = bl.get_profile(username)

    # Build heatmap from DB
    heatmap = [[0]*24 for _ in range(7)]  # 7 days x 24 hours

    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("""
            SELECT event_time FROM events
            WHERE event_type IN ('auth_success','auth_failure','auth_explicit','sudo_exec')
            AND (payload LIKE ? OR payload LIKE ?)
            AND event_time >= datetime('now', '-30 days')
        """, (f'%"{username}"%', f'%{username}%'))

        for row in await cur.fetchall():
            try:
                dt = datetime.fromisoformat(row["event_time"].replace("Z", "+00:00"))
                heatmap[dt.weekday()][dt.hour] += 1
            except:
                pass

    # Also aggregate all events by hour for this user
    total_by_hour = [0]*24
    for day in heatmap:
        for h in range(24):
            total_by_hour[h] += day[h]

    return {
        "username": username,
        "heatmap": heatmap,  # [day][hour] = count
        "total_by_hour": total_by_hour,
        "days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
    }


@router.get("/api/v1/ueba/ai/user/{username}/detail")
async def user_full_detail(username: str):
    """Full user detail: profile + IPs + MITRE + recent activity + heatmap."""
    bl = await _ensure_baselines()
    profile = bl.get_profile(username)
    peers = bl.get_peer_group(username)
    peer_dev = bl.detect_peer_deviation(username)

    # Get recent events
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Recent auth with IPs
        cur = await db.execute("""
            SELECT event_type, source_ip, event_time, hostname FROM events
            WHERE event_type IN ('auth_success','auth_failure')
            AND (payload LIKE ? OR payload LIKE ?)
            ORDER BY event_time DESC LIMIT 20
        """, (f'%"{username}"%', f'%{username}%'))
        auth_events = [dict(r) for r in await cur.fetchall()]

        # MITRE techniques triggered
        cur = await db.execute("""
            SELECT DISTINCT mitre_id, mitre_tactic FROM events
            WHERE is_suspicious=1 AND mitre_id != ''
            AND (payload LIKE ? OR payload LIKE ?)
        """, (f'%"{username}"%', f'%{username}%'))
        mitre = [{"id": r["mitre_id"], "tactic": r["mitre_tactic"]} for r in await cur.fetchall()]

        # IP history with timestamps
        ip_history = defaultdict(lambda: {"count": 0, "first": "", "last": ""})
        for ev in auth_events:
            ip = ev.get("source_ip", "")
            if ip and ip not in ("", "127.0.0.1", "::1"):
                entry = ip_history[ip]
                entry["count"] += 1
                t = ev.get("event_time", "")
                if not entry["first"] or t < entry["first"]:
                    entry["first"] = t
                if not entry["last"] or t > entry["last"]:
                    entry["last"] = t

    return {
        "username": username,
        "profile": profile,
        "peers": peers[:5],
        "peer_deviation": peer_dev,
        "mitre_techniques": mitre,
        "ip_history": {ip: dict(v) for ip, v in ip_history.items()},
        "recent_auth": auth_events[:10],
        "auth_count": len(auth_events),
    }
