"""
Cibervault Server Response API v2
Enhanced: fail2ban sync, auto-expire, smart block routing, block history

Replaces api_server_response.py
"""

import asyncio
import json
import logging
import re
import subprocess
import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta

import aiosqlite
from fastapi import APIRouter, HTTPException, Request

log = logging.getLogger("cibervault")

router = APIRouter(tags=["server-response"])

_DB_PATH = ""
_expire_task = None


def init_server_response(db_path: str):
    global _DB_PATH
    _DB_PATH = db_path


async def start_expire_task():
    """Start background task to auto-expire blocks. Call from startup."""
    global _expire_task
    _expire_task = asyncio.create_task(_expire_loop())
    log.info("Block auto-expire task started")


async def _expire_loop():
    """Background loop that cleans up expired blocks every 60s."""
    while True:
        try:
            await cleanup_expired_blocks(_DB_PATH)
        except Exception as e:
            log.error(f"Expire task error: {e}")
        await asyncio.sleep(60)


def _run(cmd: list, timeout: int = 10) -> tuple:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout + r.stderr
    except Exception as e:
        return False, str(e)


def _valid_ip(ip: str) -> bool:
    return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip)) and all(0 <= int(p) <= 255 for p in ip.split('.'))


def _get_server_ips() -> set:
    ips = {"127.0.0.1"}
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5).stdout
        for ip in out.strip().split():
            ips.add(ip.strip())
    except:
        pass
    return ips


async def _ensure_tables():
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS ip_blocks (
                block_id TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                reason TEXT DEFAULT '',
                source TEXT DEFAULT 'manual',
                blocked_by TEXT DEFAULT 'admin',
                blocked_at TEXT,
                expires_at TEXT DEFAULT '',
                status TEXT DEFAULT 'active',
                unblocked_at TEXT DEFAULT '',
                unblocked_by TEXT DEFAULT '',
                block_type TEXT DEFAULT 'server',
                agent_ids TEXT DEFAULT '[]',
                event_count INTEGER DEFAULT 0,
                last_event TEXT DEFAULT ''
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_ip_blocks_ip ON ip_blocks(ip)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_ip_blocks_status ON ip_blocks(status)")
        await db.commit()


# ══════════════════════════════════════════════════════════════════════════════
#  SMART BLOCK — Routes to server iptables, agent, or both
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/api/v1/server/block-ip")
async def block_ip(request: Request):
    """Smart IP block — blocks on server (iptables) and optionally on agents."""
    await _ensure_tables()
    body = await request.json()
    ip = body.get("ip", "").strip()
    reason = body.get("reason", "Manual block")
    duration_hours = body.get("duration_hours", 0)
    blocked_by = body.get("blocked_by", "admin")
    block_agents = body.get("block_agents", False)
    source = body.get("source", "manual")

    if not ip or not _valid_ip(ip):
        raise HTTPException(400, "Valid IP address required")

    if ip in _get_server_ips() or ip in ("127.0.0.1", "0.0.0.0"):
        raise HTTPException(400, f"Cannot block server's own IP: {ip}")

    # Check if already blocked
    ok, _ = _run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
    if ok:
        return {"status": "already_blocked", "ip": ip, "message": "IP is already blocked at firewall"}

    # Block at iptables
    ok, out = _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    if not ok:
        raise HTTPException(500, f"iptables error: {out}")
    _run(["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"])

    # Count how many events from this IP
    event_count = 0
    last_event = ""
    try:
        async with aiosqlite.connect(_DB_PATH) as db:
            cur = await db.execute(
                "SELECT COUNT(*), MAX(event_time) FROM events WHERE source_ip=?", (ip,)
            )
            row = await cur.fetchone()
            if row:
                event_count = row[0] or 0
                last_event = row[1] or ""
    except:
        pass

    # Log to database
    block_id = f"BLK-{str(uuid.uuid4())[:8].upper()}"
    now = datetime.now(timezone.utc).isoformat()
    expires = ""
    if duration_hours > 0:
        expires = (datetime.now(timezone.utc) + timedelta(hours=duration_hours)).isoformat()

    agent_ids_blocked = []

    # Also block on agents if requested
    if block_agents:
        try:
            async with aiosqlite.connect(_DB_PATH) as db:
                db.row_factory = aiosqlite.Row
                cur = await db.execute("SELECT agent_id, hostname FROM agents WHERE status='online'")
                agents = [dict(r) for r in await cur.fetchall()]
                for agent in agents:
                    cmd_id = str(uuid.uuid4())
                    await db.execute("""
                        INSERT OR IGNORE INTO pending_commands
                        (command_id, agent_id, command_type, parameters, status, issued_by, created_at)
                        VALUES (?,?,?,?,?,?,?)
                    """, (cmd_id, agent["agent_id"], "block_ip",
                          json.dumps({"ip": ip}), "pending",
                          f"firewall:{blocked_by}", now))
                    agent_ids_blocked.append(agent["agent_id"])
                await db.commit()
        except Exception as e:
            log.error(f"Agent block send error: {e}")

    try:
        async with aiosqlite.connect(_DB_PATH) as db:
            await db.execute("""
                INSERT OR REPLACE INTO ip_blocks
                (block_id, ip, reason, source, blocked_by, blocked_at, expires_at,
                 status, block_type, agent_ids, event_count, last_event)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (block_id, ip, reason, source, blocked_by, now, expires,
                  "active",
                  "both" if block_agents else "server",
                  json.dumps(agent_ids_blocked),
                  event_count, last_event))
            await db.commit()
    except Exception as e:
        log.error(f"DB error: {e}")

    _run(["netfilter-persistent", "save"])
    log.info(f"BLOCKED {ip} by {blocked_by} — {reason} (agents: {len(agent_ids_blocked)})")

    return {
        "status": "blocked",
        "block_id": block_id,
        "ip": ip,
        "reason": reason,
        "expires": expires or "permanent",
        "block_type": "both" if block_agents else "server",
        "agents_blocked": len(agent_ids_blocked),
        "event_count": event_count,
    }


@router.post("/api/v1/server/unblock-ip")
async def unblock_ip(request: Request):
    """Remove an IP block from server and agents."""
    await _ensure_tables()
    body = await request.json()
    ip = body.get("ip", "").strip()
    unblocked_by = body.get("unblocked_by", "admin")

    if not ip or not _valid_ip(ip):
        raise HTTPException(400, "Valid IP required")

    # Remove from iptables (try multiple times in case of duplicates)
    for _ in range(5):
        ok, _ = _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        if not ok:
            break
    for _ in range(5):
        ok, _ = _run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
        if not ok:
            break

    now = datetime.now(timezone.utc).isoformat()
    try:
        async with aiosqlite.connect(_DB_PATH) as db:
            await db.execute("""
                UPDATE ip_blocks SET status='unblocked', unblocked_at=?, unblocked_by=?
                WHERE ip=? AND status='active'
            """, (now, unblocked_by, ip))
            await db.commit()
    except:
        pass

    _run(["netfilter-persistent", "save"])
    log.info(f"UNBLOCKED {ip} by {unblocked_by}")
    return {"status": "unblocked", "ip": ip}


@router.get("/api/v1/server/blocked-ips")
async def list_blocked_ips():
    """List all blocked IPs with enrichment data."""
    await _ensure_tables()
    blocked = []

    # From iptables (ground truth)
    iptables_ips = set()
    ok, out = _run(["iptables", "-L", "INPUT", "-n", "--line-numbers"])
    if ok:
        for line in out.splitlines():
            m = re.match(r'(\d+)\s+DROP\s+\w+\s+--\s+(\d+\.\d+\.\d+\.\d+)\s+', line)
            if m:
                iptables_ips.add(m.group(2))

    # From DB (enriched data)
    try:
        async with aiosqlite.connect(_DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT * FROM ip_blocks WHERE status='active' ORDER BY blocked_at DESC"
            )
            for r in await cur.fetchall():
                entry = dict(r)
                entry["in_iptables"] = entry["ip"] in iptables_ips
                iptables_ips.discard(entry["ip"])
                blocked.append(entry)

            # IPs in iptables but not in DB (pre-existing rules)
            for ip in iptables_ips:
                blocked.append({
                    "block_id": "", "ip": ip, "reason": "Pre-existing iptables rule",
                    "source": "iptables", "blocked_by": "system",
                    "blocked_at": "", "expires_at": "", "status": "active",
                    "block_type": "server", "in_iptables": True,
                    "event_count": 0, "last_event": "",
                })
    except:
        # Fallback to iptables only
        for ip in iptables_ips:
            blocked.append({"ip": ip, "source": "iptables", "status": "active", "in_iptables": True})

    return {"blocked": blocked, "count": len(blocked)}


@router.post("/api/v1/server/check-ip")
async def check_ip(request: Request):
    """Check if an IP is blocked."""
    body = await request.json()
    ip = body.get("ip", "").strip()
    if not ip:
        raise HTTPException(400, "IP required")
    ok, _ = _run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
    return {"ip": ip, "blocked": ok}


@router.get("/api/v1/server/block-history")
async def block_history(limit: int = 50):
    """Full block/unblock history."""
    await _ensure_tables()
    try:
        async with aiosqlite.connect(_DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT * FROM ip_blocks ORDER BY blocked_at DESC LIMIT ?", (limit,)
            )
            return {"history": [dict(r) for r in await cur.fetchall()]}
    except:
        return {"history": []}


# ══════════════════════════════════════════════════════════════════════════════
#  FAIL2BAN INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/api/v1/server/fail2ban/status")
async def fail2ban_status():
    """Get fail2ban status and jail info."""
    f2b = {"installed": False, "running": False, "jails": []}

    ok, _ = _run(["which", "fail2ban-client"])
    f2b["installed"] = ok

    if not ok:
        return f2b

    ok, out = _run(["fail2ban-client", "status"])
    f2b["running"] = ok

    if ok:
        # Parse jail list
        m = re.search(r'Jail list:\s+(.*)', out)
        if m:
            jail_names = [j.strip() for j in m.group(1).split(",") if j.strip()]
            for jail in jail_names:
                jail_ok, jail_out = _run(["fail2ban-client", "status", jail])
                if jail_ok:
                    banned = []
                    bm = re.search(r'Banned IP list:\s+(.*)', jail_out)
                    if bm:
                        banned = [ip.strip() for ip in bm.group(1).split() if ip.strip()]
                    total_banned = 0
                    tbm = re.search(r'Currently banned:\s+(\d+)', jail_out)
                    if tbm:
                        total_banned = int(tbm.group(1))
                    total_failed = 0
                    tfm = re.search(r'Total failed:\s+(\d+)', jail_out)
                    if tfm:
                        total_failed = int(tfm.group(1))

                    f2b["jails"].append({
                        "name": jail,
                        "banned_ips": banned,
                        "currently_banned": total_banned,
                        "total_failed": total_failed,
                    })

    return f2b


@router.post("/api/v1/server/fail2ban/sync")
async def fail2ban_sync():
    """Sync fail2ban bans into Cibervault block list."""
    await _ensure_tables()
    status = await fail2ban_status()
    if not status["running"]:
        return {"synced": 0, "message": "fail2ban not running"}

    synced = 0
    now = datetime.now(timezone.utc).isoformat()

    for jail in status["jails"]:
        for ip in jail["banned_ips"]:
            # Check if already tracked
            try:
                async with aiosqlite.connect(_DB_PATH) as db:
                    cur = await db.execute(
                        "SELECT block_id FROM ip_blocks WHERE ip=? AND status='active'", (ip,)
                    )
                    if await cur.fetchone():
                        continue

                    block_id = f"F2B-{str(uuid.uuid4())[:8].upper()}"
                    await db.execute("""
                        INSERT INTO ip_blocks
                        (block_id, ip, reason, source, blocked_by, blocked_at, status, block_type)
                        VALUES (?,?,?,?,?,?,?,?)
                    """, (block_id, ip, f"fail2ban jail: {jail['name']}",
                          "fail2ban", "fail2ban", now, "active", "server"))
                    await db.commit()
                    synced += 1
            except:
                pass

    return {"synced": synced, "jails": len(status["jails"]),
            "total_banned": sum(j["currently_banned"] for j in status["jails"])}


@router.post("/api/v1/server/fail2ban/ban")
async def fail2ban_ban(request: Request):
    """Manually ban an IP via fail2ban."""
    body = await request.json()
    ip = body.get("ip", "").strip()
    jail = body.get("jail", "sshd")
    if not ip or not _valid_ip(ip):
        raise HTTPException(400, "Valid IP required")

    ok, out = _run(["fail2ban-client", "set", jail, "banip", ip])
    if ok:
        return {"status": "banned", "ip": ip, "jail": jail}
    else:
        return {"status": "error", "message": out}


@router.post("/api/v1/server/fail2ban/unban")
async def fail2ban_unban(request: Request):
    """Unban an IP from fail2ban."""
    body = await request.json()
    ip = body.get("ip", "").strip()
    jail = body.get("jail", "sshd")
    if not ip:
        raise HTTPException(400, "IP required")

    ok, out = _run(["fail2ban-client", "set", jail, "unbanip", ip])
    return {"status": "unbanned" if ok else "error", "ip": ip, "message": out if not ok else ""}


# ══════════════════════════════════════════════════════════════════════════════
#  FIREWALL STATS
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/api/v1/server/firewall-stats")
async def firewall_stats():
    """Dashboard stats for firewall management."""
    await _ensure_tables()

    # Count active blocks
    active = 0
    try:
        async with aiosqlite.connect(_DB_PATH) as db:
            cur = await db.execute("SELECT COUNT(*) FROM ip_blocks WHERE status='active'")
            active = (await cur.fetchone())[0]

            cur = await db.execute("SELECT COUNT(*) FROM ip_blocks WHERE status='unblocked'")
            unblocked = (await cur.fetchone())[0]

            cur = await db.execute("SELECT COUNT(*) FROM ip_blocks WHERE status='expired'")
            expired = (await cur.fetchone())[0]

            cur = await db.execute(
                "SELECT COUNT(*) FROM ip_blocks WHERE source='fail2ban' AND status='active'"
            )
            f2b_active = (await cur.fetchone())[0]

            # Top blocked IPs by event count
            cur = await db.execute("""
                SELECT ip, reason, event_count, blocked_at, source
                FROM ip_blocks WHERE status='active'
                ORDER BY event_count DESC LIMIT 5
            """)
            top = [dict(r) for r in await cur.fetchall()]
    except:
        unblocked = expired = f2b_active = 0
        top = []

    # iptables rule count
    ok, out = _run(["iptables", "-L", "INPUT", "-n"])
    iptables_rules = len([l for l in out.splitlines() if "DROP" in l]) if ok else 0

    return {
        "active_blocks": active,
        "iptables_rules": iptables_rules,
        "unblocked_total": unblocked,
        "expired_total": expired,
        "fail2ban_active": f2b_active,
        "top_blocked": top,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  IP ENRICHMENT — What do we know about this IP?
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/api/v1/server/ip-info/{ip}")
async def get_ip_info(ip: str):
    """Get everything Cibervault knows about an IP address."""
    if not _valid_ip(ip):
        raise HTTPException(400, "Invalid IP")

    info = {"ip": ip}

    # Check if blocked
    ok, _ = _run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
    info["blocked"] = ok

    # Events from this IP
    try:
        async with aiosqlite.connect(_DB_PATH) as db:
            db.row_factory = aiosqlite.Row

            cur = await db.execute(
                "SELECT COUNT(*) FROM events WHERE source_ip=?", (ip,)
            )
            info["total_events"] = (await cur.fetchone())[0]

            cur = await db.execute("""
                SELECT event_type, COUNT(*) as cnt FROM events
                WHERE source_ip=? GROUP BY event_type ORDER BY cnt DESC LIMIT 10
            """, (ip,))
            info["event_types"] = {r["event_type"]: r["cnt"] for r in await cur.fetchall()}

            cur = await db.execute("""
                SELECT severity, COUNT(*) as cnt FROM events
                WHERE source_ip=? AND is_suspicious=1 GROUP BY severity
            """, (ip,))
            info["severity_breakdown"] = {r["severity"]: r["cnt"] for r in await cur.fetchall()}

            cur = await db.execute("""
                SELECT DISTINCT hostname FROM events WHERE source_ip=?
            """, (ip,))
            info["targeted_hosts"] = [r["hostname"] for r in await cur.fetchall()]

            cur = await db.execute("""
                SELECT MIN(event_time) as first, MAX(event_time) as last
                FROM events WHERE source_ip=?
            """, (ip,))
            row = await cur.fetchone()
            info["first_seen"] = row["first"] if row else ""
            info["last_seen"] = row["last"] if row else ""

            # MITRE techniques
            cur = await db.execute("""
                SELECT DISTINCT mitre_id FROM events
                WHERE source_ip=? AND mitre_id != ''
            """, (ip,))
            info["mitre_techniques"] = [r["mitre_id"] for r in await cur.fetchall()]

            # Users targeted
            cur = await db.execute("""
                SELECT DISTINCT json_extract(payload, '$.user') as user
                FROM events WHERE source_ip=? AND json_extract(payload, '$.user') IS NOT NULL
                LIMIT 20
            """, (ip,))
            info["users_targeted"] = [r["user"] for r in await cur.fetchall() if r["user"]]

            # Block history
            cur = await db.execute(
                "SELECT * FROM ip_blocks WHERE ip=? ORDER BY blocked_at DESC LIMIT 5", (ip,)
            )
            info["block_history"] = [dict(r) for r in await cur.fetchall()]
    except Exception as e:
        info["error"] = str(e)

    return info


# ══════════════════════════════════════════════════════════════════════════════
#  AUTO-EXPIRE
# ══════════════════════════════════════════════════════════════════════════════

async def cleanup_expired_blocks(db_path: str):
    """Remove blocks that have expired."""
    now = datetime.now(timezone.utc).isoformat()
    try:
        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT ip FROM ip_blocks WHERE status='active' AND expires_at != '' AND expires_at < ?",
                (now,)
            )
            expired = [r["ip"] for r in await cur.fetchall()]

            for ip in expired:
                _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
                _run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
                await db.execute(
                    "UPDATE ip_blocks SET status='expired', unblocked_at=?, unblocked_by='auto-expire' WHERE ip=? AND status='active'",
                    (now, ip)
                )
                log.info(f"Auto-expired block: {ip}")
            await db.commit()

            if expired:
                _run(["netfilter-persistent", "save"])
    except Exception as e:
        log.error(f"Block cleanup error: {e}")
