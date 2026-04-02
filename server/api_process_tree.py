"""
Cibervault EDR — Process Tree API
Receives process trees from agents, stores them, serves to dashboard.

Integration: Add to main.py:
    from api_process_tree import router as ptree_router
    app.include_router(ptree_router)
"""

import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Query, Request

log = logging.getLogger("cibervault.ptree")

router = APIRouter(prefix="/api/v1", tags=["process-tree"])

DB = os.environ.get("DB_PATH", "/opt/cibervault/data/cibervault.db")


# ── DB Schema Migration ──────────────────────────────────────────────────────
PTREE_SCHEMA = """
CREATE TABLE IF NOT EXISTS process_trees (
    tree_id       TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL,
    hostname      TEXT,
    trigger_pid   TEXT,
    trigger_reason TEXT,
    root_process  TEXT,
    root_pid      INTEGER,
    capture_time  TEXT NOT NULL,
    process_count INTEGER DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS process_nodes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tree_id       TEXT NOT NULL,
    pid           INTEGER NOT NULL,
    ppid          INTEGER,
    name          TEXT,
    cmdline       TEXT,
    image_path    TEXT,
    user          TEXT,
    parent_name   TEXT,
    start_time    TEXT,
    end_time      TEXT,
    sha256        TEXT,
    md5           TEXT,
    file_size     INTEGER,
    is_suspicious INTEGER DEFAULT 0,
    suspicious_reason TEXT,
    session_id    INTEGER,
    FOREIGN KEY (tree_id) REFERENCES process_trees(tree_id)
);

CREATE TABLE IF NOT EXISTS process_edges (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    tree_id  TEXT NOT NULL,
    from_pid INTEGER NOT NULL,
    to_pid   INTEGER NOT NULL,
    FOREIGN KEY (tree_id) REFERENCES process_trees(tree_id)
);

CREATE INDEX IF NOT EXISTS idx_pnodes_tree ON process_nodes(tree_id);
CREATE INDEX IF NOT EXISTS idx_pedges_tree ON process_edges(tree_id);
CREATE INDEX IF NOT EXISTS idx_ptrees_agent ON process_trees(agent_id);
CREATE INDEX IF NOT EXISTS idx_ptrees_time ON process_trees(capture_time);
"""


async def ensure_ptree_schema():
    """Run on startup to create tables if missing."""
    async with aiosqlite.connect(DB) as db:
        await db.executescript(PTREE_SCHEMA)
        await db.commit()
    log.info("Process tree schema ready")


# ── Receive Process Tree from Agent ──────────────────────────────────────────
@router.post("/agent/process-tree")
async def receive_process_tree(request: Request):
    """
    Receive a process tree from the agent.
    Auth: Uses the agent's bearer token (same as heartbeat/events).
    """
    from auth import verify_token
    auth_header = request.headers.get("Authorization", "")
    agent_id = verify_token(auth_header)

    body = await request.json()
    tree_id = body.get("tree_id", f"tree-{uuid.uuid4().hex[:16]}")
    now = datetime.utcnow().isoformat()

    # Look up hostname from agents table
    hostname = ""
    async with aiosqlite.connect(DB) as db:
        cur = await db.execute("SELECT hostname FROM agents WHERE agent_id=?", (agent_id,))
        row = await cur.fetchone()
        if row:
            hostname = row[0]

    processes = body.get("processes", [])
    edges = body.get("edges", [])

    async with aiosqlite.connect(DB) as db:
        # Ensure tables exist
        await db.executescript(PTREE_SCHEMA)

        # Insert tree record
        await db.execute("""
            INSERT OR REPLACE INTO process_trees
            (tree_id, agent_id, hostname, trigger_pid, trigger_reason,
             root_process, root_pid, capture_time, process_count, sysmon_data, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            tree_id, agent_id, hostname,
            str(body.get("trigger_pid", "")),
            body.get("trigger_reason", ""),
            body.get("root_process", ""),
            body.get("root_pid", 0),
            body.get("capture_time", now),
            len(processes),
            json.dumps(body.get('sysmon')) if body.get('sysmon') else None,
            now,
        ))

        # Insert process nodes
        for p in processes:
            await db.execute("""
                INSERT INTO process_nodes
                (tree_id, pid, ppid, name, cmdline, image_path, user, parent_name,
                 start_time, end_time, sha256, md5, file_size,
                 is_suspicious, suspicious_reason, session_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                tree_id,
                p.get("pid", 0),
                p.get("ppid", 0),
                p.get("name", ""),
                (p.get("cmdline", "") or "")[:2000],  # Truncate long cmdlines
                p.get("image_path", ""),
                p.get("user", ""),
                p.get("parent_name", ""),
                p.get("start_time", ""),
                p.get("end_time"),
                p.get("sha256", ""),
                p.get("md5", ""),
                p.get("file_size", 0),
                1 if p.get("is_suspicious") else 0,
                p.get("suspicious_reason", ""),
                p.get("session_id", 0),
            ))

        # Insert edges
        for e in edges:
            await db.execute("""
                INSERT INTO process_edges (tree_id, from_pid, to_pid)
                VALUES (?,?,?)
            """, (tree_id, e.get("from_pid", 0), e.get("to_pid", 0)))

        await db.commit()

    # Also create a suspicious event for the alert feed
    async with aiosqlite.connect(DB) as db:
        event_id = f"ptree-{uuid.uuid4().hex[:12]}"
        severity = "high" if "ransomware" in (body.get("trigger_reason", "")).lower() else "medium"
        await db.execute("""
            INSERT OR IGNORE INTO events
            (event_id, agent_id, event_type, event_time, hostname,
             severity, risk_score, is_suspicious, payload,
             mitre_id, mitre_tactic, rule_id, rule_name, created_at)
            VALUES (?,?,?,?,?,?,?,1,?,?,?,?,?,?)
        """, (
            event_id, agent_id, "process_tree", now, hostname,
            severity, 70,
            json.dumps({
                "tree_id": tree_id,
                "trigger_reason": body.get("trigger_reason", ""),
                "root_process": body.get("root_process", ""),
                "root_pid": body.get("root_pid", 0),
                "process_count": len(processes),
                "trigger_pid": body.get("trigger_pid", ""),
            }),
            "",  # mitre_id — could be enriched later
            "Execution",
            "CV-PTREE",
            f"Process Tree: {body.get('root_process', 'unknown')} ({body.get('trigger_reason', '')})"[:120],
            now,
        ))
        await db.commit()

    log.info(f"Process tree {tree_id}: {len(processes)} processes from {hostname} "
             f"(trigger: {body.get('trigger_reason', '')[:60]})")

    return {
        "ok": True,
        "tree_id": tree_id,
        "processes_stored": len(processes),
        "edges_stored": len(edges),
    }


# ── Get Process Tree by ID ───────────────────────────────────────────────────
@router.get("/process-tree/{tree_id}")
async def get_process_tree(tree_id: str):
    """Retrieve a full process tree for dashboard visualization."""
    from user_auth import get_current_user

    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row

        # Get tree metadata
        cur = await db.execute("SELECT * FROM process_trees WHERE tree_id=?", (tree_id,))
        tree = await cur.fetchone()
        if not tree:
            raise HTTPException(404, "Process tree not found")
        tree = dict(tree)

        # Get nodes
        cur = await db.execute(
            "SELECT * FROM process_nodes WHERE tree_id=? ORDER BY start_time ASC",
            (tree_id,))
        nodes = [dict(r) for r in await cur.fetchall()]

        # Get edges
        cur = await db.execute(
            "SELECT from_pid, to_pid FROM process_edges WHERE tree_id=?",
            (tree_id,))
        edges = [{"from": r[0], "to": r[1]} for r in await cur.fetchall()]

    return {
        **tree,
        "nodes": nodes,
        "edges": edges,
    }


# ── List Process Trees ───────────────────────────────────────────────────────
@router.get("/process-trees")
async def list_process_trees(
    agent_id: str = Query(None),
    hostname: str = Query(None),
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(50, ge=1, le=200),
):
    """List recent process trees with metadata."""
    from user_auth import get_current_user

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    query = "SELECT * FROM process_trees WHERE capture_time >= ?"
    params = [cutoff]

    if agent_id:
        query += " AND agent_id = ?"
        params.append(agent_id)
    if hostname:
        query += " AND hostname = ?"
        params.append(hostname)

    query += " ORDER BY capture_time DESC LIMIT ?"
    params.append(limit)

    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(query, params)
        trees = [dict(r) for r in await cur.fetchall()]

    return {"trees": trees, "total": len(trees)}


# ── Get Trees for a Specific Event ───────────────────────────────────────────
@router.get("/process-tree/by-event/{event_id}")
async def get_tree_for_event(event_id: str):
    """Find the process tree associated with an event (if any)."""
    from user_auth import get_current_user

    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row

        # Check if event has a tree_id in payload
        cur = await db.execute("SELECT payload FROM events WHERE event_id=?", (event_id,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Event not found")

        payload = {}
        try:
            payload = json.loads(row["payload"] or "{}")
        except Exception:
            pass

        tree_id = payload.get("tree_id")
        if tree_id:
            # Direct tree reference
            return await get_process_tree(tree_id)

        # Try to find tree by matching agent + time window
        cur2 = await db.execute("SELECT agent_id, event_time FROM events WHERE event_id=?", (event_id,))
        ev = await cur2.fetchone()
        if not ev:
            return {"nodes": [], "edges": [], "message": "No tree data for this event"}

        agent_id = ev["agent_id"]
        event_time = ev["event_time"]

        # Look for trees from this agent within ±5 minutes
        try:
            et = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
            t_start = (et - timedelta(minutes=5)).isoformat()
            t_end = (et + timedelta(minutes=5)).isoformat()
        except Exception:
            return {"nodes": [], "edges": [], "message": "Could not parse event time"}

        cur3 = await db.execute("""
            SELECT tree_id FROM process_trees
            WHERE agent_id = ? AND capture_time BETWEEN ? AND ?
            ORDER BY capture_time DESC LIMIT 1
        """, (agent_id, t_start, t_end))
        tree_row = await cur3.fetchone()

        if tree_row:
            return await get_process_tree(tree_row["tree_id"])

    return {"nodes": [], "edges": [], "message": "No process tree found for this event"}
