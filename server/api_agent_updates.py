"""
Cibervault EDR - Agent Update & Policy Management API
Handles: binary uploads, policy push, update tracking, per-agent config

Integration: Add to main.py:
    from api_agent_updates import router as updates_router, ensure_updates_schema
    app.include_router(updates_router)
    # In startup(): await ensure_updates_schema()
"""

import json
import logging
import os
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, File, Form
from fastapi.responses import FileResponse

log = logging.getLogger("cibervault.updates")

router = APIRouter(prefix="/api/v1", tags=["agent-updates"])

DB = os.environ.get("DB_PATH", "/opt/cibervault/data/cibervault.db")
UPLOAD_DIR = os.environ.get("AGENT_UPLOAD_DIR", "/opt/cibervault/agent-binaries")

# ── Schema ────────────────────────────────────────────────────────────────
UPDATES_SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_binaries (
    binary_id    TEXT PRIMARY KEY,
    filename     TEXT NOT NULL,
    version      TEXT NOT NULL,
    platform     TEXT DEFAULT 'win-x64',
    file_size    INTEGER,
    sha256       TEXT,
    uploaded_by  TEXT,
    uploaded_at  TEXT NOT NULL,
    notes        TEXT,
    is_active    INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS agent_policies (
    policy_id    TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    description  TEXT,
    policy_data  TEXT NOT NULL,
    version      INTEGER DEFAULT 1,
    created_by   TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    is_default   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS agent_policy_assignments (
    agent_id     TEXT NOT NULL,
    policy_id    TEXT NOT NULL,
    assigned_at  TEXT NOT NULL,
    assigned_by  TEXT,
    status       TEXT DEFAULT 'pending',
    applied_at   TEXT,
    PRIMARY KEY (agent_id, policy_id)
);

CREATE TABLE IF NOT EXISTS agent_update_tasks (
    task_id      TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    task_type    TEXT NOT NULL,
    binary_id    TEXT,
    policy_id    TEXT,
    status       TEXT DEFAULT 'pending',
    created_by   TEXT,
    created_at   TEXT NOT NULL,
    completed_at TEXT,
    result       TEXT
);
"""


async def ensure_updates_schema():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    async with aiosqlite.connect(DB) as db:
        await db.executescript(UPDATES_SCHEMA)
        await db.commit()

        # Create default policy if none exists
        cur = await db.execute("SELECT COUNT(*) FROM agent_policies")
        count = (await cur.fetchone())[0]
        if count == 0:
            default_policy = {
                "process_monitor": {
                    "enabled": True,
                    "buffer_minutes": 10,
                    "max_buffer_size": 5000,
                    "tree_cooldown_sec": 30,
                    "sysmon_enrichment": True,
                    "sysmon_window_minutes": 5,
                },
                "detection": {
                    "suspicious_parents": {
                        "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
                        "excel.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
                        "outlook.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
                        "svchost.exe": ["cmd.exe", "powershell.exe", "mshta.exe", "certutil.exe"],
                        "wmiprvse.exe": ["cmd.exe", "powershell.exe"],
                    },
                    "suspicious_cmd_patterns": [
                        "-encodedcommand", "-enc ", "frombase64string",
                        "invoke-expression", "iex ", "downloadstring", "downloadfile",
                        "invoke-webrequest", "hidden", "-nop ", "bypass",
                        "vssadmin delete", "wmic shadowcopy", "bcdedit /set",
                        "wbadmin delete", "cipher /w", "icacls.*everyone.*full",
                        "attrib +h +s", "net user /add", "net localgroup admin",
                        "schtasks /create", "reg add.*run",
                        "mimikatz", "lazagne", "procdump", "rubeus",
                    ],
                    "suspicious_paths": [
                        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                        "\\downloads\\", "\\public\\", "\\programdata\\",
                        "\\recycle", "\\perflogs\\"
                    ],
                    "lolbins": [
                        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                        "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
                        "bitsadmin.exe", "msiexec.exe", "wmic.exe", "attrib.exe",
                        "schtasks.exe", "sc.exe", "net.exe", "netsh.exe",
                        "icacls.exe", "vssadmin.exe", "bcdedit.exe",
                    ],
                },
                "heartbeat_interval_sec": 10,
                "command_poll_interval_sec": 5,
            }
            now = datetime.now(timezone.utc).isoformat()
            await db.execute("""
                INSERT INTO agent_policies (policy_id, name, description, policy_data, version, created_by, created_at, updated_at, is_default)
                VALUES (?, ?, ?, ?, 1, 'system', ?, ?, 1)
            """, ("default-policy", "Default Policy", "Default agent detection and monitoring policy",
                  json.dumps(default_policy), now, now))
            await db.commit()
    log.info("Agent updates schema ready")


# ══════════════════════════════════════════════════════════════════════════
#  BINARY MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════

@router.post("/admin/agent-binary/upload")
async def upload_agent_binary(
    request: Request,
    file: UploadFile = File(...),
    version: str = Form(...),
    platform: str = Form("win-x64"),
    notes: str = Form(""),
):
    """Upload a new agent binary."""
    from user_auth import get_current_user, require_admin
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): raise HTTPException(401, "Auth required")
    from user_auth import decode_jwt
    user = decode_jwt(auth[7:])
    if user.get("role") != "admin": raise HTTPException(403, "Admin only")

    # Read and hash the file
    content = await file.read()
    if len(content) > 200 * 1024 * 1024:  # 200MB limit
        raise HTTPException(400, "File too large (max 200MB)")

    sha256 = hashlib.sha256(content).hexdigest()
    binary_id = "bin-" + uuid.uuid4().hex[:12]
    filename = file.filename or f"CibervaultAgent-{version}.exe"

    # Save to disk
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    filepath = os.path.join(UPLOAD_DIR, f"{binary_id}_{filename}")
    with open(filepath, "wb") as f:
        f.write(content)

    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB) as db:
        await db.execute("""
            INSERT INTO agent_binaries (binary_id, filename, version, platform, file_size, sha256, uploaded_by, uploaded_at, notes, is_active)
            VALUES (?,?,?,?,?,?,?,?,?,0)
        """, (binary_id, filename, version, platform, len(content), sha256, user["username"], now, notes))
        await db.commit()

    log.info(f"Agent binary uploaded: {filename} v{version} ({len(content)} bytes) by {user['username']}")
    return {"binary_id": binary_id, "filename": filename, "version": version, "size": len(content), "sha256": sha256}


@router.get("/admin/agent-binaries")
async def list_agent_binaries(request: Request):
    """List all uploaded agent binaries."""
    from user_auth import get_current_user
    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM agent_binaries ORDER BY uploaded_at DESC")
        rows = [dict(r) for r in await cur.fetchall()]
    return {"binaries": rows}


@router.post("/admin/agent-binary/{binary_id}/activate")
async def activate_binary(binary_id: str, request: Request):
    """Set a binary as the active/current version."""
    from user_auth import decode_jwt
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): raise HTTPException(401)
    user = decode_jwt(auth[7:])
    if user.get("role") != "admin": raise HTTPException(403)

    async with aiosqlite.connect(DB) as db:
        await db.execute("UPDATE agent_binaries SET is_active=0")
        await db.execute("UPDATE agent_binaries SET is_active=1 WHERE binary_id=?", (binary_id,))
        await db.commit()
    return {"ok": True, "active": binary_id}


@router.delete("/admin/agent-binary/{binary_id}")
async def delete_binary(binary_id: str, request: Request):
    """Delete an uploaded binary."""
    from user_auth import decode_jwt
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): raise HTTPException(401)
    user = decode_jwt(auth[7:])
    if user.get("role") != "admin": raise HTTPException(403)

    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT filename FROM agent_binaries WHERE binary_id=?", (binary_id,))
        row = await cur.fetchone()
        if not row: raise HTTPException(404)
        # Remove file
        filepath = os.path.join(UPLOAD_DIR, f"{binary_id}_{row['filename']}")
        if os.path.exists(filepath): os.remove(filepath)
        await db.execute("DELETE FROM agent_binaries WHERE binary_id=?", (binary_id,))
        await db.commit()
    return {"ok": True}


@router.get("/agent/update/binary")
async def agent_download_binary(request: Request):
    """Agent endpoint: download the active binary for self-update."""
    from auth import verify_token
    agent_id = verify_token(request.headers.get("Authorization", ""))

    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM agent_binaries WHERE is_active=1 LIMIT 1")
        row = await cur.fetchone()

    if not row:
        return {"update_available": False}

    binary = dict(row)
    filepath = os.path.join(UPLOAD_DIR, f"{binary['binary_id']}_{binary['filename']}")
    if not os.path.exists(filepath):
        raise HTTPException(404, "Binary file missing")

    return FileResponse(filepath, filename=binary["filename"],
                        headers={"X-Agent-Version": binary["version"], "X-SHA256": binary["sha256"]})


@router.get("/agent/update/check")
async def agent_check_update(request: Request):
    """Agent endpoint: check if a newer binary is available."""
    from auth import verify_token
    agent_id = verify_token(request.headers.get("Authorization", ""))

    body = dict(request.query_params)
    current_version = body.get("version", "")

    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT version, sha256, file_size, binary_id FROM agent_binaries WHERE is_active=1 LIMIT 1")
        row = await cur.fetchone()

    if not row:
        return {"update_available": False}

    active = dict(row)
    if active["version"] == current_version:
        return {"update_available": False, "current_version": current_version}

    return {
        "update_available": True,
        "new_version": active["version"],
        "sha256": active["sha256"],
        "file_size": active["file_size"],
        "download_url": "/api/v1/agent/update/binary",
    }


# ══════════════════════════════════════════════════════════════════════════
#  POLICY MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════

@router.get("/admin/policies")
async def list_policies(request: Request):
    """List all policies."""
    from user_auth import get_current_user
    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM agent_policies ORDER BY is_default DESC, updated_at DESC")
        rows = [dict(r) for r in await cur.fetchall()]
    for r in rows:
        if r.get("policy_data"):
            try: r["policy_data"] = json.loads(r["policy_data"])
            except: pass
    return {"policies": rows}


@router.post("/admin/policies")
async def create_policy(request: Request):
    """Create a new policy."""
    from user_auth import decode_jwt
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): raise HTTPException(401)
    user = decode_jwt(auth[7:])

    body = await request.json()
    policy_id = "pol-" + uuid.uuid4().hex[:12]
    now = datetime.now(timezone.utc).isoformat()

    async with aiosqlite.connect(DB) as db:
        await db.execute("""
            INSERT INTO agent_policies (policy_id, name, description, policy_data, version, created_by, created_at, updated_at, is_default)
            VALUES (?,?,?,?,1,?,?,?,0)
        """, (policy_id, body.get("name", "New Policy"), body.get("description", ""),
              json.dumps(body.get("policy_data", {})), user["username"], now, now))
        await db.commit()

    return {"policy_id": policy_id}


@router.put("/admin/policies/{policy_id}")
async def update_policy(policy_id: str, request: Request):
    """Update an existing policy."""
    from user_auth import decode_jwt
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): raise HTTPException(401)
    user = decode_jwt(auth[7:])

    body = await request.json()
    now = datetime.now(timezone.utc).isoformat()

    async with aiosqlite.connect(DB) as db:
        await db.execute("""
            UPDATE agent_policies SET
                name=COALESCE(?,name),
                description=COALESCE(?,description),
                policy_data=COALESCE(?,policy_data),
                version=version+1,
                updated_at=?
            WHERE policy_id=?
        """, (body.get("name"), body.get("description"),
              json.dumps(body["policy_data"]) if "policy_data" in body else None,
              now, policy_id))
        await db.commit()
    return {"ok": True, "policy_id": policy_id}


@router.delete("/admin/policies/{policy_id}")
async def delete_policy(policy_id: str, request: Request):
    """Delete a policy (cannot delete default)."""
    from user_auth import decode_jwt
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): raise HTTPException(401)

    async with aiosqlite.connect(DB) as db:
        cur = await db.execute("SELECT is_default FROM agent_policies WHERE policy_id=?", (policy_id,))
        row = await cur.fetchone()
        if not row: raise HTTPException(404)
        if row[0]: raise HTTPException(400, "Cannot delete default policy")
        await db.execute("DELETE FROM agent_policies WHERE policy_id=?", (policy_id,))
        await db.execute("DELETE FROM agent_policy_assignments WHERE policy_id=?", (policy_id,))
        await db.commit()
    return {"ok": True}


# ── Policy Assignment ─────────────────────────────────────────────────────

@router.post("/admin/policies/{policy_id}/assign")
async def assign_policy(policy_id: str, request: Request):
    """Assign a policy to one or more agents and push it."""
    from user_auth import decode_jwt
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): raise HTTPException(401)
    user = decode_jwt(auth[7:])

    body = await request.json()
    agent_ids = body.get("agent_ids", [])
    if not agent_ids: raise HTTPException(400, "agent_ids required")

    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB) as db:
        for aid in agent_ids:
            await db.execute("""
                INSERT OR REPLACE INTO agent_policy_assignments
                (agent_id, policy_id, assigned_at, assigned_by, status)
                VALUES (?,?,?,?,'pending')
            """, (aid, policy_id, now, user["username"]))

            # Create update task (agent will pick this up via command polling)
            task_id = "task-" + uuid.uuid4().hex[:12]
            await db.execute("""
                INSERT INTO agent_update_tasks
                (task_id, agent_id, task_type, policy_id, status, created_by, created_at)
                VALUES (?,?,'policy_update',?,'pending',?,?)
            """, (task_id, aid, policy_id, user["username"], now))

            # Also issue a command so agent picks it up immediately
            cmd_id = str(uuid.uuid4())
            await db.execute("""
                INSERT INTO commands (command_id, agent_id, command_type, parameters, issued_by, status, created_at, expires_at)
                VALUES (?,?,'policy_update',?,?,'pending',?,datetime('now','+1 hour','localtime'))
            """, (cmd_id, aid, json.dumps({"policy_id": policy_id, "task_id": task_id}), user["username"], now))

        await db.commit()

    log.info(f"Policy {policy_id} assigned to {len(agent_ids)} agents by {user['username']}")
    return {"ok": True, "assigned": len(agent_ids)}


# ── Push Binary Update ────────────────────────────────────────────────────

@router.post("/admin/push-update")
async def push_binary_update(request: Request):
    """Push a binary update to selected agents."""
    from user_auth import decode_jwt
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): raise HTTPException(401)
    user = decode_jwt(auth[7:])
    if user.get("role") != "admin": raise HTTPException(403, "Admin only")

    body = await request.json()
    agent_ids = body.get("agent_ids", [])
    binary_id = body.get("binary_id")
    if not agent_ids or not binary_id:
        raise HTTPException(400, "agent_ids and binary_id required")

    # Verify binary exists
    async with aiosqlite.connect(DB) as db:
        cur = await db.execute("SELECT version, sha256 FROM agent_binaries WHERE binary_id=?", (binary_id,))
        row = await cur.fetchone()
        if not row: raise HTTPException(404, "Binary not found")
        version, sha256 = row

        now = datetime.now(timezone.utc).isoformat()
        for aid in agent_ids:
            task_id = "task-" + uuid.uuid4().hex[:12]
            await db.execute("""
                INSERT INTO agent_update_tasks
                (task_id, agent_id, task_type, binary_id, status, created_by, created_at)
                VALUES (?,?,'binary_update',?,'pending',?,?)
            """, (task_id, aid, binary_id, user["username"], now))

            # Issue command to agent
            cmd_id = str(uuid.uuid4())
            await db.execute("""
                INSERT INTO commands (command_id, agent_id, command_type, parameters, issued_by, status, created_at, expires_at)
                VALUES (?,?,'self_update',?,?,'pending',?,datetime('now','+1 hour','localtime'))
            """, (cmd_id, aid, json.dumps({
                "binary_id": binary_id, "version": version,
                "sha256": sha256, "task_id": task_id,
                "download_url": "/api/v1/agent/update/binary",
            }), user["username"], now))

        await db.commit()

    log.info(f"Binary update {binary_id} (v{version}) pushed to {len(agent_ids)} agents by {user['username']}")
    return {"ok": True, "pushed": len(agent_ids), "version": version}


# ── Agent Policy Fetch ────────────────────────────────────────────────────

@router.get("/agent/policy")
async def agent_get_policy(request: Request):
    """Agent endpoint: get the current policy assigned to this agent."""
    from auth import verify_token
    agent_id = verify_token(request.headers.get("Authorization", ""))

    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        # Check for specific assignment first
        cur = await db.execute("""
            SELECT p.* FROM agent_policies p
            JOIN agent_policy_assignments a ON p.policy_id = a.policy_id
            WHERE a.agent_id = ?
            ORDER BY a.assigned_at DESC LIMIT 1
        """, (agent_id,))
        row = await cur.fetchone()

        if not row:
            # Fall back to default policy
            cur = await db.execute("SELECT * FROM agent_policies WHERE is_default=1 LIMIT 1")
            row = await cur.fetchone()

        if not row:
            return {"policy": None}

        policy = dict(row)
        if policy.get("policy_data"):
            try: policy["policy_data"] = json.loads(policy["policy_data"])
            except: pass

        # Mark assignment as applied
        await db.execute("""
            UPDATE agent_policy_assignments SET status='applied', applied_at=?
            WHERE agent_id=? AND status='pending'
        """, (datetime.now(timezone.utc).isoformat(), agent_id))
        await db.commit()

    return {"policy": policy}


# ── Update Status Tracking ────────────────────────────────────────────────

@router.get("/admin/update-tasks")
async def list_update_tasks(
    agent_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    request: Request = None,
):
    """List update tasks with optional filters."""
    from user_auth import get_current_user

    query = "SELECT * FROM agent_update_tasks WHERE 1=1"
    params = []
    if agent_id:
        query += " AND agent_id=?"
        params.append(agent_id)
    if status:
        query += " AND status=?"
        params.append(status)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(query, params)
        rows = [dict(r) for r in await cur.fetchall()]
    return {"tasks": rows}


@router.post("/agent/update/result")
async def agent_update_result(request: Request):
    """Agent reports the result of an update task."""
    from auth import verify_token
    agent_id = verify_token(request.headers.get("Authorization", ""))

    body = await request.json()
    task_id = body.get("task_id", "")
    status = body.get("status", "completed")
    result = body.get("result", "")

    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB) as db:
        await db.execute("""
            UPDATE agent_update_tasks SET status=?, completed_at=?, result=?
            WHERE task_id=? AND agent_id=?
        """, (status, now, result, task_id, agent_id))
        await db.commit()

    return {"ok": True}
