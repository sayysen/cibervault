"""
Cibervault SOAR Engine — Automated Response Rules
Evaluates incoming events against SOAR rules and triggers automated actions.

Features:
- Auto-block IP on brute force detection
- Auto-isolate host on malware/critical severity
- Auto-kill process on known-bad patterns
- Auto-disable user on suspicious auth
- Cooldown periods to prevent action spam
- Full action audit log
- AI-enriched action decisions
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

import aiosqlite

log = logging.getLogger("soar")

# ── Default SOAR Rules (seeded on first run) ──────────────────────────────────

DEFAULT_SOAR_RULES = [
    {
        "rule_id": "SOAR-001",
        "name": "Auto-Block Brute Force IP",
        "description": "Automatically block source IP after 10+ failed login attempts in 5 minutes",
        "enabled": True,
        "trigger_type": "threshold",
        "trigger_conditions": {
            "event_types": ["auth_failure"],
            "group_by": "source_ip",
            "threshold": 10,
            "window_minutes": 5,
        },
        "action_type": "block_ip",
        "action_params": {"duration_hours": 24},
        "severity_filter": ["high", "critical"],
        "cooldown_minutes": 60,
        "require_confirmation": False,
        "mitre_id": "T1110",
    },
    {
        "rule_id": "SOAR-002",
        "name": "Auto-Isolate on Critical Malware",
        "description": "Isolate host when critical malware execution is detected",
        "enabled": False,  # Off by default — dangerous
        "trigger_type": "match",
        "trigger_conditions": {
            "event_types": ["process_create", "malware_detected"],
            "severity": "critical",
            "mitre_tactics": ["Execution", "Defense Evasion"],
        },
        "action_type": "isolate_host",
        "action_params": {},
        "severity_filter": ["critical"],
        "cooldown_minutes": 120,
        "require_confirmation": True,
        "mitre_id": "T1204",
    },
    {
        "rule_id": "SOAR-003",
        "name": "Auto-Scan on Suspicious Process",
        "description": "Trigger Defender scan when suspicious process execution is detected",
        "enabled": True,
        "trigger_type": "match",
        "trigger_conditions": {
            "event_types": ["process_create"],
            "match_field": "cmdline",
            "match_patterns": ["mimikatz", "lazagne", "procdump", "rubeus", "sharphound", "bloodhound"],
        },
        "action_type": "defender_scan",
        "action_params": {"scan_type": "quick"},
        "severity_filter": ["high", "critical"],
        "cooldown_minutes": 30,
        "require_confirmation": False,
        "mitre_id": "T1003",
    },
    {
        "rule_id": "SOAR-004",
        "name": "Auto-Collect Triage on Lateral Movement",
        "description": "Automatically collect forensic triage data when lateral movement is detected",
        "enabled": True,
        "trigger_type": "match",
        "trigger_conditions": {
            "event_types": ["auth_explicit", "process_create", "network_connection"],
            "mitre_tactics": ["Lateral Movement"],
        },
        "action_type": "collect_triage",
        "action_params": {},
        "severity_filter": ["high", "critical"],
        "cooldown_minutes": 60,
        "require_confirmation": False,
        "mitre_id": "T1021",
    },
    {
        "rule_id": "SOAR-005",
        "name": "Block C2 Communication IP",
        "description": "Auto-block IPs flagged as C2 by detection rules",
        "enabled": True,
        "trigger_type": "match",
        "trigger_conditions": {
            "event_types": ["network_connection", "dns_query"],
            "mitre_tactics": ["Command and Control"],
            "severity": "critical",
        },
        "action_type": "block_ip",
        "action_params": {"duration_hours": 72},
        "severity_filter": ["critical"],
        "cooldown_minutes": 30,
        "require_confirmation": False,
        "mitre_id": "T1071",
    },
]


# ── DB Schema ─────────────────────────────────────────────────────────────────

async def init_soar_db(db_path: str):
    """Create SOAR tables if they don't exist."""
    async with aiosqlite.connect(db_path) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS soar_rules (
                rule_id        TEXT PRIMARY KEY,
                name           TEXT NOT NULL,
                description    TEXT DEFAULT '',
                enabled        INTEGER DEFAULT 1,
                trigger_type   TEXT DEFAULT 'match',
                trigger_conditions TEXT DEFAULT '{}',
                action_type    TEXT NOT NULL,
                action_params  TEXT DEFAULT '{}',
                severity_filter TEXT DEFAULT '["high","critical"]',
                cooldown_minutes INTEGER DEFAULT 60,
                require_confirmation INTEGER DEFAULT 0,
                mitre_id       TEXT DEFAULT '',
                created_at     TEXT,
                updated_at     TEXT,
                created_by     TEXT DEFAULT 'system',
                total_executions INTEGER DEFAULT 0,
                last_executed  TEXT
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS soar_actions (
                action_id      TEXT PRIMARY KEY,
                rule_id        TEXT,
                rule_name      TEXT,
                action_type    TEXT NOT NULL,
                action_params  TEXT DEFAULT '{}',
                agent_id       TEXT,
                hostname       TEXT,
                trigger_event_id TEXT,
                trigger_summary TEXT,
                status         TEXT DEFAULT 'pending',
                result         TEXT DEFAULT '',
                requires_confirmation INTEGER DEFAULT 0,
                confirmed_by   TEXT,
                created_at     TEXT,
                executed_at    TEXT
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS soar_cooldowns (
                cooldown_key   TEXT PRIMARY KEY,
                rule_id        TEXT,
                expires_at     TEXT
            )
        """)

        # Seed default rules if table is empty
        cur = await db.execute("SELECT COUNT(*) FROM soar_rules")
        count = (await cur.fetchone())[0]
        if count == 0:
            now = datetime.now(timezone.utc).isoformat()
            for rule in DEFAULT_SOAR_RULES:
                await db.execute("""
                    INSERT INTO soar_rules
                    (rule_id, name, description, enabled, trigger_type, trigger_conditions,
                     action_type, action_params, severity_filter, cooldown_minutes,
                     require_confirmation, mitre_id, created_at, updated_at, created_by)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    rule["rule_id"], rule["name"], rule["description"],
                    1 if rule["enabled"] else 0, rule["trigger_type"],
                    json.dumps(rule["trigger_conditions"]),
                    rule["action_type"], json.dumps(rule["action_params"]),
                    json.dumps(rule["severity_filter"]),
                    rule["cooldown_minutes"],
                    1 if rule["require_confirmation"] else 0,
                    rule.get("mitre_id", ""),
                    now, now, "system",
                ))
            await db.commit()
            log.info(f"Seeded {len(DEFAULT_SOAR_RULES)} default SOAR rules")

    log.info("SOAR engine initialized")


# ── Evaluation Engine ─────────────────────────────────────────────────────────

async def evaluate_event(db_path: str, event: dict, agent_id: str, hostname: str) -> list:
    """
    Evaluate a single event against all enabled SOAR rules.
    Returns list of actions to take.
    """
    actions = []
    now = datetime.now(timezone.utc)

    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row

        # Load enabled rules
        cur = await db.execute("SELECT * FROM soar_rules WHERE enabled=1")
        rules = [dict(r) for r in await cur.fetchall()]

        # Clean expired cooldowns
        await db.execute("DELETE FROM soar_cooldowns WHERE expires_at < ?", (now.isoformat(),))
        await db.commit()

        for rule in rules:
            try:
                conditions = json.loads(rule.get("trigger_conditions", "{}"))
                sev_filter = json.loads(rule.get("severity_filter", '["high","critical"]'))
            except:
                continue

            # Check severity filter
            event_sev = event.get("severity", "info")
            if sev_filter and event_sev not in sev_filter:
                continue

            # Check event type match
            rule_etypes = conditions.get("event_types", [])
            event_etype = event.get("event_type", "")
            if rule_etypes and event_etype not in rule_etypes:
                continue

            matched = False

            if rule["trigger_type"] == "match":
                matched = _check_match(event, conditions)
            elif rule["trigger_type"] == "threshold":
                matched = await _check_threshold(db, event, conditions, agent_id)

            if not matched:
                continue

            # Check cooldown
            cooldown_key = f"{rule['rule_id']}:{agent_id}:{event.get('source_ip', '')}"
            cool_cur = await db.execute(
                "SELECT expires_at FROM soar_cooldowns WHERE cooldown_key=?", (cooldown_key,)
            )
            cool_row = await cool_cur.fetchone()
            if cool_row:
                continue  # Still in cooldown

            # ─── Match! Create action ───
            action_id = f"SA-{str(uuid.uuid4())[:8].upper()}"
            action_params = json.loads(rule.get("action_params", "{}"))

            # Auto-fill parameters from event context
            if rule["action_type"] == "block_ip" and event.get("source_ip"):
                action_params["ip"] = event["source_ip"]
            if rule["action_type"] == "kill_process" and event.get("pid"):
                action_params["pid"] = str(event["pid"])

            trigger_summary = (
                f"[{event_sev.upper()}] {event_etype} on {hostname}"
                + (f" from {event.get('source_ip')}" if event.get("source_ip") else "")
                + (f" [{event.get('mitre_id', '')}]" if event.get("mitre_id") else "")
            )

            status = "pending_confirmation" if rule.get("require_confirmation") else "pending"

            # Insert action
            await db.execute("""
                INSERT INTO soar_actions
                (action_id, rule_id, rule_name, action_type, action_params,
                 agent_id, hostname, trigger_event_id, trigger_summary,
                 status, requires_confirmation, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                action_id, rule["rule_id"], rule["name"],
                rule["action_type"], json.dumps(action_params),
                agent_id, hostname,
                event.get("event_id", ""),
                trigger_summary,
                status,
                1 if rule.get("require_confirmation") else 0,
                now.isoformat(),
            ))

            # Set cooldown
            expires = now + timedelta(minutes=rule.get("cooldown_minutes", 60))
            await db.execute("""
                INSERT OR REPLACE INTO soar_cooldowns (cooldown_key, rule_id, expires_at)
                VALUES (?,?,?)
            """, (cooldown_key, rule["rule_id"], expires.isoformat()))

            # Update rule execution count
            await db.execute("""
                UPDATE soar_rules SET total_executions = total_executions + 1,
                last_executed = ? WHERE rule_id = ?
            """, (now.isoformat(), rule["rule_id"]))

            await db.commit()

            actions.append({
                "action_id": action_id,
                "rule_id": rule["rule_id"],
                "rule_name": rule["name"],
                "action_type": rule["action_type"],
                "action_params": action_params,
                "agent_id": agent_id,
                "hostname": hostname,
                "status": status,
                "trigger": trigger_summary,
            })

            log.info(f"SOAR triggered: {rule['name']} → {rule['action_type']} on {hostname} (action={action_id})")

    return actions


def _check_match(event: dict, conditions: dict) -> bool:
    """Check if event matches rule conditions (pattern, severity, MITRE)."""

    # Check MITRE tactic
    mitre_tactics = conditions.get("mitre_tactics", [])
    if mitre_tactics:
        event_tactic = event.get("mitre_tactic", "")
        if not any(t.lower() in event_tactic.lower() for t in mitre_tactics):
            return False

    # Check severity
    req_sev = conditions.get("severity")
    if req_sev and event.get("severity") != req_sev:
        return False

    # Check field pattern match
    match_field = conditions.get("match_field")
    match_patterns = conditions.get("match_patterns", [])
    if match_field and match_patterns:
        # Check in event directly and in payload
        field_val = event.get(match_field, "")
        if not field_val:
            payload = event.get("payload")
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except:
                    pass
            if isinstance(payload, dict):
                field_val = payload.get(match_field, "")

        field_lower = str(field_val).lower()
        if not any(p.lower() in field_lower for p in match_patterns):
            return False

    return True


async def _check_threshold(db, event: dict, conditions: dict, agent_id: str) -> bool:
    """Check threshold-based triggers (e.g., N events in M minutes)."""
    threshold = conditions.get("threshold", 5)
    window_min = conditions.get("window_minutes", 5)
    group_by = conditions.get("group_by", "source_ip")

    group_val = event.get(group_by, "")
    if not group_val:
        return False

    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_min)).isoformat()
    etypes = conditions.get("event_types", [])

    # Count matching events in window
    if etypes:
        placeholders = ",".join("?" for _ in etypes)
        query = f"""
            SELECT COUNT(*) FROM events
            WHERE agent_id=? AND event_type IN ({placeholders})
            AND source_ip=? AND event_time >= ?
        """
        params = [agent_id] + etypes + [group_val, cutoff]
    else:
        query = """
            SELECT COUNT(*) FROM events
            WHERE agent_id=? AND source_ip=? AND event_time >= ?
        """
        params = [agent_id, group_val, cutoff]

    cur = await db.execute(query, params)
    count = (await cur.fetchone())[0]
    return count >= threshold


# ── Execute Pending Actions ───────────────────────────────────────────────────

async def execute_pending_actions(db_path: str) -> list:
    """
    Execute all pending (non-confirmation-required) SOAR actions.
    Called by the event ingestion pipeline or a background task.
    Returns list of command_ids issued.
    """
    executed = []

    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM soar_actions WHERE status='pending' ORDER BY created_at"
        )
        pending = [dict(r) for r in await cur.fetchall()]

        for action in pending:
            try:
                params = json.loads(action.get("action_params", "{}"))
            except:
                params = {}

            # Issue command to agent
            cmd_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc).isoformat()

            # Smart routing: block_ip on server uses iptables, on agents uses commands
            if action["action_type"] == "block_ip" and params.get("ip"):
                # Server-side block via iptables
                try:
                    import subprocess
                    ip = params["ip"]
                    subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                                   capture_output=True, timeout=5)
                    subprocess.run(["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
                                   capture_output=True, timeout=5)
                    log.info(f"SOAR: Server-side block {ip} via iptables")
                    # Also record in ip_blocks table
                    try:
                        await db.execute("""
                            INSERT OR IGNORE INTO ip_blocks
                            (block_id, ip, reason, source, blocked_by, blocked_at, status, block_type)
                            VALUES (?,?,?,?,?,?,?,?)
                        """, (f"SOAR-{cmd_id[:8]}", ip, f"SOAR rule: {action.get('rule_name','')}",
                              "SOAR", f"SOAR:{action['rule_id']}", now, "active", "server"))
                    except: pass  # Table might not exist yet
                except Exception as e:
                    log.error(f"SOAR iptables block failed: {e}")

            # Also send command to agents
            await db.execute("""
                INSERT OR IGNORE INTO pending_commands
                (command_id, agent_id, command_type, parameters, status, issued_by, created_at)
                VALUES (?,?,?,?,?,?,?)
            """, (
                cmd_id,
                action["agent_id"],
                action["action_type"],
                json.dumps(params),
                "pending",
                f"SOAR:{action['rule_id']}",
                now,
            ))

            # Update action status
            await db.execute("""
                UPDATE soar_actions SET status='executed', executed_at=?, result=?
                WHERE action_id=?
            """, (now, f"command_id={cmd_id}", action["action_id"]))

            executed.append({
                "action_id": action["action_id"],
                "command_id": cmd_id,
                "action_type": action["action_type"],
                "agent_id": action["agent_id"],
                "hostname": action.get("hostname", ""),
            })

        await db.commit()

    if executed:
        log.info(f"SOAR executed {len(executed)} automated actions")
    return executed


# ── Confirm Pending Action (for require_confirmation rules) ───────────────────

async def confirm_action(db_path: str, action_id: str, confirmed_by: str, approve: bool) -> dict:
    """Confirm or reject a SOAR action that requires approval."""
    now = datetime.now(timezone.utc).isoformat()

    async with aiosqlite.connect(db_path) as db:
        if approve:
            await db.execute("""
                UPDATE soar_actions SET status='pending', confirmed_by=?
                WHERE action_id=? AND status='pending_confirmation'
            """, (confirmed_by, action_id))
        else:
            await db.execute("""
                UPDATE soar_actions SET status='rejected', confirmed_by=?, executed_at=?
                WHERE action_id=? AND status='pending_confirmation'
            """, (confirmed_by, now, action_id))
        await db.commit()

    status = "approved" if approve else "rejected"
    log.info(f"SOAR action {action_id} {status} by {confirmed_by}")
    return {"action_id": action_id, "status": status, "by": confirmed_by}


# ── Get SOAR Stats ────────────────────────────────────────────────────────────

async def get_soar_stats(db_path: str) -> dict:
    """Get SOAR dashboard stats."""
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row

        cur = await db.execute("SELECT COUNT(*) FROM soar_rules WHERE enabled=1")
        active_rules = (await cur.fetchone())[0]

        cur = await db.execute("SELECT COUNT(*) FROM soar_actions WHERE status='executed'")
        total_executed = (await cur.fetchone())[0]

        cur = await db.execute("SELECT COUNT(*) FROM soar_actions WHERE status='pending_confirmation'")
        pending_approval = (await cur.fetchone())[0]

        cur = await db.execute("""
            SELECT action_type, COUNT(*) as cnt FROM soar_actions
            WHERE status='executed' AND created_at >= datetime('now', '-24 hours')
            GROUP BY action_type ORDER BY cnt DESC
        """)
        actions_24h = {r["action_type"]: r["cnt"] for r in await cur.fetchall()}

        cur = await db.execute("""
            SELECT rule_name, COUNT(*) as cnt FROM soar_actions
            WHERE status='executed' AND created_at >= datetime('now', '-7 days')
            GROUP BY rule_name ORDER BY cnt DESC LIMIT 5
        """)
        top_rules = [{"name": r["rule_name"], "count": r["cnt"]} for r in await cur.fetchall()]

    return {
        "active_rules": active_rules,
        "total_executed": total_executed,
        "pending_approval": pending_approval,
        "actions_24h": actions_24h,
        "top_rules_7d": top_rules,
    }
