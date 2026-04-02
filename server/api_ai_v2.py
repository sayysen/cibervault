"""
Cibervault AI v2 API Routes
New endpoints for: SOAR, Alert Correlation, AI Rule Generation, Enhanced Context

Add to main.py:
    from api_ai_v2 import router as ai_v2_router
    app.include_router(ai_v2_router)
"""

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Request

log = logging.getLogger("cibervault")

router = APIRouter(tags=["ai-v2"])

# These will be set during init
_DB_PATH = ""
_get_current_user = None
_require_admin = None


def init_ai_v2(db_path: str, get_current_user_dep, require_admin_dep):
    """Call this from main.py to wire dependencies."""
    global _DB_PATH, _get_current_user, _require_admin
    _DB_PATH = db_path
    _get_current_user = get_current_user_dep
    _require_admin = require_admin_dep


def _db():
    return _DB_PATH


# ═══════════════════════════════════════════════════════════════════════════════
#  SOAR ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/api/v1/soar/rules")
async def get_soar_rules(request: Request):
    """Get all SOAR automation rules."""
    async with aiosqlite.connect(_db()) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM soar_rules ORDER BY rule_id")
        rules = []
        for r in await cur.fetchall():
            rule = dict(r)
            for field in ("trigger_conditions", "action_params", "severity_filter"):
                if rule.get(field):
                    try:
                        rule[field] = json.loads(rule[field])
                    except:
                        pass
            rules.append(rule)
    return {"rules": rules}


@router.post("/api/v1/soar/rules")
async def create_soar_rule(request: Request):
    """Create a new SOAR automation rule."""
    body = await request.json()
    rule_id = f"SOAR-{str(uuid.uuid4())[:6].upper()}"
    now = datetime.now(timezone.utc).isoformat()

    async with aiosqlite.connect(_db()) as db:
        await db.execute("""
            INSERT INTO soar_rules
            (rule_id, name, description, enabled, trigger_type, trigger_conditions,
             action_type, action_params, severity_filter, cooldown_minutes,
             require_confirmation, mitre_id, created_at, updated_at, created_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            rule_id,
            body.get("name", "New SOAR Rule"),
            body.get("description", ""),
            1 if body.get("enabled", True) else 0,
            body.get("trigger_type", "match"),
            json.dumps(body.get("trigger_conditions", {})),
            body.get("action_type", "block_ip"),
            json.dumps(body.get("action_params", {})),
            json.dumps(body.get("severity_filter", ["high", "critical"])),
            body.get("cooldown_minutes", 60),
            1 if body.get("require_confirmation", False) else 0,
            body.get("mitre_id", ""),
            now, now,
            "admin",
        ))
        await db.commit()

    return {"rule_id": rule_id, "status": "created"}


@router.patch("/api/v1/soar/rules/{rule_id}")
async def update_soar_rule(rule_id: str, request: Request):
    """Update a SOAR rule."""
    body = await request.json()
    now = datetime.now(timezone.utc).isoformat()

    updates = []
    params = []

    field_map = {
        "name": "name", "description": "description",
        "enabled": "enabled", "trigger_type": "trigger_type",
        "action_type": "action_type", "cooldown_minutes": "cooldown_minutes",
        "require_confirmation": "require_confirmation", "mitre_id": "mitre_id",
    }
    json_fields = {"trigger_conditions", "action_params", "severity_filter"}

    for key, col in field_map.items():
        if key in body:
            val = body[key]
            if key in ("enabled", "require_confirmation"):
                val = 1 if val else 0
            updates.append(f"{col}=?")
            params.append(val)

    for key in json_fields:
        if key in body:
            updates.append(f"{key}=?")
            params.append(json.dumps(body[key]))

    if not updates:
        raise HTTPException(400, "No fields to update")

    updates.append("updated_at=?")
    params.append(now)
    params.append(rule_id)

    async with aiosqlite.connect(_db()) as db:
        await db.execute(f"UPDATE soar_rules SET {','.join(updates)} WHERE rule_id=?", params)
        await db.commit()

    return {"rule_id": rule_id, "status": "updated"}


@router.delete("/api/v1/soar/rules/{rule_id}")
async def delete_soar_rule(rule_id: str):
    """Delete a SOAR rule."""
    async with aiosqlite.connect(_db()) as db:
        await db.execute("DELETE FROM soar_rules WHERE rule_id=?", (rule_id,))
        await db.commit()
    return {"rule_id": rule_id, "status": "deleted"}


@router.get("/api/v1/soar/actions")
async def get_soar_actions(limit: int = 50, status: str = ""):
    """Get SOAR action log."""
    async with aiosqlite.connect(_db()) as db:
        db.row_factory = aiosqlite.Row
        if status:
            cur = await db.execute(
                "SELECT * FROM soar_actions WHERE status=? ORDER BY created_at DESC LIMIT ?",
                (status, limit)
            )
        else:
            cur = await db.execute(
                "SELECT * FROM soar_actions ORDER BY created_at DESC LIMIT ?", (limit,)
            )
        actions = []
        for r in await cur.fetchall():
            a = dict(r)
            if a.get("action_params"):
                try:
                    a["action_params"] = json.loads(a["action_params"])
                except:
                    pass
            actions.append(a)
    return {"actions": actions}


@router.post("/api/v1/soar/actions/{action_id}/confirm")
async def confirm_soar_action(action_id: str, request: Request):
    """Approve or reject a pending SOAR action."""
    body = await request.json()
    approve = body.get("approve", True)

    from soar_engine import confirm_action, execute_pending_actions
    result = await confirm_action(_db(), action_id, "admin", approve)

    # If approved, execute it
    if approve:
        await execute_pending_actions(_db())

    return result


@router.get("/api/v1/soar/stats")
async def soar_stats():
    """Get SOAR dashboard statistics."""
    from soar_engine import get_soar_stats
    return await get_soar_stats(_db())


# ═══════════════════════════════════════════════════════════════════════════════
#  ALERT CORRELATION ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/api/v1/ai/correlate")
async def run_correlation(request: Request):
    """Run AI alert correlation to group related events into incidents."""
    body = await request.json()
    window_hours = body.get("window_hours", 4)
    min_cluster = body.get("min_cluster", 2)

    from ai_correlator import correlate_alerts
    new_incidents = await correlate_alerts(_db(), window_hours, min_cluster)

    # AI-enrich new incidents
    from ai_analyst import call_llm
    from ai_correlator import ai_enrich_incident
    enriched = []
    for inc in new_incidents[:5]:  # Limit AI calls
        try:
            result = await ai_enrich_incident(_db(), inc["incident_id"], call_llm)
            enriched.append(result)
        except Exception as e:
            log.error(f"Enrichment failed: {e}")

    return {
        "new_incidents": len(new_incidents),
        "incidents": new_incidents,
        "enrichments": enriched,
    }


@router.get("/api/v1/ai/incidents")
async def get_correlated_incidents(status: str = "", limit: int = 20):
    """Get correlated incidents."""
    async with aiosqlite.connect(_db()) as db:
        db.row_factory = aiosqlite.Row
        if status:
            cur = await db.execute(
                "SELECT * FROM correlated_incidents WHERE status=? ORDER BY created_at DESC LIMIT ?",
                (status, limit)
            )
        else:
            cur = await db.execute(
                "SELECT * FROM correlated_incidents ORDER BY created_at DESC LIMIT ?", (limit,)
            )
        incidents = []
        for r in await cur.fetchall():
            inc = dict(r)
            for f in ("kill_chain_stages", "affected_hosts", "source_ips", "mitre_techniques", "event_ids"):
                if inc.get(f):
                    try:
                        inc[f] = json.loads(inc[f])
                    except:
                        pass
            if inc.get("ai_analysis"):
                try:
                    inc["ai_analysis"] = json.loads(inc["ai_analysis"])
                except:
                    pass
            incidents.append(inc)
    return {"incidents": incidents}


@router.patch("/api/v1/ai/incidents/{incident_id}")
async def update_incident(incident_id: str, request: Request):
    """Update incident status/assignment."""
    body = await request.json()
    now = datetime.now(timezone.utc).isoformat()

    updates = []
    params = []
    for field in ("status", "assigned_to", "priority", "severity"):
        if field in body:
            updates.append(f"{field}=?")
            params.append(body[field])

    if not updates:
        raise HTTPException(400, "No fields to update")

    updates.append("updated_at=?")
    params.append(now)
    params.append(incident_id)

    async with aiosqlite.connect(_db()) as db:
        await db.execute(
            f"UPDATE correlated_incidents SET {','.join(updates)} WHERE incident_id=?", params
        )
        await db.commit()

    return {"incident_id": incident_id, "status": "updated"}


@router.post("/api/v1/ai/incidents/{incident_id}/enrich")
async def enrich_incident(incident_id: str):
    """Run AI analysis on a specific incident."""
    from ai_analyst import call_llm
    from ai_correlator import ai_enrich_incident
    result = await ai_enrich_incident(_db(), incident_id, call_llm)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  AI RULE GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/api/v1/ai/generate-rule")
async def ai_generate_rule(request: Request):
    """AI generates a detection rule from observed attack patterns or user description."""
    body = await request.json()
    description = body.get("description", "")
    from_incident = body.get("incident_id", "")
    from_events = body.get("event_ids", [])

    context = ""

    # Build context from incident
    if from_incident:
        async with aiosqlite.connect(_db()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT * FROM correlated_incidents WHERE incident_id=?", (from_incident,)
            )
            inc = await cur.fetchone()
            if inc:
                inc = dict(inc)
                context += f"\nIncident: {inc.get('title', '')}"
                context += f"\nSummary: {inc.get('summary', '')}"
                context += f"\nKill Chain: {inc.get('kill_chain_stages', '[]')}"
                context += f"\nMITRE: {inc.get('mitre_techniques', '[]')}"

    # Build context from events
    if from_events:
        async with aiosqlite.connect(_db()) as db:
            db.row_factory = aiosqlite.Row
            for eid in from_events[:10]:
                cur = await db.execute("SELECT * FROM events WHERE event_id=?", (eid,))
                ev = await cur.fetchone()
                if ev:
                    ev = dict(ev)
                    context += f"\nEvent: {ev.get('event_type','')} | {ev.get('hostname','')} | {ev.get('severity','')} | MITRE: {ev.get('mitre_id','')} | Rule: {ev.get('rule_name','')}"
                    payload = ev.get("payload", "{}")
                    try:
                        p = json.loads(payload)
                        if p.get("cmdline"):
                            context += f"\n  cmdline: {p['cmdline'][:200]}"
                        if p.get("image"):
                            context += f"\n  process: {p['image']}"
                    except:
                        pass

    # Get existing rules for context
    async with aiosqlite.connect(_db()) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT rule_id, name, event_types, match_field, match_pattern FROM detection_rules LIMIT 10")
        existing = [dict(r) for r in await cur.fetchall()]

    from ai_analyst import call_llm

    system = """You are a detection engineer. Generate a Cibervault detection rule.
Respond ONLY with this JSON:
{
  "name": "Rule name",
  "description": "What this rule detects",
  "event_types": ["process_create"],
  "severity": "high",
  "mitre_id": "T1059.001",
  "mitre_tactic": "Execution",
  "base_score": 70,
  "match_field": "cmdline",
  "match_pattern": "regex_pattern_here",
  "rationale": "Why this rule matters"
}

Valid event_types: process_create, network_connection, file_create, file_modify, file_delete,
auth_failure, auth_success, auth_explicit, service_install, registry_modify, dns_query,
audit_clear, privilege_escalation, scheduled_task, wmi_activity, powershell_script

Valid match_fields: cmdline, image, parent_image, target_filename, destination_ip,
source_ip, user, registry_key, service_name, query_name

match_pattern should be a Python regex pattern."""

    prompt = f"""Generate a detection rule for:
{description or 'Based on the attack pattern observed below'}

{context if context else 'No specific event context provided.'}

Existing rules (avoid duplicates):
{json.dumps([r['name'] for r in existing])}

Generate a precise, low-false-positive detection rule as JSON:"""

    try:
        result = await call_llm(prompt, system, max_tokens=600, task="analyze")

        # Parse response
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

        if not parsed.get("name"):
            return {"error": "AI could not generate a valid rule", "raw": result[:500]}

        # Return rule for user review (not auto-created)
        rule_id = f"AI-{str(uuid.uuid4())[:6].upper()}"
        parsed["rule_id"] = rule_id
        parsed["source"] = "ai_generated"
        parsed["status"] = "draft"

        return {"rule": parsed, "status": "draft"}

    except Exception as e:
        log.error(f"AI rule generation failed: {e}")
        return {"error": str(e)}


@router.post("/api/v1/ai/generate-rule/accept")
async def accept_ai_rule(request: Request):
    """Accept and save an AI-generated detection rule."""
    body = await request.json()
    rule = body.get("rule", {})

    if not rule.get("name"):
        raise HTTPException(400, "Invalid rule")

    rule_id = f"CUSTOM-{str(uuid.uuid4())[:8].upper()}"
    now = datetime.now(timezone.utc).isoformat()

    async with aiosqlite.connect(_db()) as db:
        await db.execute("""
            INSERT INTO detection_rules
            (rule_id, name, description, event_types, severity, mitre_id, mitre_tactic,
             base_score, match_field, match_pattern, enabled, created_by, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            rule_id,
            rule.get("name", "AI Generated Rule"),
            rule.get("description", "") + f" [AI-generated: {rule.get('rationale', '')}]",
            json.dumps(rule.get("event_types", [])),
            rule.get("severity", "medium"),
            rule.get("mitre_id", ""),
            rule.get("mitre_tactic", ""),
            int(rule.get("base_score", 50)),
            rule.get("match_field", "cmdline"),
            rule.get("match_pattern", ""),
            1,
            "ai_analyst",
            now,
        ))
        await db.commit()

    return {"rule_id": rule_id, "status": "created", "name": rule.get("name")}


# ═══════════════════════════════════════════════════════════════════════════════
#  ENHANCED AI CHAT CONTEXT
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/api/v1/ai/chat/v2")
async def ai_chat_v2(request: Request):
    """Enhanced AI chat with richer SIEM context including process trees, UEBA, Wazuh."""
    body = await request.json()
    message = body.get("message", "").strip()
    history = body.get("history", [])
    if not message:
        raise HTTPException(400, "message required")

    async with aiosqlite.connect(_db()) as db:
        db.row_factory = aiosqlite.Row

        # ── 1. Recent alerts (expanded) ──
        cur = await db.execute("""
            SELECT event_id, event_type, hostname, mitre_id, mitre_tactic, rule_name,
                   severity, risk_score, source_ip, event_time, payload
            FROM events WHERE is_suspicious=1
            ORDER BY event_time DESC LIMIT 6
        """)
        recent_alerts = [dict(r) for r in await cur.fetchall()]

        # ── 2. Agents ──
        cur = await db.execute("SELECT hostname, os, ip_address, status FROM agents LIMIT 10")
        agents = [dict(r) for r in await cur.fetchall()]

        # ── 3. Severity counts 24h ──
        cur = await db.execute("""
            SELECT severity, COUNT(*) as cnt FROM events
            WHERE is_suspicious=1 AND event_time > datetime('now','-24 hours')
            GROUP BY severity
        """)
        sev_counts = {r["severity"]: r["cnt"] for r in await cur.fetchall()}

        # ── 4. Top MITRE tactics ──
        cur = await db.execute("""
            SELECT mitre_tactic, COUNT(*) as cnt FROM events
            WHERE mitre_tactic != '' AND is_suspicious=1
            AND event_time > datetime('now','-24 hours')
            GROUP BY mitre_tactic ORDER BY cnt DESC LIMIT 5
        """)
        top_tactics = [f"{r['mitre_tactic']}({r['cnt']})" for r in await cur.fetchall()]

        # ── 5. Process trees (NEW) ──
        process_context = ""
        try:
            cur = await db.execute("""
                SELECT payload FROM events
                WHERE event_type='process_tree' AND event_time > datetime('now', '-1 hour')
                ORDER BY event_time DESC LIMIT 3
            """)
            ptrees = await cur.fetchall()
            if ptrees:
                process_context = "\nRECENT PROCESS TREES:\n"
                for pt in ptrees:
                    try:
                        p = json.loads(pt["payload"])
                        trees = p.get("process_trees") or p.get("trees") or []
                        for tree in trees[:2]:
                            process_context += f"- {tree.get('name','?')} (PID:{tree.get('pid','?')}) → children: {len(tree.get('children',[]))}\n"
                    except:
                        pass
        except:
            pass

        # ── 6. UEBA anomalies (NEW) ──
        ueba_context = ""
        try:
            cur = await db.execute("""
                SELECT hostname, username, anomaly_type, anomaly_score, details
                FROM ueba_alerts
                WHERE created_at > datetime('now', '-24 hours')
                ORDER BY anomaly_score DESC LIMIT 5
            """)
            ueba = [dict(r) for r in await cur.fetchall()]
            if ueba:
                ueba_context = "\nUEBA ANOMALIES (24h):\n"
                for u in ueba:
                    ueba_context += f"- [{u.get('anomaly_type','')}] {u.get('username','?')}@{u.get('hostname','?')} score:{u.get('anomaly_score',0)}\n"
        except:
            pass

        # ── 7. Correlated incidents (NEW) ──
        incident_context = ""
        try:
            cur = await db.execute("""
                SELECT incident_id, title, severity, priority, event_count, status
                FROM correlated_incidents
                WHERE status='open' ORDER BY created_at DESC LIMIT 3
            """)
            incidents = [dict(r) for r in await cur.fetchall()]
            if incidents:
                incident_context = "\nOPEN INCIDENTS:\n"
                for inc in incidents:
                    incident_context += f"- [{inc['priority']}][{inc['severity'].upper()}] {inc['title']} ({inc['event_count']} events)\n"
        except:
            pass

        # ── 8. SOAR recent actions (NEW) ──
        soar_context = ""
        try:
            cur = await db.execute("""
                SELECT action_type, hostname, status, trigger_summary
                FROM soar_actions
                WHERE created_at > datetime('now', '-24 hours')
                ORDER BY created_at DESC LIMIT 5
            """)
            soar_actions = [dict(r) for r in await cur.fetchall()]
            if soar_actions:
                soar_context = "\nSOAR ACTIONS (24h):\n"
                for sa in soar_actions:
                    soar_context += f"- {sa['action_type']} on {sa.get('hostname','?')} [{sa['status']}] — {sa.get('trigger_summary','')[:80]}\n"
        except:
            pass

    # ── Build enriched system prompt ──
    alert_lines = []
    for a in recent_alerts:
        line = f"- [{a['severity'].upper()}] {a['event_type']} on {a['hostname']}"
        if a.get('source_ip'):
            line += f" from {a['source_ip']}"
        if a.get('mitre_id'):
            line += f" [{a['mitre_id']}]"
        if a.get('rule_name'):
            line += f" — {a['rule_name'][:50]}"
        # Include cmdline for process events
        if a.get("payload") and a["event_type"] in ("process_create", "process_tree"):
            try:
                p = json.loads(a["payload"])
                cmd = p.get("cmdline", p.get("CommandLine", ""))
                if cmd:
                    line += f"\n  cmdline: {cmd[:120]}"
            except:
                pass
        alert_lines.append(line)

    system_prompt = f"""You are the Cibervault AI Security Analyst — an expert SOC analyst AI.
You have FULL access to the SIEM data below. Be CONCISE: max 4 sentences unless asked for detail. Reference real data.

Use markdown formatting: **bold** for emphasis, `code` for IPs/hashes/commands, bullet lists for actions.

ENVIRONMENT STATUS:
- Endpoints: {', '.join(a['hostname'] + '(' + a.get('status','?') + ')' for a in agents)}
- Alerts 24h: Critical:{sev_counts.get('critical',0)} High:{sev_counts.get('high',0)} Medium:{sev_counts.get('medium',0)} Low:{sev_counts.get('low',0)}
- Top MITRE tactics: {', '.join(top_tactics) or 'none detected'}

RECENT ALERTS:
{chr(10).join(alert_lines[:12])}
{process_context}
{ueba_context}
{incident_context}
{soar_context}

CAPABILITIES YOU CAN SUGGEST:
- Block IP, isolate host, kill process (Active Response)
- Run Defender scan, collect triage data
- Investigate with threat hunting queries
- Generate remediation scripts
- Create detection rules for new patterns
- Run SOAR auto-response rules

Answer security questions with specific data. Be direct and actionable."""

    # Build messages
    messages = []
    for h in history[-8:]:
        messages.append({"role": h["role"], "content": h["content"][:600]})
    messages.append({"role": "user", "content": message})

    from ai_analyst import call_llm, _AI_SETTINGS
    if not _AI_SETTINGS.get("enabled"):
        return {"reply": "AI not configured. Go to AI Analyst → Setup.", "error": True}

    try:
        if _AI_SETTINGS.get("backend") == "claude" and _AI_SETTINGS.get("claude_key"):
            import aiohttp as aiohttp_mod
            headers = {
                "x-api-key": _AI_SETTINGS["claude_key"],
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }
            payload = {
                "model": _AI_SETTINGS.get("claude_model", "claude-haiku-4-5-20251001"),
                "max_tokens": 1200,
                "system": system_prompt,
                "messages": messages,
            }
            async with aiohttp_mod.ClientSession() as s:
                async with s.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=headers, json=payload,
                    timeout=aiohttp_mod.ClientTimeout(total=60)
                ) as r:
                    data = await r.json()
                    reply = data["content"][0]["text"] if r.status == 200 else f"API error {r.status}"
        else:
            full_prompt = system_prompt + "\n\n"
            for h in history[-6:]:
                role = "User" if h["role"] == "user" else "Assistant"
                full_prompt += f"{role}: {h['content'][:400]}\n"
            full_prompt += f"User: {message}\nAssistant:"
            reply = await call_llm(full_prompt, "", max_tokens=300, task="chat")

        return {
            "reply": reply,
            "context": {
                "alerts_24h": sum(sev_counts.values()),
                "top_tactics": top_tactics,
                "open_incidents": len(incidents) if 'incidents' in dir() else 0,
                "ueba_anomalies": len(ueba) if 'ueba' in dir() else 0,
            }
        }
    except Exception as e:
        log.error(f"AI chat v2 error: {e}")
        return {"reply": f"AI error: {e}", "error": True}
