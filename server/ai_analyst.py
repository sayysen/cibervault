"""
Cibervault AI Analyst - Phase 4
Easy setup: just set ANTHROPIC_API_KEY or install Ollama locally.
No Docker, no complexity.

Features:
- Event analysis in plain English
- Auto-generate PowerShell/Bash remediation scripts
- Natural language threat hunting
- Incident reports
- Behavioral anomaly explanations
"""

import asyncio
import json
import logging
import os
import re
import aiohttp
from datetime import datetime, timezone

log = logging.getLogger("ai")

# ── Config - read from DB settings table ─────────────────────────────────────
_AI_SETTINGS = {
    "backend":        os.getenv("AI_BACKEND", "ollama"),   # "ollama" or "claude"
    "ollama_url":     os.getenv("OLLAMA_URL", "http://localhost:11434"),
    "ollama_model":   os.getenv("OLLAMA_MODEL", "phi3:mini"),       # reasoning/chat
    "ollama_coder":   os.getenv("OLLAMA_CODER", "qwen2.5-coder:7b"), # code/scripts
    "claude_key":     os.getenv("ANTHROPIC_API_KEY", ""),
    "claude_model":   "claude-haiku-4-5-20251001",
    "enabled":        True,   # Ollama is default and available
}

def update_settings(new: dict):
    _AI_SETTINGS.update(new)
    if new.get("claude_key"):
        _AI_SETTINGS["backend"] = "claude"
        _AI_SETTINGS["enabled"] = True
    elif new.get("ollama_url"):
        _AI_SETTINGS["backend"] = "ollama"


# ── Core LLM call ─────────────────────────────────────────────────────────────

async def call_llm(prompt: str, system: str = "", max_tokens: int = 1200, task: str = "chat") -> str:
    """Single entry point for all LLM calls.
    task: 'chat'|'analyze' → reasoning model (llama3.2)
          'code'|'script'  → coder model (qwen2.5-coder)
    """
    if _AI_SETTINGS["backend"] == "claude" and _AI_SETTINGS.get("claude_key"):
        return await _call_claude(prompt, system, max_tokens)
    else:
        # Pick the right model for the task
        if task in ("code", "script", "remediation"):
            model = _AI_SETTINGS.get("ollama_coder", "qwen2.5-coder:7b")
        else:
            model = _AI_SETTINGS.get("ollama_model", "llama3.2")
        return await _call_ollama(prompt, system, max_tokens, model=model)


async def _call_claude(prompt: str, system: str, max_tokens: int) -> str:
    key = _AI_SETTINGS["claude_key"]
    headers = {
        "x-api-key":         key,
        "anthropic-version": "2023-06-01",
        "content-type":      "application/json",
    }
    body = {
        "model":      _AI_SETTINGS["claude_model"],
        "max_tokens": max_tokens,
        "system":     system or "You are a SOC analyst AI. Be concise and technical.",
        "messages":   [{"role": "user", "content": prompt}],
    }
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers, json=body,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as r:
                if r.status != 200:
                    txt = await r.text()
                    return f"[Claude API error {r.status}: {txt[:200]}]"
                data = await r.json()
                return data["content"][0]["text"]
    except Exception as e:
        return f"[Claude error: {e}]"


async def _call_ollama(prompt: str, system: str, max_tokens: int, model: str = "") -> str:
    url   = _AI_SETTINGS["ollama_url"]
    model = model or _AI_SETTINGS["ollama_model"]
    body  = {
        "model":  model,
        "prompt": prompt,
        "system": system or "You are a SOC analyst AI. Be concise and technical.",
        "stream": False,
        "options": {"num_predict": max_tokens, "temperature": 0.2, "num_thread": 48},
    }
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(
                f"{url}/api/generate", json=body,
                timeout=aiohttp.ClientTimeout(total=300)
            ) as r:
                if r.status != 200:
                    return f"[Ollama error {r.status}]"
                data = await r.json()
                return data.get("response", "[No response]")
    except aiohttp.ClientConnectorError:
        return (
            "[Ollama not running. Install with:\n"
            "  curl -fsSL https://ollama.ai/install.sh | sh\n"
            "  ollama pull llama3.2\n"
            "Then set AI_BACKEND=ollama in settings]"
        )
    except asyncio.TimeoutError:
        return "[Ollama timeout - model may be loading, try again]"
    except Exception as e:
        return f"[Ollama error: {e}]"


def _parse_json(text: str) -> dict:
    """Extract JSON from LLM response safely."""
    # Try direct parse first
    try:
        return json.loads(text)
    except Exception:
        pass
    # Find JSON block
    for pattern in [r'\{[^{}]+(?:\{[^{}]*\}[^{}]*)*\}', r'\{.*\}']:
        m = re.search(pattern, text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except Exception:
                pass
    return {}


# ── Status ────────────────────────────────────────────────────────────────────

async def get_status() -> dict:
    """Check AI backend availability."""
    backend = _AI_SETTINGS["backend"]

    if backend == "claude" and _AI_SETTINGS.get("claude_key"):
        try:
            result = await _call_claude("Reply with just: OK", "Reply with just: OK", 10)
            return {
                "backend":     "Claude API",
                "model":       _AI_SETTINGS["claude_model"],
                "available":   "OK" in result,
                "api_key_set": True,
            }
        except Exception as e:
            return {"backend": "Claude API", "available": False, "error": str(e)}

    # Ollama
    url = _AI_SETTINGS.get("ollama_url", "http://localhost:11434")
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{url}/api/tags",
                             timeout=aiohttp.ClientTimeout(total=5)) as r:
                data     = await r.json()
                models   = [m["name"] for m in data.get("models", [])]
                chat_model  = _AI_SETTINGS.get("ollama_model",  "llama3.2")
                coder_model = _AI_SETTINGS.get("ollama_coder",  "qwen2.5-coder:7b")
                chat_ok  = any(chat_model.split(":")[0]  in m for m in models)
                coder_ok = any(coder_model.split(":")[0] in m for m in models)
                return {
                    "backend":      "Ollama (Local)",
                    "available":    chat_ok,
                    "model":        chat_model,
                    "coder_model":  coder_model,
                    "chat_ready":   chat_ok,
                    "coder_ready":  coder_ok,
                    "models":       models,
                    "ollama_url":   url,
                }
    except Exception as e:
        return {
            "backend":   "Ollama (Local)",
            "available": False,
            "error":     str(e),
            "setup_guide": {
                "step1": "Install: curl -fsSL https://ollama.ai/install.sh | sh",
                "step2": "Pull model: ollama pull llama3.2",
                "step3": "Pull coder: ollama pull qwen2.5-coder:7b",
                "alternative": "Use Claude API — go to Configure tab",
            }
        }


async def analyze_event(event: dict) -> dict:
    """Analyze a single security event."""
    etype   = event.get("event_type","unknown")
    host    = event.get("hostname","?")
    sev     = event.get("severity","info")
    mitre   = event.get("mitre_id","")
    rule    = event.get("rule_name","")
    score   = event.get("risk_score", 0)
    src_ip  = event.get("source_ip","")

    payload = event.get("payload", {})
    if isinstance(payload, str):
        try: payload = json.loads(payload)
        except: payload = {}

    proc = ""
    cmd  = ""
    user = ""
    if isinstance(payload, dict):
        proc = (payload.get("process") or {}).get("name","")
        cmd  = (payload.get("process") or {}).get("cmdline","")[:200]
        user = (payload.get("win_event") or payload.get("auth") or {}).get("user","")
        if not user: user = (payload.get("process") or {}).get("user","")

    system = """You are a SOC analyst. Analyze this security event and respond ONLY with this JSON:
{
  "summary": "1-2 sentence plain English summary",
  "threat_level": "critical|high|medium|low|info",
  "what_happened": "technical explanation",
  "attacker_goal": "what attacker wants to achieve",
  "false_positive_chance": "high|medium|low",
  "immediate_action": "what analyst should do RIGHT NOW",
  "investigate_next": ["step1", "step2", "step3"]
}"""

    prompt = f"""Event: {etype} | Host: {host} | Severity: {sev} | Score: {score}
MITRE: {mitre} | Rule: {rule} | Source IP: {src_ip}
Process: {proc} | User: {user}
Command: {cmd}

Analyze and respond with JSON only."""

    response = await call_llm(prompt, system, max_tokens=600)
    parsed   = _parse_json(response)

    if not parsed.get("summary"):
        return {
            "summary":              f"{etype} event on {host}",
            "threat_level":         sev,
            "what_happened":        response[:300] if response else "Analysis unavailable",
            "attacker_goal":        "Unknown",
            "false_positive_chance":"medium",
            "immediate_action":     "Review manually",
            "investigate_next":     ["Check full event payload", "Review related events"],
        }
    return parsed


async def generate_remediation(event: dict, os_type: str = "windows") -> dict:
    """Generate a remediation script for an incident."""
    etype  = event.get("event_type","")
    host   = event.get("hostname","?")
    mitre  = event.get("mitre_id","")
    src_ip = event.get("source_ip","")

    payload = event.get("payload", {})
    if isinstance(payload, str):
        try: payload = json.loads(payload)
        except: payload = {}

    proc = ""
    cmd  = ""
    if isinstance(payload, dict):
        proc = (payload.get("process") or {}).get("name","")
        cmd  = (payload.get("process") or {}).get("cmdline","")[:200]

    is_windows = os_type.lower() == "windows"
    lang = "PowerShell" if is_windows else "Bash"

    # BLOCKED dangerous patterns
    BLOCKED = [
        "Format-Volume", "rm -rf /", "Remove-Item C:\\Windows",
        "Stop-Service WinDefend", "net stop", "dd if=/dev/zero",
        "Set-MpPreference -DisableRealtimeMonitoring $true",
    ]

    system = f"""You are a security engineer. Generate a {lang} remediation script.
Rules:
- Script MUST start with: # CIBERVAULT AUTO-REMEDIATION
- Add # comments explaining each step
- Include safety checks before destructive actions
- Collect evidence FIRST, then contain, then remediate
- Output ONLY the script, no markdown fences"""

    prompt = f"""Generate a {lang} remediation script for:

Incident: {etype} on {host}
MITRE: {mitre}
Process: {proc}
Command: {cmd}
Source IP: {src_ip}
OS: {os_type}

Script should:
1. Create evidence folder and save forensic data
2. Stop the threat (kill process / block IP if applicable)
3. Check for persistence (registry/cron/services)
4. Verify defenses are enabled
5. Print summary of actions taken"""

    script = await call_llm(prompt, system, max_tokens=1500)

    # Remove markdown fences if model added them
    script = re.sub(r'^```(?:powershell|bash|sh|ps1)?\s*\n?', '', script.strip(), flags=re.I)
    script = re.sub(r'\n?```\s*$', '', script.strip())

    # Block dangerous commands
    for bad in BLOCKED:
        if bad.lower() in script.lower():
            script = f"# SAFETY BLOCK: Script contained dangerous command: {bad}\n# Please review manually."
            break

    if not script.startswith("#"):
        script = f"# CIBERVAULT AUTO-REMEDIATION\n# Event: {etype} on {host}\n# Generated: {datetime.now().isoformat()}\n# !! REVIEW BEFORE EXECUTING !!\n\n" + script

    return {
        "script":       script,
        "language":     lang,
        "event_type":   etype,
        "hostname":     host,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "warning":      "AI-generated script. Review carefully before executing. Test in safe environment first.",
    }


async def analyze_incident(events: list) -> dict:
    """Correlate multiple events into an incident analysis."""
    if not events:
        return {"error": "No events"}

    timeline = []
    for ev in events[:25]:
        timeline.append({
            "t":    (ev.get("event_time",""))[:16],
            "type": ev.get("event_type",""),
            "host": ev.get("hostname",""),
            "sev":  ev.get("severity",""),
            "rule": ev.get("rule_name","")[:50],
            "mitre":ev.get("mitre_id",""),
            "score":ev.get("risk_score",0),
        })

    system = """You are a SOC incident analyst. Analyze an attack timeline.
Respond ONLY with this JSON:
{
  "title": "incident title",
  "summary": "2-3 sentence attack chain description",
  "kill_chain": "Reconnaissance|Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|C2|Exfiltration|Impact",
  "confidence": "high|medium|low",
  "iocs": ["ioc1", "ioc2"],
  "affected": ["host1"],
  "priority": "P1|P2|P3|P4",
  "actions": ["action1", "action2", "action3"]
}"""

    prompt = f"""Analyze this incident timeline ({len(events)} events):
{json.dumps(timeline, indent=1)}

Identify the attack pattern. JSON only."""

    result = await call_llm(prompt, system, max_tokens=800)
    parsed = _parse_json(result)

    if not parsed.get("title"):
        return {
            "title":      f"Incident — {len(events)} events",
            "summary":    result[:500],
            "priority":   "P2",
            "kill_chain": "Unknown",
            "confidence": "low",
            "actions":    ["Review events manually"],
        }
    return parsed


async def hunt_query(question: str, context: list) -> str:
    """Answer a natural language threat hunting question."""
    etypes  = list(set(e.get("event_type","") for e in context[:200]))[:15]
    hosts   = list(set(e.get("hostname","") for e in context[:200]))[:10]
    mitres  = list(set(e.get("mitre_id","") for e in context[:200] if e.get("mitre_id")))[:10]
    high    = [e for e in context if e.get("severity") in ("critical","high")][:5]

    system = """You are a threat hunting expert. Answer security questions clearly and specifically.
Provide actionable intelligence. Reference MITRE ATT&CK when relevant."""

    prompt = f"""Threat Hunt Question: {question}

Environment:
- Monitored hosts: {', '.join(hosts) or 'none'}
- Event types seen: {', '.join(etypes) or 'none'}
- MITRE techniques detected: {', '.join(mitres) or 'none'}
- High severity events: {len(high)} in context
- Total events: {len(context)}

Answer with specific findings and recommended hunt steps:"""

    return await call_llm(prompt, system, max_tokens=800)


async def generate_report(events: list, hostname: str = "") -> str:
    """Generate a professional incident report."""
    incident = await analyze_incident(events)

    hosts   = list(set(e.get("hostname","") for e in events))
    t_start = min((e.get("event_time","") for e in events), default="?")[:19]
    t_end   = max((e.get("event_time","") for e in events), default="?")[:19]
    sevs    = {}
    for e in events:
        s = e.get("severity","info")
        sevs[s] = sevs.get(s,0)+1

    system = """You are a SOC manager writing an incident report. Be professional, clear, and thorough.
Format: Executive Summary | Timeline | Technical Details | Impact | Root Cause | Recommendations"""

    prompt = f"""Write a professional security incident report:

Title: {incident.get('title','Security Incident')}
Priority: {incident.get('priority','P2')}
Affected Systems: {', '.join(hosts)}
Timeframe: {t_start} to {t_end}
Event Count: {len(events)} total | Severity breakdown: {json.dumps(sevs)}
Attack Chain: {incident.get('kill_chain','Unknown')}
Summary: {incident.get('summary','')}
IOCs: {', '.join(incident.get('iocs',[]))}
Recommended Actions: {', '.join(incident.get('actions',[]))}

Write a complete professional report:"""

    return await call_llm(prompt, system, max_tokens=2000)
