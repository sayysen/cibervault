"""
Cibervault EDR — Email Notification Service

Sends HTML email alerts via SMTP.
Config is stored in the database (configurable from dashboard).
Supports: Gmail, Office365, custom SMTP with TLS/STARTTLS.
"""

import smtplib
import json
import logging
import asyncio
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from email.utils          import formatdate
from datetime             import datetime
from typing               import Optional

import aiosqlite
from database import DB

log = logging.getLogger("cibervault.email")


# ─── Load SMTP config from database ──────────────────────────────────────────

async def get_smtp_config() -> Optional[dict]:
    """Load SMTP configuration from database."""
    async with aiosqlite.connect(DB) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM smtp_config LIMIT 1")
        row = await cur.fetchone()
    return dict(row) if row else None


async def save_smtp_config(cfg: dict) -> None:
    """Save or update SMTP configuration."""
    async with aiosqlite.connect(DB) as db:
        # Upsert: delete existing then insert
        await db.execute("DELETE FROM smtp_config")
        await db.execute("""
            INSERT INTO smtp_config
            (host, port, username, password, from_addr, from_name,
             use_tls, use_starttls, recipients, enabled, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            cfg.get("host", ""),
            int(cfg.get("port", 587)),
            cfg.get("username", ""),
            cfg.get("password", ""),
            cfg.get("from_addr", ""),
            cfg.get("from_name", "Cibervault EDR"),
            int(cfg.get("use_tls", 0)),
            int(cfg.get("use_starttls", 1)),
            json.dumps(cfg.get("recipients", [])),
            int(cfg.get("enabled", 1)),
            datetime.utcnow().isoformat(),
        ))
        await db.commit()


# ─── Core send function ───────────────────────────────────────────────────────

async def send_alert_email(
    alert: dict,
    score_info: dict,
    cfg: Optional[dict] = None,
) -> tuple[bool, str]:
    """
    Send an HTML incident alert email.
    Returns (success: bool, message: str).
    """
    if cfg is None:
        cfg = await get_smtp_config()

    if not cfg or not cfg.get("enabled"):
        return False, "SMTP not configured or disabled"

    recipients = cfg.get("recipients") or []
    if isinstance(recipients, str):
        try:
            recipients = json.loads(recipients)
        except Exception:
            recipients = [r.strip() for r in recipients.split(",") if r.strip()]

    if not recipients:
        return False, "No recipients configured"

    # Build email
    subject = build_subject(alert, score_info)
    html    = build_html_body(alert, score_info)
    text    = build_text_body(alert, score_info)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"{cfg.get('from_name', 'Cibervault EDR')} <{cfg['from_addr']}>"
    msg["To"]      = ", ".join(recipients)
    msg["Date"]    = formatdate(localtime=True)
    msg["X-Mailer"] = "Cibervault-EDR/1.0"

    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    # Send in thread pool (smtplib is blocking)
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _send_blocking, cfg, recipients, msg)
        log.info(f"Alert email sent: {subject} → {recipients}")
        return True, "Sent OK"
    except Exception as e:
        log.error(f"Email send failed: {e}")
        return False, str(e)


def _send_blocking(cfg: dict, recipients: list[str], msg: MIMEMultipart):
    """Blocking SMTP send — runs in thread pool."""
    host   = cfg["host"]
    port   = int(cfg.get("port", 587))
    user   = cfg.get("username", "")
    passwd = cfg.get("password", "")
    tls    = bool(cfg.get("use_tls"))
    starttls = bool(cfg.get("use_starttls"))

    if tls:
        # SSL from the start (port 465)
        server = smtplib.SMTP_SSL(host, port, timeout=15)
    else:
        server = smtplib.SMTP(host, port, timeout=15)
        server.ehlo()
        if starttls:
            server.starttls()
            server.ehlo()

    if user and passwd:
        server.login(user, passwd)

    server.sendmail(msg["From"], recipients, msg.as_string())
    server.quit()


# ─── Test connection ──────────────────────────────────────────────────────────

async def test_smtp_connection(cfg: dict) -> tuple[bool, str]:
    """Test SMTP credentials without sending a real email."""
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _test_blocking, cfg)
        return True, "Connection successful"
    except smtplib.SMTPAuthenticationError:
        return False, "Authentication failed — check username/password"
    except smtplib.SMTPConnectError as e:
        return False, f"Cannot connect to {cfg.get('host')}:{cfg.get('port')} — {e}"
    except Exception as e:
        return False, str(e)


def _test_blocking(cfg: dict):
    host   = cfg["host"]
    port   = int(cfg.get("port", 587))
    user   = cfg.get("username", "")
    passwd = cfg.get("password", "")
    tls    = bool(cfg.get("use_tls"))

    if tls:
        server = smtplib.SMTP_SSL(host, port, timeout=10)
    else:
        server = smtplib.SMTP(host, port, timeout=10)
        server.ehlo()
        if cfg.get("use_starttls"):
            server.starttls()
            server.ehlo()

    if user and passwd:
        server.login(user, passwd)
    server.quit()


# ─── Email builders ───────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "#E53E3E",
    "high":     "#E87A1B",
    "medium":   "#D4AC0D",
    "low":      "#2EA05E",
    "info":     "#3B82F6",
}

def build_subject(alert: dict, score_info: dict) -> str:
    score    = score_info.get("score", 0)
    band     = score_info.get("severity_band", "unknown").upper()
    hostname = alert.get("hostname", "Unknown Host")
    ev_type  = alert.get("event_type", "unknown").replace("_", " ").title()
    return f"[CIBERVAULT {band}] {ev_type} on {hostname} — Score {score}"


def build_text_body(alert: dict, score_info: dict) -> str:
    bd = score_info.get("breakdown", {})
    proc = alert.get("process", {})
    net  = alert.get("network", {})
    return f"""
CIBERVAULT EDR — SECURITY ALERT
================================
Time:        {alert.get('event_time', 'N/A')}
Hostname:    {alert.get('hostname', 'N/A')}
Event Type:  {alert.get('event_type', 'N/A')}
Risk Score:  {score_info.get('score', 0)} / 100  ({score_info.get('severity_band','').upper()})

SCORE BREAKDOWN
  Base score:        {bd.get('base_score', 0)}
  MITRE tactic:      {bd.get('mitre_tactic', 'unknown')} (×{bd.get('mitre_weight',1)})
  Asset criticality: {bd.get('asset_criticality','low')} (×{bd.get('asset_weight',1)})
  Frequency boost:   ×{bd.get('frequency_boost',1)} ({bd.get('frequency_count',1)} events)

PROCESS
  Name:    {proc.get('name','N/A')}
  PID:     {proc.get('pid','N/A')}
  Parent:  {proc.get('parent_name','N/A')}
  User:    {proc.get('user','N/A')}
  Command: {proc.get('cmdline','N/A')}

NETWORK
  Destination: {net.get('dst_ip','N/A')}:{net.get('dst_port','N/A')}
  Protocol:    {net.get('protocol','N/A')}

--
Cibervault EDR | https://cibervault.com
To unsubscribe or configure notifications, update SMTP settings in the dashboard.
""".strip()


def build_html_body(alert: dict, score_info: dict) -> str:
    score    = score_info.get("score", 0)
    band     = score_info.get("severity_band", "info")
    color    = SEVERITY_COLORS.get(band, "#3B82F6")
    hostname = alert.get("hostname", "Unknown Host")
    ev_type  = alert.get("event_type", "unknown").replace("_", " ").title()
    ev_time  = alert.get("event_time", "N/A")
    proc     = alert.get("process", {})
    net      = alert.get("network", {})
    bd       = score_info.get("breakdown", {})
    agent_id = alert.get("agent_id", "")

    # Score ring (SVG)
    pct   = score / 100
    circ  = 2 * 3.14159 * 28
    dash  = pct * circ
    gap   = circ - dash

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#0D1319; color:#E8EEF4; margin:0; padding:0; }}
  .container {{ max-width:600px; margin:0 auto; padding:24px 16px; }}
  .card {{ background:#111820; border:1px solid rgba(255,255,255,0.08); border-radius:12px; padding:24px; margin-bottom:16px; }}
  .header {{ border-left:4px solid {color}; padding-left:16px; margin-bottom:20px; }}
  .badge {{ display:inline-block; padding:3px 10px; border-radius:4px; font-size:11px; font-weight:600; letter-spacing:0.08em; text-transform:uppercase; }}
  .badge-{band} {{ background:{color}22; color:{color}; border:1px solid {color}44; }}
  table {{ width:100%; border-collapse:collapse; }}
  td {{ padding:7px 0; border-bottom:1px solid rgba(255,255,255,0.06); font-size:13px; vertical-align:top; }}
  td:first-child {{ color:#8A9BB0; width:40%; padding-right:12px; }}
  td:last-child {{ font-family:monospace; font-size:12px; }}
  .score-ring {{ display:flex; align-items:center; gap:16px; }}
  .section-title {{ font-size:11px; font-weight:600; letter-spacing:0.1em; text-transform:uppercase; color:#4D6075; margin:16px 0 10px; }}
  .cmdline {{ background:#0D1319; border:1px solid rgba(255,255,255,0.08); border-radius:6px; padding:8px 12px; font-family:monospace; font-size:11px; color:#E87A1B; word-break:break-all; margin-top:4px; }}
  .btn {{ display:inline-block; padding:10px 20px; background:{color}22; border:1px solid {color}44; border-radius:6px; color:{color}; text-decoration:none; font-size:12px; font-weight:600; margin-top:8px; }}
  .footer {{ text-align:center; font-size:11px; color:#4D6075; padding:16px 0; }}
  .breakdown-row {{ display:flex; justify-content:space-between; padding:5px 0; border-bottom:1px solid rgba(255,255,255,0.04); font-size:12px; }}
  .breakdown-label {{ color:#8A9BB0; }}
  .breakdown-val {{ font-family:monospace; color:#E8EEF4; }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="card">
    <div class="header">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
        <span style="font-size:20px;font-weight:600;color:#E8EEF4">{ev_type}</span>
        <span class="badge badge-{band}">{band}</span>
      </div>
      <div style="font-size:13px;color:#8A9BB0">{ev_time} &nbsp;·&nbsp; {hostname}</div>
    </div>

    <!-- Score ring + breakdown -->
    <div class="score-ring">
      <svg width="80" height="80" viewBox="0 0 80 80">
        <circle cx="40" cy="40" r="28" fill="none" stroke="{color}22" stroke-width="8"/>
        <circle cx="40" cy="40" r="28" fill="none" stroke="{color}" stroke-width="8"
          stroke-dasharray="{dash:.1f} {gap:.1f}" stroke-linecap="round"
          transform="rotate(-90 40 40)"/>
        <text x="40" y="38" text-anchor="middle" fill="{color}" font-size="16" font-weight="700" font-family="sans-serif">{score}</text>
        <text x="40" y="52" text-anchor="middle" fill="#8A9BB0" font-size="8" font-family="sans-serif">/ 100</text>
      </svg>
      <div style="flex:1">
        <div class="breakdown-row"><span class="breakdown-label">Base score</span><span class="breakdown-val">{bd.get('base_score', 0)}</span></div>
        <div class="breakdown-row"><span class="breakdown-label">MITRE tactic</span><span class="breakdown-val">{bd.get('mitre_tactic','unknown')} ×{bd.get('mitre_weight',1)}</span></div>
        <div class="breakdown-row"><span class="breakdown-label">Asset criticality</span><span class="breakdown-val">{bd.get('asset_criticality','low')} ×{bd.get('asset_weight',1)}</span></div>
        <div class="breakdown-row"><span class="breakdown-label">Frequency boost</span><span class="breakdown-val">{bd.get('frequency_count',1)} events ×{bd.get('frequency_boost',1):.2f}</span></div>
      </div>
    </div>
  </div>

  <!-- Process details -->
  <div class="card">
    <div class="section-title">Process Details</div>
    <table>
      <tr><td>Process</td><td>{proc.get('name','N/A')}</td></tr>
      <tr><td>PID</td><td>{proc.get('pid','N/A')}</td></tr>
      <tr><td>Parent</td><td>{proc.get('parent_name','N/A')} (PID {proc.get('parent_pid','N/A')})</td></tr>
      <tr><td>User</td><td>{proc.get('user','N/A')}</td></tr>
      <tr><td>Path</td><td>{proc.get('exe_path','N/A')}</td></tr>
    </table>
    {"<div class='cmdline'>" + proc.get('cmdline','') + "</div>" if proc.get('cmdline') else ""}
  </div>

  {"<!-- Network --><div class='card'><div class='section-title'>Network Connection</div><table><tr><td>Destination</td><td>" + net.get('dst_ip','N/A') + ":" + str(net.get('dst_port','N/A')) + "</td></tr><tr><td>Protocol</td><td>" + net.get('protocol','N/A') + "</td></tr><tr><td>Direction</td><td>" + net.get('direction','N/A') + "</td></tr></table></div>" if net.get('dst_ip') else ""}

  <!-- Actions -->
  <div class="card">
    <div class="section-title">Actions</div>
    <p style="font-size:13px;color:#8A9BB0;margin:0 0 12px">Investigate this incident in the Cibervault dashboard or mark as false positive.</p>
    <a class="btn" href="#">Open in Dashboard</a>
    &nbsp;
    <a class="btn" href="#" style="background:rgba(46,160,94,0.12);color:#2EA05E;border-color:rgba(46,160,94,0.3)">Mark as False Positive</a>
  </div>

  <div class="footer">
    Cibervault EDR &nbsp;·&nbsp; Agent {agent_id[:8]}… &nbsp;·&nbsp;
    To stop receiving these emails, disable notifications in the dashboard.
  </div>
</div>
</body>
</html>"""
