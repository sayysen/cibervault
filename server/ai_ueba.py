"""
Cibervault AI-UEBA Engine
AI-powered User and Entity Behavior Analytics

Features:
1. AI Behavior Baselines — learns each user's normal patterns, auto-detects deviations
2. AI Risk Scoring — replaces static weights with contextual AI-assessed risk
3. User Investigation Assistant — "is this user compromised?" with full behavioral context
4. AI Peer Group Analysis — detects when a user acts differently from similar role users

Works alongside the existing rule-based UEBA engine (ueba.py) — this adds
AI interpretation on top of the raw anomaly detections.
"""

import json
import logging
import math
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Optional

import aiosqlite

log = logging.getLogger("ai_ueba")


# ══════════════════════════════════════════════════════════════════════════════
#  BEHAVIORAL BASELINE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class BehaviorBaseline:
    """
    Maintains per-user behavioral baselines from event history.
    Computes deviation scores for new activity.
    """

    def __init__(self):
        self._profiles = {}  # user -> profile dict

    async def build_from_db(self, db_path: str, days: int = 30):
        """Build baselines from historical event data."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row

            # Auth events for login patterns
            cur = await db.execute("""
                SELECT event_type, hostname, source_ip, event_time, payload
                FROM events
                WHERE event_type IN ('auth_success','auth_failure','auth_explicit','sudo_exec')
                AND event_time >= ?
                ORDER BY event_time ASC
            """, (cutoff,))
            auth_events = [dict(r) for r in await cur.fetchall()]

            # Process events for activity patterns
            cur = await db.execute("""
                SELECT event_type, hostname, event_time, payload, mitre_tactic, severity
                FROM events
                WHERE event_type IN ('process_create','file_create','file_modify','network_connection','service_install')
                AND event_time >= ?
                ORDER BY event_time ASC
            """, (cutoff,))
            activity_events = [dict(r) for r in await cur.fetchall()]

        # Build per-user profiles
        user_data = defaultdict(lambda: {
            "login_hours": [],
            "login_days": [],
            "source_ips": set(),
            "hostnames": set(),
            "event_types": defaultdict(int),
            "daily_event_counts": defaultdict(int),
            "tactics_seen": defaultdict(int),
            "severity_counts": defaultdict(int),
            "failed_logins": 0,
            "successful_logins": 0,
            "processes_launched": [],
            "total_events": 0,
        })

        for ev in auth_events:
            user = self._extract_user(ev)
            if not user:
                continue
            profile = user_data[user]

            try:
                dt = datetime.fromisoformat(ev["event_time"].replace("Z", "+00:00"))
                profile["login_hours"].append(dt.hour)
                profile["login_days"].append(dt.weekday())
                day_key = dt.strftime("%Y-%m-%d")
                profile["daily_event_counts"][day_key] += 1
            except:
                pass

            if ev.get("source_ip") and ev["source_ip"] not in ("", "127.0.0.1", "::1"):
                profile["source_ips"].add(ev["source_ip"])
            if ev.get("hostname"):
                profile["hostnames"].add(ev["hostname"])

            if ev["event_type"] == "auth_failure":
                profile["failed_logins"] += 1
            elif ev["event_type"] == "auth_success":
                profile["successful_logins"] += 1

            profile["event_types"][ev["event_type"]] += 1
            profile["total_events"] += 1

        for ev in activity_events:
            user = self._extract_user(ev)
            host = ev.get("hostname", "unknown")
            # Attribute activity to host if no user found
            key = user or f"host:{host}"
            profile = user_data[key]

            profile["event_types"][ev["event_type"]] += 1
            if ev.get("mitre_tactic"):
                profile["tactics_seen"][ev["mitre_tactic"]] += 1
            if ev.get("severity"):
                profile["severity_counts"][ev["severity"]] += 1
            profile["total_events"] += 1

            try:
                dt = datetime.fromisoformat(ev["event_time"].replace("Z", "+00:00"))
                day_key = dt.strftime("%Y-%m-%d")
                profile["daily_event_counts"][day_key] += 1
            except:
                pass

            # Track processes
            if ev["event_type"] == "process_create":
                try:
                    p = json.loads(ev.get("payload", "{}"))
                    img = p.get("image", p.get("Image", ""))
                    if img:
                        profile["processes_launched"].append(img.lower())
                except:
                    pass

        # Compute statistical baselines
        for user, data in user_data.items():
            hours = data["login_hours"]
            days = data["login_days"]
            daily_counts = list(data["daily_event_counts"].values())

            self._profiles[user] = {
                "user": user,
                "total_events": data["total_events"],
                "login_count": data["successful_logins"] + data["failed_logins"],
                "fail_ratio": data["failed_logins"] / max(1, data["successful_logins"] + data["failed_logins"]),
                # Time patterns
                "avg_login_hour": sum(hours) / max(1, len(hours)) if hours else 12,
                "std_login_hour": _std(hours) if len(hours) >= 3 else 4.0,
                "common_hours": list(set(hours)),
                "common_days": list(set(days)),
                "off_hours_pct": sum(1 for h in hours if h < 8 or h >= 19) / max(1, len(hours)),
                # Network
                "known_ips": list(data["source_ips"]),
                "ip_count": len(data["source_ips"]),
                "known_hosts": list(data["hostnames"]),
                # Activity
                "event_type_dist": dict(data["event_types"]),
                "daily_avg": sum(daily_counts) / max(1, len(daily_counts)) if daily_counts else 0,
                "daily_std": _std(daily_counts) if len(daily_counts) >= 3 else 10.0,
                "tactics_seen": dict(data["tactics_seen"]),
                "severity_profile": dict(data["severity_counts"]),
                # Process baseline
                "common_processes": _top_n(data["processes_launched"], 20),
                "process_diversity": len(set(data["processes_launched"])),
            }

        log.info(f"AI-UEBA: Built baselines for {len(self._profiles)} users/entities from {days} days of data")
        return len(self._profiles)

    def score_activity(self, user: str, activity: dict) -> dict:
        """
        Score current activity against user's baseline.
        Returns deviation scores for each dimension.
        """
        profile = self._profiles.get(user)
        if not profile:
            return {"user": user, "has_baseline": False, "overall_deviation": 0.5,
                    "note": "No baseline — new or rarely seen user (inherently suspicious)"}

        scores = {}

        # Time deviation
        hour = activity.get("hour")
        if hour is not None:
            avg = profile["avg_login_hour"]
            std = max(profile["std_login_hour"], 1.0)
            time_z = abs(hour - avg) / std
            scores["time_deviation"] = min(time_z / 3.0, 1.0)  # Normalize to 0-1

        # IP deviation
        src_ip = activity.get("source_ip", "")
        if src_ip and src_ip not in ("127.0.0.1", "::1", ""):
            if src_ip in profile["known_ips"]:
                scores["ip_deviation"] = 0.0
            else:
                scores["ip_deviation"] = 0.7 if profile["ip_count"] >= 3 else 0.3

        # Activity volume deviation
        event_count = activity.get("event_count_today", 0)
        if profile["daily_avg"] > 0:
            vol_z = abs(event_count - profile["daily_avg"]) / max(profile["daily_std"], 1.0)
            scores["volume_deviation"] = min(vol_z / 3.0, 1.0)

        # Process deviation
        process = activity.get("process", "").lower()
        if process and profile["common_processes"]:
            if process in profile["common_processes"]:
                scores["process_deviation"] = 0.0
            else:
                scores["process_deviation"] = 0.6

        # Tactic deviation
        tactic = activity.get("mitre_tactic", "")
        if tactic:
            if tactic in profile["tactics_seen"]:
                scores["tactic_deviation"] = 0.1  # Seen before
            else:
                scores["tactic_deviation"] = 0.8  # New tactic for this user

        # Overall deviation (weighted average)
        if scores:
            weights = {
                "time_deviation": 0.2,
                "ip_deviation": 0.25,
                "volume_deviation": 0.15,
                "process_deviation": 0.2,
                "tactic_deviation": 0.2,
            }
            total_w = sum(weights.get(k, 0.15) for k in scores)
            overall = sum(scores.get(k, 0) * weights.get(k, 0.15) for k in scores) / max(total_w, 0.01)
        else:
            overall = 0.5

        return {
            "user": user,
            "has_baseline": True,
            "baseline_events": profile["total_events"],
            "scores": scores,
            "overall_deviation": round(overall, 3),
            "risk_level": "critical" if overall >= 0.75 else "high" if overall >= 0.5 else "medium" if overall >= 0.25 else "low",
        }

    def get_profile(self, user: str) -> dict:
        """Get full baseline profile for a user."""
        return self._profiles.get(user, {"user": user, "has_baseline": False})

    def get_all_profiles(self) -> list:
        """Get all tracked profiles."""
        return list(self._profiles.values())

    def get_peer_group(self, user: str) -> list:
        """
        Find users with similar behavioral profiles (peer group).
        Compares login patterns, IP usage, activity volume.
        """
        target = self._profiles.get(user)
        if not target:
            return []

        peers = []
        for other_user, other in self._profiles.items():
            if other_user == user or other_user.startswith("host:"):
                continue

            similarity = 0.0
            dimensions = 0

            # Compare login hours
            if target["common_hours"] and other["common_hours"]:
                overlap = len(set(target["common_hours"]) & set(other["common_hours"]))
                total = len(set(target["common_hours"]) | set(other["common_hours"]))
                similarity += overlap / max(total, 1)
                dimensions += 1

            # Compare activity volume
            if target["daily_avg"] > 0 and other["daily_avg"] > 0:
                ratio = min(target["daily_avg"], other["daily_avg"]) / max(target["daily_avg"], other["daily_avg"])
                similarity += ratio
                dimensions += 1

            # Compare event type distribution
            t_types = set(target["event_type_dist"].keys())
            o_types = set(other["event_type_dist"].keys())
            if t_types and o_types:
                type_overlap = len(t_types & o_types) / max(len(t_types | o_types), 1)
                similarity += type_overlap
                dimensions += 1

            # Compare host access
            t_hosts = set(target["known_hosts"])
            o_hosts = set(other["known_hosts"])
            if t_hosts and o_hosts:
                host_overlap = len(t_hosts & o_hosts) / max(len(t_hosts | o_hosts), 1)
                similarity += host_overlap
                dimensions += 1

            if dimensions > 0:
                avg_sim = similarity / dimensions
                if avg_sim >= 0.3:  # At least 30% similar
                    peers.append({
                        "user": other_user,
                        "similarity": round(avg_sim, 3),
                        "daily_avg": other["daily_avg"],
                        "login_count": other["login_count"],
                    })

        return sorted(peers, key=lambda p: p["similarity"], reverse=True)[:10]

    def detect_peer_deviation(self, user: str) -> dict:
        """
        Compare user's recent behavior against their peer group.
        Returns whether this user is acting outside their peer norm.
        """
        target = self._profiles.get(user)
        peers = self.get_peer_group(user)

        if not target or not peers:
            return {"user": user, "has_peers": False, "deviation": None}

        # Compare key metrics against peer averages
        peer_avg_daily = sum(p["daily_avg"] for p in peers) / len(peers) if peers else 0
        peer_avg_hours = []
        for pu in peers:
            p = self._profiles.get(pu["user"], {})
            peer_avg_hours.extend(p.get("common_hours", []))

        deviations = {}

        # Volume vs peers
        if peer_avg_daily > 0:
            vol_ratio = target["daily_avg"] / max(peer_avg_daily, 0.1)
            deviations["volume_vs_peers"] = abs(1.0 - vol_ratio)

        # Hours vs peers
        if peer_avg_hours and target["common_hours"]:
            peer_hour_set = set(peer_avg_hours)
            user_unique_hours = set(target["common_hours"]) - peer_hour_set
            deviations["unique_hours"] = len(user_unique_hours) / max(len(target["common_hours"]), 1)

        # IP diversity vs peers
        peer_avg_ips = sum(self._profiles.get(p["user"], {}).get("ip_count", 0) for p in peers) / max(len(peers), 1)
        if peer_avg_ips > 0:
            deviations["ip_diversity_vs_peers"] = abs(target["ip_count"] - peer_avg_ips) / max(peer_avg_ips, 1)

        overall = sum(deviations.values()) / max(len(deviations), 1) if deviations else 0

        return {
            "user": user,
            "has_peers": True,
            "peer_count": len(peers),
            "deviations": deviations,
            "overall_peer_deviation": round(overall, 3),
            "assessment": "anomalous" if overall >= 0.5 else "slightly unusual" if overall >= 0.25 else "normal",
        }

    def _extract_user(self, event: dict) -> str:
        """Extract username from event."""
        try:
            p = json.loads(event.get("payload", "{}"))
        except:
            p = {}

        user = (p.get("user") or p.get("User") or
                p.get("win_event", {}).get("user", "") or
                p.get("auth", {}).get("user", "") or "").lower().strip()

        if user in ("", "system", "local service", "network service", "-"):
            return ""
        return user


# ══════════════════════════════════════════════════════════════════════════════
#  AI-POWERED RISK SCORING
# ══════════════════════════════════════════════════════════════════════════════

async def ai_score_alert(alert: dict, baseline: BehaviorBaseline, call_llm_fn) -> dict:
    """
    Use AI to contextually score a UEBA alert.
    Considers user baseline, peer group, and attack context.
    """
    user = alert.get("user", alert.get("hostname", "unknown"))
    profile = baseline.get_profile(user)
    peer_dev = baseline.detect_peer_deviation(user)

    system = """You are a SOC analyst AI scoring a UEBA behavioral anomaly.
Given the alert details and user's behavioral baseline, assess the risk.
Respond ONLY with JSON:
{
  "ai_risk_score": 0-100,
  "confidence": "high|medium|low",
  "assessment": "1-2 sentence explanation",
  "likely_benign": true/false,
  "recommended_action": "investigate|monitor|escalate|dismiss",
  "reasoning": ["reason1", "reason2"]
}"""

    prompt = f"""Score this behavioral anomaly:

Alert: {alert.get('description', alert.get('ueba_type', 'unknown'))}
User: {user}
Severity: {alert.get('severity', 'medium')}
MITRE: {alert.get('mitre_id', 'none')} — {alert.get('mitre_tactic', '')}

User Baseline (last 30 days):
- Total events: {profile.get('total_events', 0)}
- Login count: {profile.get('login_count', 0)}
- Fail ratio: {profile.get('fail_ratio', 0):.1%}
- Known IPs: {len(profile.get('known_ips', []))}
- Common hours: {profile.get('common_hours', [])}
- Off-hours pct: {profile.get('off_hours_pct', 0):.1%}
- Daily avg events: {profile.get('daily_avg', 0):.1f}

Peer Comparison:
- Peers found: {peer_dev.get('peer_count', 0)}
- Deviation from peers: {peer_dev.get('overall_peer_deviation', 'N/A')}
- Assessment: {peer_dev.get('assessment', 'unknown')}

Score this alert considering the user's normal behavior and peer group. JSON only:"""

    try:
        result = await call_llm_fn(prompt, system, max_tokens=400, task="analyze")
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

        if parsed.get("ai_risk_score") is not None:
            return {
                "alert_type": alert.get("ueba_type", "unknown"),
                "user": user,
                "original_score": alert.get("risk_score", 50),
                "ai_score": parsed["ai_risk_score"],
                "confidence": parsed.get("confidence", "medium"),
                "assessment": parsed.get("assessment", ""),
                "likely_benign": parsed.get("likely_benign", False),
                "action": parsed.get("recommended_action", "investigate"),
                "reasoning": parsed.get("reasoning", []),
            }
    except Exception as e:
        log.error(f"AI risk scoring failed: {e}")

    return {
        "alert_type": alert.get("ueba_type", "unknown"),
        "user": user,
        "original_score": alert.get("risk_score", 50),
        "ai_score": alert.get("risk_score", 50),
        "confidence": "low",
        "assessment": "AI scoring unavailable — using rule-based score",
        "action": "investigate",
    }


# ══════════════════════════════════════════════════════════════════════════════
#  USER INVESTIGATION ASSISTANT
# ══════════════════════════════════════════════════════════════════════════════

async def investigate_user(db_path: str, username: str, baseline: BehaviorBaseline, call_llm_fn) -> dict:
    """
    AI-powered user investigation: "Is this user compromised?"
    Gathers all behavioral context and asks AI for a verdict.
    """
    profile = baseline.get_profile(username)
    peer_dev = baseline.detect_peer_deviation(username)
    peers = baseline.get_peer_group(username)

    # Gather recent events for this user
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row

        # Recent suspicious events
        cur = await db.execute("""
            SELECT event_type, hostname, severity, risk_score, source_ip,
                   mitre_id, mitre_tactic, rule_name, event_time
            FROM events
            WHERE is_suspicious=1 AND payload LIKE ?
            ORDER BY event_time DESC LIMIT 20
        """, (f'%"{username}"%',))
        suspicious = [dict(r) for r in await cur.fetchall()]

        # Recent UEBA alerts
        cur = await db.execute("""
            SELECT event_type, severity, risk_score, rule_name, event_time, payload
            FROM events
            WHERE rule_id LIKE 'UEBA%' AND payload LIKE ?
            ORDER BY event_time DESC LIMIT 10
        """, (f'%"{username}"%',))
        ueba_alerts = [dict(r) for r in await cur.fetchall()]

        # Auth history
        cur = await db.execute("""
            SELECT event_type, source_ip, event_time, hostname
            FROM events
            WHERE event_type IN ('auth_success','auth_failure')
            AND payload LIKE ?
            ORDER BY event_time DESC LIMIT 30
        """, (f'%"{username}"%',))
        auth_history = [dict(r) for r in await cur.fetchall()]

    # Build investigation context
    auth_summary = defaultdict(int)
    recent_ips = set()
    for a in auth_history:
        auth_summary[a["event_type"]] += 1
        if a.get("source_ip"):
            recent_ips.add(a["source_ip"])

    system = """You are a senior SOC analyst investigating whether a user account is compromised.
Analyze ALL the behavioral data and provide a thorough assessment.

Respond ONLY with JSON:
{
  "verdict": "likely_compromised|suspicious|likely_legitimate|insufficient_data",
  "confidence": "high|medium|low",
  "risk_score": 0-100,
  "summary": "2-3 sentence executive summary",
  "indicators": ["indicator1", "indicator2", "indicator3"],
  "benign_explanations": ["possible benign explanation"],
  "timeline": "brief narrative of what happened",
  "recommended_actions": ["action1", "action2", "action3"],
  "escalate": true/false
}"""

    susp_lines = []
    for s in suspicious[:10]:
        susp_lines.append(f"[{s['severity'].upper()}] {s['event_type']} on {s['hostname']} "
                         f"from {s.get('source_ip','-')} [{s.get('mitre_id','')}] "
                         f"— {s.get('rule_name','')[:50]}")

    ueba_lines = []
    for u in ueba_alerts[:5]:
        ueba_lines.append(f"[{u['severity']}] {u.get('rule_name','')} (score: {u['risk_score']})")

    prompt = f"""Investigate user: {username}

BEHAVIORAL BASELINE (30 days):
- Total events: {profile.get('total_events', 0)}
- Login count: {profile.get('login_count', 0)}
- Fail ratio: {profile.get('fail_ratio', 0):.1%}
- Known IPs: {profile.get('known_ips', [])}
- Common login hours: {profile.get('common_hours', [])}
- Off-hours activity: {profile.get('off_hours_pct', 0):.1%}
- Daily avg: {profile.get('daily_avg', 0):.1f} events
- Common processes: {profile.get('common_processes', [])[:10]}

PEER GROUP ANALYSIS:
- Similar users found: {peer_dev.get('peer_count', 0)}
- Deviation from peers: {peer_dev.get('overall_peer_deviation', 'N/A')}
- Peer assessment: {peer_dev.get('assessment', 'unknown')}

RECENT AUTH ({len(auth_history)} events):
- Successes: {auth_summary.get('auth_success',0)}, Failures: {auth_summary.get('auth_failure',0)}
- Recent IPs: {', '.join(list(recent_ips)[:5])}

SUSPICIOUS EVENTS ({len(suspicious)} total):
{chr(10).join(susp_lines) or 'None'}

UEBA ALERTS:
{chr(10).join(ueba_lines) or 'None'}

Is this user compromised? Provide your full assessment as JSON:"""

    try:
        result = await call_llm_fn(prompt, system, max_tokens=800, task="analyze")
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

        if not parsed.get("verdict"):
            parsed = {
                "verdict": "insufficient_data",
                "summary": result[:300],
                "risk_score": 50,
                "confidence": "low",
                "recommended_actions": ["Manual review needed"],
            }

        return {
            "username": username,
            "investigation": parsed,
            "baseline": {
                "total_events": profile.get("total_events", 0),
                "login_count": profile.get("login_count", 0),
                "fail_ratio": profile.get("fail_ratio", 0),
                "known_ips": profile.get("known_ips", []),
                "daily_avg": profile.get("daily_avg", 0),
            },
            "peer_analysis": peer_dev,
            "recent_alerts": len(suspicious),
            "ueba_alerts": len(ueba_alerts),
        }

    except Exception as e:
        log.error(f"User investigation failed: {e}")
        return {"username": username, "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _std(values: list) -> float:
    """Standard deviation."""
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


def _top_n(items: list, n: int = 10) -> list:
    """Most common items."""
    counts = defaultdict(int)
    for item in items:
        counts[item] += 1
    return [k for k, v in sorted(counts.items(), key=lambda x: -x[1])[:n]]


# ══════════════════════════════════════════════════════════════════════════════
#  SINGLETON
# ══════════════════════════════════════════════════════════════════════════════

_baseline = BehaviorBaseline()

def get_baseline() -> BehaviorBaseline:
    return _baseline
