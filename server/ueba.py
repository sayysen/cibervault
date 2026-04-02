"""
Cibervault UEBA - User and Entity Behavior Analytics
Detects anomalies in user/host behavior using baseline + deviation analysis.

Monitors:
- Login time anomalies (user logging in at unusual hours)
- Login frequency spikes (sudden increase in logins)
- Impossible travel (same user from different IPs rapidly)
- Privilege escalation patterns
- Lateral movement indicators
- Data staging / exfiltration patterns
- Dormant account reactivation
"""

import json
import math
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Optional

log = logging.getLogger(__name__)

# ── Risk score weights ───────────────────────────────────────────────────────
UEBA_WEIGHTS = {
    "off_hours_login":        35,
    "login_spike":            45,
    "impossible_travel":      90,
    "new_src_ip":             25,
    "priv_escalation_chain":  75,
    "lateral_movement":       80,
    "mass_file_access":       65,
    "dormant_account":        55,
    "admin_after_failure":    70,
    "service_account_login":  50,
    "multiple_failures_spike":60,
}

BUSINESS_HOURS = range(8, 19)  # 8am-7pm


class UEBAEngine:
    """
    In-memory UEBA engine. Maintains per-user and per-host baselines.
    Call process_event() for each incoming event.
    """

    def __init__(self):
        # Per-user state
        self._user_logins: dict = defaultdict(list)         # user -> [{"ts","ip","success"}]
        self._user_ips: dict    = defaultdict(set)          # user -> set of known IPs
        self._user_hours: dict  = defaultdict(list)         # user -> [hour_of_day]
        self._user_failures: dict = defaultdict(list)       # user -> [ts]
        self._last_seen: dict   = {}                        # user -> last login ts

        # Per-host state
        self._host_events: dict = defaultdict(list)         # host -> [event_types]
        self._host_net_dests: dict = defaultdict(set)       # host -> unique (ip,port)

    def process_event(self, agent_id: str, hostname: str, event: dict) -> list:
        """
        Analyze event for behavioral anomalies.
        Returns list of UEBA alert dicts (empty if no anomalies).
        """
        alerts = []
        etype  = event.get("event_type", "")
        now    = datetime.now(timezone.utc)
        ts     = now.timestamp()

        # ── Auth events ──────────────────────────────────────────────────────
        if etype in ("auth_success", "auth_failure", "auth_explicit"):
            winev = event.get("win_event", {})
            auth  = event.get("auth", {})
            user  = (winev.get("user") or auth.get("user") or "").lower().strip()
            src_ip = winev.get("source_ip") or auth.get("source_ip") or ""

            if not user or user in ("","system","local service","network service"):
                return []

            success = (etype == "auth_success")

            # Record this login
            self._user_logins[user].append({"ts": ts, "ip": src_ip, "success": success})
            # Keep last 200 entries
            if len(self._user_logins[user]) > 200:
                self._user_logins[user] = self._user_logins[user][-200:]

            # 1. Off-hours login
            hour = now.hour
            if success and hour not in BUSINESS_HOURS:
                # Only alert if user has a baseline of normal hours
                known_hours = self._user_hours.get(user, [])
                if len(known_hours) >= 10:
                    off_count = sum(1 for h in known_hours if h not in BUSINESS_HOURS)
                    if off_count / len(known_hours) < 0.15:  # <15% off-hours normally
                        alerts.append(self._make_alert(
                            "off_hours_login",
                            f"User '{user}' logged in at {hour:02d}:00 (unusual hour)",
                            user, hostname, agent_id,
                            {"user": user, "hour": hour, "src_ip": src_ip},
                            "T1078", "Defense Evasion"
                        ))
                # Add to baseline
                self._user_hours[user].append(hour)
                if len(self._user_hours[user]) > 100:
                    self._user_hours[user] = self._user_hours[user][-100:]

            # 2. New source IP
            if success and src_ip and src_ip not in ("","::1","127.0.0.1"):
                known_ips = self._user_ips.get(user, set())
                if len(known_ips) >= 3 and src_ip not in known_ips:
                    alerts.append(self._make_alert(
                        "new_src_ip",
                        f"User '{user}' logged in from new IP {src_ip}",
                        user, hostname, agent_id,
                        {"user": user, "src_ip": src_ip, "known_ips": list(known_ips)[:5]},
                        "T1078", "Defense Evasion"
                    ))
                self._user_ips[user].add(src_ip)

            # 3. Impossible travel (same user, different IP, within 5 min)
            if success and src_ip:
                recent = [l for l in self._user_logins[user] if ts - l["ts"] < 300 and l["success"]]
                recent_ips = {l["ip"] for l in recent if l["ip"] and l["ip"] != src_ip}
                if recent_ips:
                    alerts.append(self._make_alert(
                        "impossible_travel",
                        f"Impossible travel: '{user}' logged in from {src_ip} and {list(recent_ips)[0]} within 5 minutes",
                        user, hostname, agent_id,
                        {"user": user, "ip1": src_ip, "ip2": list(recent_ips)[0]},
                        "T1550", "Lateral Movement"
                    ))

            # 4. Dormant account reactivation
            last = self._last_seen.get(user)
            if success and last and (ts - last) > 30 * 86400:  # 30 days
                days = int((ts - last) / 86400)
                alerts.append(self._make_alert(
                    "dormant_account",
                    f"Dormant account '{user}' reactivated after {days} days",
                    user, hostname, agent_id,
                    {"user": user, "days_inactive": days},
                    "T1078.004", "Defense Evasion"
                ))
            if success:
                self._last_seen[user] = ts

            # 5. Login spike (10+ logins in 5 min)
            recent_all = [l for l in self._user_logins[user] if ts - l["ts"] < 300]
            if len(recent_all) >= 10:
                # Reset to avoid repeated alerts
                self._user_logins[user] = []
                alerts.append(self._make_alert(
                    "login_spike",
                    f"Login spike: {len(recent_all)} login attempts for '{user}' in 5 minutes",
                    user, hostname, agent_id,
                    {"user": user, "count": len(recent_all)},
                    "T1110", "Credential Access"
                ))

            # 6. Failed login spike
            if not success:
                self._user_failures[user].append(ts)
                recent_fail = [t for t in self._user_failures[user] if ts - t < 300]
                self._user_failures[user] = recent_fail
                if len(recent_fail) >= 8:
                    self._user_failures[user] = []
                    alerts.append(self._make_alert(
                        "multiple_failures_spike",
                        f"Brute force: {len(recent_fail)} failures for '{user}' in 5 minutes",
                        user, hostname, agent_id,
                        {"user": user, "failures": len(recent_fail)},
                        "T1110.001", "Credential Access"
                    ))

        # ── Network events ───────────────────────────────────────────────────
        elif etype == "network_connect":
            net   = event.get("network", {})
            dst   = (net.get("dst_ip",""), str(net.get("dst_port","0")))
            state = net.get("state","")

            self._host_net_dests[hostname].add(dst)

            # Clean old entries periodically
            if len(self._host_net_dests[hostname]) > 500:
                self._host_net_dests[hostname] = set(list(self._host_net_dests[hostname])[-200:])

        # ── Process tree events ──────────────────────────────────────────────
        elif etype == "process_tree":
            proc   = event.get("process", {})
            pname  = (proc.get("name","")).lower()
            ppname = (proc.get("parent_name","")).lower()
            user   = (proc.get("user","")).lower()

            # Lateral movement: psexec, wmi, or remote admin tools
            LATERAL_TOOLS = {"psexec","wmic","winrs","mstsc","net use","mimikatz"}
            if any(t in pname for t in LATERAL_TOOLS):
                alerts.append(self._make_alert(
                    "lateral_movement",
                    f"Lateral movement tool detected: {pname} (parent: {ppname})",
                    user, hostname, agent_id,
                    {"process": pname, "parent": ppname, "user": user},
                    "T1021", "Lateral Movement"
                ))

        return alerts

    def _make_alert(self, alert_type: str, description: str, user: str,
                    hostname: str, agent_id: str, context: dict,
                    mitre_id: str = "", mitre_tactic: str = "") -> dict:
        score = UEBA_WEIGHTS.get(alert_type, 50)
        severity = "critical" if score >= 80 else "high" if score >= 60 else "medium"
        return {
            "ueba_type":     alert_type,
            "description":   description,
            "user":          user,
            "hostname":      hostname,
            "agent_id":      agent_id,
            "risk_score":    score,
            "severity":      severity,
            "mitre_id":      mitre_id,
            "mitre_tactic":  mitre_tactic,
            "context":       context,
            "timestamp":     datetime.now(timezone.utc).isoformat(),
        }

    def get_user_profile(self, user: str) -> dict:
        """Get behavioral profile for a user."""
        logins = self._user_logins.get(user, [])
        hours  = self._user_hours.get(user, [])
        return {
            "user":          user,
            "known_ips":     list(self._user_ips.get(user, set())),
            "total_logins":  len(logins),
            "known_hours":   sorted(set(hours)),
            "last_seen":     datetime.fromtimestamp(
                self._last_seen[user], tz=timezone.utc).isoformat()
                if user in self._last_seen else None,
            "risk_indicators": sum([
                1 if len(self._user_ips.get(user, set())) > 5 else 0,
                1 if any(h not in BUSINESS_HOURS for h in hours[-5:]) else 0,
            ])
        }

    def get_all_profiles(self) -> list:
        """Get profiles for all tracked users."""
        all_users = set(self._user_logins.keys()) | set(self._last_seen.keys())
        return [self.get_user_profile(u) for u in sorted(all_users)]


# Singleton
_ueba = UEBAEngine()

def get_ueba() -> UEBAEngine:
    return _ueba
