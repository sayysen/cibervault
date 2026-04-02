"""
Cibervault Syslog Receiver
Listens on UDP/TCP 514 for syslog from:
- Firewalls (pfSense, FortiGate, Cisco ASA)
- Switches/routers
- Network appliances
- Linux servers (rsyslog/syslog-ng forward)
"""
import asyncio
import json
import logging
import re
import uuid
from datetime import datetime, timezone

log = logging.getLogger("syslog")

# Common syslog facility/severity names
FACILITIES = {0:"kern",1:"user",2:"mail",3:"daemon",4:"auth",5:"syslog",
              6:"lpr",7:"news",8:"uucp",9:"cron",10:"authpriv",16:"local0",
              17:"local1",18:"local2",19:"local3",20:"local4",21:"local5",22:"local6",23:"local7"}
SEVERITIES = {0:"emerg",1:"alert",2:"crit",3:"err",4:"warning",5:"notice",6:"info",7:"debug"}

# Severity to risk score
SEV_SCORE = {"emerg":95,"alert":85,"crit":75,"err":60,"warning":40,"notice":20,"info":5,"debug":0}
SEV_MAP   = {"emerg":"critical","alert":"critical","crit":"critical","err":"high",
             "warning":"medium","notice":"low","info":"info","debug":"info"}

# Patterns for threat detection in syslog
SYSLOG_PATTERNS = [
    (r"authentication failure|failed password|invalid user|connection refused",  "T1110", True,  "auth_failure"),
    (r"accepted password|accepted publickey|session opened for user",            "T1078", False, "auth_success"),
    (r"sudo.*(command not allowed|incorrect password|authentication failure)",   "T1548", True,  "sudo_violation"),
    (r"kernel.*oom.kill|out of memory",                                          "",      True,  "oom_kill"),
    (r"segfault|general protection fault|kernel bug",                            "",      True,  "kernel_error"),
    (r"firewall.*block|iptables.*drop|denied.*connection",                       "T1071", True,  "firewall_block"),
    (r"port scan|nmap|masscan|scanning",                                         "T1046", True,  "port_scan"),
    (r"useradd|userdel|usermod|groupadd|passwd",                                "T1136", True,  "user_modify"),
    (r"su\[|sudo\[",                                                             "T1548", False, "privilege_use"),
    (r"cron.*CMD|crontab",                                                       "T1053", False, "cron_exec"),
    (r"rkhunter|chkrootkit.*warning|rootkit",                                   "",      True,  "rootkit_detected"),
    (r"sshd.*error|ssh.*failed|ssh.*invalid",                                   "T1110", True,  "ssh_error"),
]


def parse_syslog(raw: str) -> dict:
    """Parse RFC3164 and RFC5424 syslog messages."""
    raw = raw.strip()
    result = {
        "raw":       raw[:2000],
        "facility":  "unknown",
        "severity":  "info",
        "hostname":  "unknown",
        "program":   "",
        "pid":       "",
        "message":   raw,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Extract priority: <PRI>
    pri_match = re.match(r'^<(\d+)>', raw)
    if pri_match:
        pri = int(pri_match.group(1))
        fac = pri >> 3
        sev = pri & 0x07
        result["facility"] = FACILITIES.get(fac, str(fac))
        result["severity"]  = SEVERITIES.get(sev, "info")
        raw = raw[pri_match.end():]

    # RFC3164: "Jan  1 00:00:00 hostname program[pid]: message"
    rfc3164 = re.match(
        r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:\[]+)(?:\[(\d+)\])?:\s*(.*)',
        raw, re.DOTALL
    )
    if rfc3164:
        result["hostname"] = rfc3164.group(2)
        result["program"]  = rfc3164.group(3).strip()
        result["pid"]      = rfc3164.group(4) or ""
        result["message"]  = rfc3164.group(5)[:1000]
        return result

    # RFC5424: version timestamp hostname appname procid msgid structured message
    rfc5424 = re.match(
        r'^1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+|-)\s*(.*)',
        raw, re.DOTALL
    )
    if rfc5424:
        result["timestamp"] = rfc5424.group(1)
        result["hostname"]  = rfc5424.group(2)
        result["program"]   = rfc5424.group(3)
        result["pid"]       = rfc5424.group(4)
        result["message"]   = rfc5424.group(8)[:1000]
        return result

    # Fallback - treat whole line as message
    result["message"] = raw[:1000]
    return result


def analyze_syslog(parsed: dict) -> tuple:
    """Check parsed syslog for security relevance. Returns (event_type, mitre, is_suspicious, score)."""
    msg = (parsed.get("message","") + " " + parsed.get("raw","")).lower()
    sev = parsed.get("severity","info")
    base_score = SEV_SCORE.get(sev, 5)

    for pattern, mitre, is_susp, etype in SYSLOG_PATTERNS:
        if re.search(pattern, msg, re.IGNORECASE):
            score = max(base_score, 60 if is_susp else 20)
            return etype, mitre, is_susp, score

    # High severity messages are always suspicious
    if sev in ("emerg", "alert", "crit", "err"):
        return "syslog_error", "", True, base_score

    return "syslog", "", False, base_score


def syslog_to_event(raw: str, source_ip: str) -> dict:
    """Convert raw syslog to Cibervault event format."""
    parsed   = parse_syslog(raw)
    etype, mitre, is_susp, score = analyze_syslog(parsed)

    sev = parsed.get("severity","info")
    return {
        "event_id":        str(uuid.uuid4()),
        "event_type":      etype,
        "event_time":      parsed["timestamp"],
        "host":            {"hostname": parsed["hostname"] or source_ip},
        "source_ip":       source_ip,
        "syslog": {
            "facility":  parsed["facility"],
            "severity":  sev,
            "program":   parsed["program"],
            "pid":       parsed["pid"],
            "message":   parsed["message"],
            "hostname":  parsed["hostname"],
        },
        "mitre_technique": mitre,
        "mitre_tactic":    "",
        "is_suspicious":   is_susp,
        "risk_score":      score,
        "severity":        SEV_MAP.get(sev, "info"),
    }


class SyslogProtocol(asyncio.DatagramProtocol):
    """UDP syslog receiver."""
    def __init__(self, callback):
        self.callback = callback

    def datagram_received(self, data, addr):
        try:
            raw = data.decode("utf-8", errors="ignore")
            self.callback(raw, addr[0])
        except Exception as e:
            log.debug(f"Syslog UDP error: {e}")


async def start_syslog_server(callback, host="0.0.0.0", port=514):
    """Start UDP and TCP syslog listeners."""
    loop = asyncio.get_event_loop()

    # UDP listener
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: SyslogProtocol(callback),
            local_addr=(host, port)
        )
        log.info(f"Syslog UDP listener: {host}:{port}")
    except PermissionError:
        log.warning(f"Cannot bind to port {port} (need root). Try port 1514.")
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: SyslogProtocol(callback),
                local_addr=(host, 1514)
            )
            log.info(f"Syslog UDP listener (fallback): {host}:1514")
        except Exception as e:
            log.warning(f"Syslog UDP unavailable: {e}")
    except Exception as e:
        log.warning(f"Syslog UDP error: {e}")
