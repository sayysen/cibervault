#!/usr/bin/env python3
"""
Cibervault Linux Agent v2 — Full Telemetry Collector

Collects and sends structured security telemetry to the Cibervault server:
  1. Auth Monitor     — SSH, sudo, su, PAM from /var/log/auth.log
  2. Process Monitor  — New processes via auditd or /proc polling
  3. Network Monitor  — Active connections, listeners, outbound traffic
  4. File Integrity   — inotify on sensitive paths, SHA256 change detection
  5. Session Monitor  — Active SSH/TTY sessions, duration, idle time
  6. System Inventory — OS, packages, users, cron jobs (periodic)

Runs as systemd service: cibervault-agent.service
"""

import asyncio
import hashlib
import json
import logging
import os
import platform
import pwd
import re
import signal
import socket
import subprocess
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

# Optional imports
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    import inotify.adapters
    HAS_INOTIFY = True
except ImportError:
    HAS_INOTIFY = False

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════════════════════

VERSION = "2.0-linux"
CONFIG_DIR = "/opt/cibervault"
CONFIG_FILE = f"{CONFIG_DIR}/agent.conf"
STATE_FILE = f"{CONFIG_DIR}/data/linux-agent-state.json"
LOG_FILE = f"{CONFIG_DIR}/logs/linux-agent.log"

# Defaults — overridden by config file
SERVER_URL = "http://127.0.0.1:8081"
AGENT_SECRET = ""
AGENT_ID = ""
AGENT_TOKEN = ""
HOSTNAME = socket.gethostname()

# Intervals (seconds)
AUTH_POLL_SEC = 2           # Auth log check interval
PROC_POLL_SEC = 10          # Process scan interval
NET_POLL_SEC = 30           # Network connection scan
SESSION_POLL_SEC = 15       # Active session check
HEARTBEAT_SEC = 10          # Heartbeat to server
INVENTORY_SEC = 3600        # System inventory (hourly)
FIM_BASELINE_SEC = 300      # File integrity re-baseline
EVENT_BATCH_SEC = 5         # Batch send interval
EVENT_BATCH_SIZE = 50       # Max events per batch

# Sensitive paths for FIM
FIM_WATCH_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers",
    "/etc/ssh/sshd_config", "/etc/ssh/ssh_config",
    "/etc/crontab", "/etc/hosts", "/etc/resolv.conf",
    "/etc/pam.d/", "/etc/security/",
    "/root/.ssh/", "/root/.bashrc", "/root/.bash_history",
    "/var/spool/cron/",
    "/etc/systemd/system/",
    "/etc/ld.so.preload",
    "/usr/lib/systemd/system/",
]

# Suspicious process patterns
SUSPICIOUS_CMDS = [
    r"nc\s+-.*-e", r"ncat.*-e", r"socat.*exec",       # Reverse shells
    r"bash\s+-i\s+>&\s+/dev/tcp", r"python.*pty\.spawn", # More rev shells
    r"curl.*\|\s*bash", r"wget.*\|\s*bash",             # Download & exec
    r"base64\s+-d", r"python.*-c.*import",               # Encoded commands
    r"nmap\s", r"masscan\s", r"nikto",                   # Scanning
    r"mimipenguin", r"linpeas", r"linenum",              # Post-exploit tools
    r"chisel", r"ligolo", r"frp",                        # Tunneling
    r"cryptominer|xmrig|minerd",                         # Crypto miners
    r"/tmp/\.\w+", r"/dev/shm/\.\w+",                   # Hidden in tmp/shm
    r"chmod\s+[47]777", r"chmod\s+\+s",                  # Dangerous perms
    r"iptables\s+-F", r"iptables\s+-X",                  # Firewall flush
    r"history\s+-c", r"unset\s+HISTFILE",                # Anti-forensics
    r"rm\s+-rf\s+/var/log",                              # Log deletion
    r"useradd\s+", r"usermod.*-aG.*sudo",                # User creation/escalation
    r"crontab\s+-", r"at\s+",                            # Scheduled tasks
    r"tcpdump\s+-", r"tshark\s+",                        # Packet capture
    r"sshpass\s+", r"hydra\s+", r"medusa\s+",            # Brute force tools
]

# ══════════════════════════════════════════════════════════════════════════════
#  LOGGING
# ══════════════════════════════════════════════════════════════════════════════

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ]
)
log = logging.getLogger("cibervault-agent")

# ══════════════════════════════════════════════════════════════════════════════
#  EVENT QUEUE
# ══════════════════════════════════════════════════════════════════════════════

_event_queue = asyncio.Queue() if hasattr(asyncio, 'Queue') else None
_running = True


def queue_event(event_type: str, data: dict, severity: str = "info",
                risk_score: int = 0, mitre_id: str = "", mitre_tactic: str = "",
                source_ip: str = "", user: str = "", is_suspicious: bool = False):
    """Queue a telemetry event for batch sending."""
    event = {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "event_time": datetime.now(timezone.utc).isoformat(),
        "hostname": HOSTNAME,
        "severity": severity,
        "risk_score": risk_score,
        "is_suspicious": is_suspicious,
        "mitre_id": mitre_id,
        "mitre_tactic": mitre_tactic,
        "source_ip": source_ip,
        "description": data.get("description", ""),
        "payload": data,
    }
    if user:
        event["payload"]["user"] = user

    try:
        _event_queue.put_nowait(event)
    except:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  1. AUTH MONITOR — /var/log/auth.log
# ══════════════════════════════════════════════════════════════════════════════

class AuthMonitor:
    """Tails /var/log/auth.log for security events."""

    AUTH_LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"]

    # Patterns: (regex, event_type, severity_fn, mitre_id, mitre_tactic, is_suspicious)
    PATTERNS = [
        # SSH
        (r"sshd\[\d+\]: Accepted (\w+) for (\S+) from (\S+) port (\d+)",
         "auth_success", "medium", "T1078", "Initial Access", False),
        (r"sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)",
         "auth_failure", "high", "T1110", "Credential Access", True),
        (r"sshd\[\d+\]: Invalid user (\S+) from (\S+)",
         "auth_failure", "high", "T1110.001", "Credential Access", True),
        (r"sshd\[\d+\]: Connection closed by authenticating user (\S+) (\S+)",
         "auth_failure", "medium", "T1110", "Credential Access", False),
        (r"sshd\[\d+\]: Disconnected from authenticating user (\S+) (\S+)",
         "auth_failure", "medium", "T1110", "Credential Access", False),
        # Sudo
        (r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)",
         "sudo_exec", "medium", "T1548.003", "Privilege Escalation", False),
        (r"sudo:\s+(\S+)\s+:.*authentication failure",
         "sudo_failure", "high", "T1548.003", "Privilege Escalation", True),
        # Su
        (r"su\[\d+\]: Successful su for (\S+) by (\S+)",
         "su_success", "medium", "T1548.003", "Privilege Escalation", False),
        (r"su\[\d+\]: FAILED su for (\S+) by (\S+)",
         "su_failure", "high", "T1548.003", "Privilege Escalation", True),
        # PAM
        (r"pam_unix\((\S+):auth\): authentication failure.*user=(\S+)",
         "pam_failure", "high", "T1110", "Credential Access", True),
        # User management
        (r"useradd\[\d+\]: new user: name=(\S+)",
         "user_created", "high", "T1136.001", "Persistence", True),
        (r"usermod\[\d+\]: change user '(\S+)'",
         "user_modified", "medium", "T1098", "Persistence", True),
        (r"userdel\[\d+\]: delete user '(\S+)'",
         "user_deleted", "high", "T1531", "Impact", True),
        (r"passwd\[\d+\]: pam_unix.*password changed for (\S+)",
         "password_changed", "medium", "T1098", "Persistence", False),
        # Group changes
        (r"usermod\[\d+\]: add '(\S+)' to group '(\S+)'",
         "group_add", "high", "T1098", "Persistence", True),
    ]

    def __init__(self):
        self._log_path = None
        self._file = None
        self._inode = 0
        self._pos = 0
        self._fail_tracker = defaultdict(list)  # ip -> [timestamps]

        # Find auth log
        for path in self.AUTH_LOG_PATHS:
            if os.path.exists(path):
                self._log_path = path
                break

    async def start(self):
        if not self._log_path:
            log.warning("No auth log found — auth monitoring disabled")
            return

        # Seek to end (only process new events)
        try:
            stat = os.stat(self._log_path)
            self._inode = stat.st_ino
            self._file = open(self._log_path, 'r')
            self._file.seek(0, 2)  # End of file
            self._pos = self._file.tell()
            log.info(f"Auth monitor watching {self._log_path}")
        except Exception as e:
            log.error(f"Cannot open auth log: {e}")
            return

        while _running:
            try:
                await self._poll()
            except Exception as e:
                log.error(f"Auth monitor error: {e}")
                await self._reopen()
            await asyncio.sleep(AUTH_POLL_SEC)

    async def _poll(self):
        # Check for log rotation
        try:
            stat = os.stat(self._log_path)
            if stat.st_ino != self._inode:
                await self._reopen()
                return
        except:
            return

        # Read new lines
        lines = self._file.readlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            self._process_line(line)

    async def _reopen(self):
        """Handle log rotation."""
        try:
            if self._file:
                self._file.close()
            stat = os.stat(self._log_path)
            self._inode = stat.st_ino
            self._file = open(self._log_path, 'r')
            log.info("Auth log rotated — reopened")
        except Exception as e:
            log.error(f"Cannot reopen auth log: {e}")

    def _process_line(self, line: str):
        for pattern, etype, severity, mitre_id, mitre_tactic, is_susp in self.PATTERNS:
            m = re.search(pattern, line)
            if not m:
                continue

            groups = m.groups()
            data = {"raw": line[:500], "description": line[:200]}
            src_ip = ""
            user = ""

            if etype == "auth_success":
                method, user, src_ip, port = groups[0], groups[1], groups[2], groups[3]
                data.update({"method": method, "user": user, "source_ip": src_ip, "port": port})
                severity = "low"

            elif etype == "auth_failure":
                if len(groups) >= 3:
                    user, src_ip = groups[0], groups[1]
                elif len(groups) >= 2:
                    user, src_ip = groups[0], groups[1]
                data.update({"user": user, "source_ip": src_ip})

                # Track brute force
                now = time.time()
                self._fail_tracker[src_ip].append(now)
                # Clean old entries (5 min window)
                self._fail_tracker[src_ip] = [t for t in self._fail_tracker[src_ip] if now - t < 300]
                count = len(self._fail_tracker[src_ip])
                if count >= 10:
                    data["brute_force"] = True
                    data["fail_count_5min"] = count
                    data["description"] = f"Brute force: {count} failures from {src_ip} in 5 min"
                    severity = "critical"
                    risk_score = min(95, 50 + count * 2)
                    queue_event("brute_force_detected", data, severity="critical",
                               risk_score=risk_score, mitre_id="T1110",
                               mitre_tactic="Credential Access", source_ip=src_ip,
                               user=user, is_suspicious=True)

            elif etype == "sudo_exec":
                user = groups[0]
                cmd = groups[1] if len(groups) > 1 else ""
                data.update({"user": user, "command": cmd[:500]})
                # Check if command is suspicious
                for pat in SUSPICIOUS_CMDS:
                    if re.search(pat, cmd, re.IGNORECASE):
                        is_susp = True
                        severity = "critical"
                        data["suspicious_reason"] = f"Matched pattern: {pat}"
                        break

            elif etype == "sudo_failure":
                user = groups[0]
                data["user"] = user
                is_susp = True

            elif etype in ("su_success", "su_failure"):
                user = groups[0]
                by_user = groups[1] if len(groups) > 1 else ""
                data.update({"user": user, "by_user": by_user})

            elif etype in ("user_created", "user_modified", "user_deleted", "password_changed"):
                user = groups[0]
                data["user"] = user

            elif etype == "group_add":
                user = groups[0]
                group = groups[1] if len(groups) > 1 else ""
                data.update({"user": user, "group": group})
                if group in ("sudo", "wheel", "root", "admin"):
                    severity = "critical"
                    is_susp = True
                    data["description"] = f"User {user} added to privileged group {group}"

            elif etype == "pam_failure":
                service = groups[0] if len(groups) > 0 else ""
                user = groups[1] if len(groups) > 1 else ""
                data.update({"service": service, "user": user})

            risk = {"critical": 85, "high": 65, "medium": 40, "low": 15, "info": 5}.get(severity, 30)
            queue_event(etype, data, severity=severity, risk_score=risk,
                       mitre_id=mitre_id, mitre_tactic=mitre_tactic,
                       source_ip=src_ip, user=user, is_suspicious=is_susp)
            return  # Only match first pattern


# ══════════════════════════════════════════════════════════════════════════════
#  2. PROCESS MONITOR — /proc + suspicious command detection
# ══════════════════════════════════════════════════════════════════════════════

class ProcessMonitor:
    """Scans /proc for new and suspicious processes."""

    def __init__(self):
        self._known_pids = {}  # pid -> {cmdline, user, ppid, start}
        self._seen_cmds = set()

    async def start(self):
        log.info("Process monitor started")
        # Initial snapshot
        self._snapshot()

        while _running:
            try:
                self._scan()
            except Exception as e:
                log.error(f"Process monitor error: {e}")
            await asyncio.sleep(PROC_POLL_SEC)

    def _snapshot(self):
        """Build initial process table."""
        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue
            pid = int(pid_dir.name)
            info = self._read_proc(pid)
            if info:
                self._known_pids[pid] = info

    def _scan(self):
        """Scan for new processes and detect suspicious ones."""
        current_pids = set()

        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue
            pid = int(pid_dir.name)
            current_pids.add(pid)

            if pid in self._known_pids:
                continue

            # New process!
            info = self._read_proc(pid)
            if not info:
                continue

            self._known_pids[pid] = info
            cmdline = info.get("cmdline", "")

            # Skip kernel threads and very short-lived
            if not cmdline or cmdline.startswith("["):
                continue

            # Deduplicate frequent commands
            cmd_key = f"{info.get('name', '')}:{cmdline[:100]}"
            if cmd_key in self._seen_cmds:
                continue
            self._seen_cmds.add(cmd_key)
            # Trim seen cache
            if len(self._seen_cmds) > 5000:
                self._seen_cmds = set(list(self._seen_cmds)[-2000:])

            # Check for suspicious patterns
            is_suspicious = False
            suspicious_reason = ""
            severity = "info"
            mitre_id = ""
            mitre_tactic = ""

            for pat in SUSPICIOUS_CMDS:
                if re.search(pat, cmdline, re.IGNORECASE):
                    is_suspicious = True
                    suspicious_reason = f"Matched: {pat}"
                    severity = "high"
                    mitre_id = "T1059"
                    mitre_tactic = "Execution"
                    break

            # Check suspicious paths
            exe = info.get("exe", "")
            if any(p in exe.lower() for p in ["/tmp/", "/dev/shm/", "/var/tmp/"]):
                is_suspicious = True
                suspicious_reason = f"Exec from suspicious path: {exe}"
                severity = "high"
                mitre_id = "T1059"
                mitre_tactic = "Execution"

            # Check if running as root from unusual parent
            if info.get("user") == "root" and info.get("ppid_name") not in (
                "systemd", "sshd", "bash", "sh", "sudo", "cron", "init",
                "screen", "tmux", "python3", "python", ""
            ):
                if not cmdline.startswith("["):
                    is_suspicious = True
                    if not suspicious_reason:
                        suspicious_reason = f"Root process from unusual parent: {info.get('ppid_name')}"
                        severity = "medium"

            data = {
                "pid": pid,
                "ppid": info.get("ppid", 0),
                "name": info.get("name", ""),
                "cmdline": cmdline[:1000],
                "exe": exe[:500],
                "user": info.get("user", ""),
                "ppid_name": info.get("ppid_name", ""),
                "cwd": info.get("cwd", ""),
                "description": f"Process: {info.get('name','')} ({cmdline[:100]})",
            }
            if is_suspicious:
                data["suspicious_reason"] = suspicious_reason

            risk = {"critical": 90, "high": 70, "medium": 45, "low": 15, "info": 5}.get(severity, 5)

            if is_suspicious:
                queue_event("process_create", data, severity=severity,
                           risk_score=risk, mitre_id=mitre_id,
                           mitre_tactic=mitre_tactic, user=info.get("user", ""),
                           is_suspicious=True)

        # Clean dead PIDs
        dead = set(self._known_pids.keys()) - current_pids
        for pid in dead:
            del self._known_pids[pid]

    def _read_proc(self, pid: int) -> dict:
        """Read process info from /proc/PID/."""
        try:
            base = f"/proc/{pid}"

            # cmdline
            try:
                cmdline = Path(f"{base}/cmdline").read_text().replace("\x00", " ").strip()
            except:
                cmdline = ""

            # status (name, ppid, uid)
            name = ""
            ppid = 0
            uid = 0
            try:
                for line in Path(f"{base}/status").read_text().splitlines():
                    if line.startswith("Name:"):
                        name = line.split(":", 1)[1].strip()
                    elif line.startswith("PPid:"):
                        ppid = int(line.split(":", 1)[1].strip())
                    elif line.startswith("Uid:"):
                        uid = int(line.split(":", 1)[1].strip().split()[0])
            except:
                pass

            # User from UID
            try:
                user = pwd.getpwuid(uid).pw_name
            except:
                user = str(uid)

            # Exe path
            try:
                exe = os.readlink(f"{base}/exe")
            except:
                exe = ""

            # CWD
            try:
                cwd = os.readlink(f"{base}/cwd")
            except:
                cwd = ""

            # Parent name
            ppid_name = ""
            try:
                ppid_name = Path(f"/proc/{ppid}/comm").read_text().strip()
            except:
                pass

            return {
                "cmdline": cmdline, "name": name, "ppid": ppid,
                "user": user, "exe": exe, "cwd": cwd,
                "ppid_name": ppid_name, "uid": uid,
            }
        except:
            return None


# ══════════════════════════════════════════════════════════════════════════════
#  3. NETWORK MONITOR — ss + connection tracking
# ══════════════════════════════════════════════════════════════════════════════

class NetworkMonitor:
    """Monitors network connections for anomalies."""

    def __init__(self):
        self._known_listeners = set()
        self._known_outbound = set()
        self._connection_counts = defaultdict(int)

    async def start(self):
        log.info("Network monitor started")
        # Initial baseline of listeners
        self._baseline_listeners()

        while _running:
            try:
                self._scan()
            except Exception as e:
                log.error(f"Network monitor error: {e}")
            await asyncio.sleep(NET_POLL_SEC)

    def _baseline_listeners(self):
        """Record current listening ports."""
        listeners = self._get_listeners()
        self._known_listeners = set(listeners.keys())
        log.info(f"Network baseline: {len(self._known_listeners)} listening ports")

    def _scan(self):
        """Scan for new listeners and suspicious outbound."""
        # Check for new listeners
        listeners = self._get_listeners()
        for key, info in listeners.items():
            if key not in self._known_listeners:
                self._known_listeners.add(key)
                data = {
                    "port": info["port"],
                    "process": info["process"],
                    "pid": info["pid"],
                    "protocol": info["proto"],
                    "bind_addr": info["addr"],
                    "description": f"New listener: {info['process']} on {info['proto']}:{info['port']}",
                }
                severity = "high" if info["port"] < 1024 else "medium"
                queue_event("new_listener", data, severity=severity,
                           risk_score=60, mitre_id="T1571",
                           mitre_tactic="Command and Control",
                           is_suspicious=True)

        # Check outbound connections
        outbound = self._get_outbound()
        for conn in outbound:
            dest_key = f"{conn['dest_ip']}:{conn['dest_port']}"

            # Track connection frequency
            self._connection_counts[dest_key] += 1

            # Suspicious: high-port outbound, unusual destinations
            is_suspicious = False
            reason = ""
            if conn["dest_port"] in (4444, 5555, 8888, 9999, 1234, 31337):
                is_suspicious = True
                reason = f"Common backdoor port: {conn['dest_port']}"
            elif conn["dest_port"] > 10000 and conn["process"] not in (
                "sshd", "apt", "dpkg", "python3", "curl", "wget", "ollama"
            ):
                # Unusual high-port outbound
                pass

            if is_suspicious:
                data = {
                    "dest_ip": conn["dest_ip"],
                    "dest_port": conn["dest_port"],
                    "process": conn["process"],
                    "pid": conn["pid"],
                    "source_port": conn["src_port"],
                    "state": conn["state"],
                    "description": f"Suspicious outbound: {conn['process']} → {dest_key} ({reason})",
                    "suspicious_reason": reason,
                }
                queue_event("network_connection", data, severity="high",
                           risk_score=70, mitre_id="T1071",
                           mitre_tactic="Command and Control",
                           source_ip=conn["dest_ip"], is_suspicious=True)

    def _get_listeners(self) -> dict:
        """Get listening ports via ss."""
        result = {}
        try:
            out = subprocess.run(
                ["ss", "-tlnp"], capture_output=True, text=True, timeout=5
            ).stdout
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 6:
                    continue
                addr = parts[3]
                # Parse address:port
                if ":" in addr:
                    port = addr.rsplit(":", 1)[-1]
                    bind = addr.rsplit(":", 1)[0]
                else:
                    continue
                try:
                    port = int(port)
                except:
                    continue
                # Parse process
                proc_match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', parts[-1]) if len(parts) > 5 else None
                proc = proc_match.group(1) if proc_match else ""
                pid = proc_match.group(2) if proc_match else ""
                key = f"{bind}:{port}"
                result[key] = {"port": port, "addr": bind, "process": proc, "pid": pid, "proto": "tcp"}
        except Exception as e:
            log.debug(f"ss listener scan error: {e}")
        return result

    def _get_outbound(self) -> list:
        """Get established outbound connections."""
        connections = []
        try:
            out = subprocess.run(
                ["ss", "-tnp", "state", "established"], capture_output=True, text=True, timeout=5
            ).stdout
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 5:
                    continue
                local = parts[3]
                peer = parts[4]
                # Parse local
                src_port = local.rsplit(":", 1)[-1] if ":" in local else ""
                # Parse peer
                if ":" in peer:
                    dest_ip = peer.rsplit(":", 1)[0].strip("[]")
                    dest_port = peer.rsplit(":", 1)[-1]
                else:
                    continue
                try:
                    dest_port = int(dest_port)
                    src_port = int(src_port)
                except:
                    continue
                # Skip localhost
                if dest_ip in ("127.0.0.1", "::1", "0.0.0.0"):
                    continue
                proc_match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', parts[-1]) if len(parts) > 4 else None
                proc = proc_match.group(1) if proc_match else ""
                pid = proc_match.group(2) if proc_match else ""
                connections.append({
                    "dest_ip": dest_ip, "dest_port": dest_port,
                    "src_port": src_port, "process": proc, "pid": pid,
                    "state": "established",
                })
        except Exception as e:
            log.debug(f"ss outbound scan error: {e}")
        return connections


# ══════════════════════════════════════════════════════════════════════════════
#  4. FILE INTEGRITY MONITOR — SHA256 + inotify
# ══════════════════════════════════════════════════════════════════════════════

class FileIntegrityMonitor:
    """Monitors sensitive files for changes."""

    def __init__(self):
        self._baselines = {}  # path -> {hash, size, mtime, owner, perms}

    async def start(self):
        log.info("File integrity monitor started")
        self._build_baseline()

        while _running:
            try:
                self._check()
            except Exception as e:
                log.error(f"FIM error: {e}")
            await asyncio.sleep(FIM_BASELINE_SEC)

    def _build_baseline(self):
        """Hash all watched files."""
        count = 0
        for path in FIM_WATCH_PATHS:
            if os.path.isdir(path):
                # Watch files in directory
                try:
                    for entry in os.scandir(path):
                        if entry.is_file():
                            info = self._hash_file(entry.path)
                            if info:
                                self._baselines[entry.path] = info
                                count += 1
                except:
                    pass
            elif os.path.isfile(path):
                info = self._hash_file(path)
                if info:
                    self._baselines[path] = info
                    count += 1
        log.info(f"FIM baseline: {count} files tracked")

    def _check(self):
        """Compare current state against baseline."""
        for path, baseline in list(self._baselines.items()):
            if not os.path.exists(path):
                # File deleted!
                data = {
                    "path": path,
                    "action": "deleted",
                    "previous_hash": baseline["hash"],
                    "previous_owner": baseline["owner"],
                    "description": f"Sensitive file deleted: {path}",
                }
                queue_event("file_delete", data, severity="critical",
                           risk_score=85, mitre_id="T1070.004",
                           mitre_tactic="Defense Evasion", is_suspicious=True)
                del self._baselines[path]
                continue

            current = self._hash_file(path)
            if not current:
                continue

            if current["hash"] != baseline["hash"]:
                data = {
                    "path": path,
                    "action": "modified",
                    "previous_hash": baseline["hash"],
                    "current_hash": current["hash"],
                    "previous_size": baseline["size"],
                    "current_size": current["size"],
                    "owner": current["owner"],
                    "permissions": current["perms"],
                    "description": f"Sensitive file modified: {path}",
                }
                severity = "critical" if path in ("/etc/passwd", "/etc/shadow", "/etc/sudoers") else "high"
                queue_event("file_modify", data, severity=severity,
                           risk_score=75, mitre_id="T1222",
                           mitre_tactic="Defense Evasion", is_suspicious=True)
                self._baselines[path] = current

            elif current["perms"] != baseline["perms"]:
                data = {
                    "path": path,
                    "action": "permissions_changed",
                    "previous_perms": baseline["perms"],
                    "current_perms": current["perms"],
                    "description": f"File permissions changed: {path} ({baseline['perms']} → {current['perms']})",
                }
                queue_event("file_modify", data, severity="high",
                           risk_score=65, mitre_id="T1222.002",
                           mitre_tactic="Defense Evasion", is_suspicious=True)
                self._baselines[path] = current

        # Check for new files in watched directories
        for path in FIM_WATCH_PATHS:
            if os.path.isdir(path):
                try:
                    for entry in os.scandir(path):
                        if entry.is_file() and entry.path not in self._baselines:
                            info = self._hash_file(entry.path)
                            if info:
                                self._baselines[entry.path] = info
                                data = {
                                    "path": entry.path,
                                    "action": "created",
                                    "hash": info["hash"],
                                    "owner": info["owner"],
                                    "permissions": info["perms"],
                                    "description": f"New file in sensitive directory: {entry.path}",
                                }
                                queue_event("file_create", data, severity="high",
                                           risk_score=60, mitre_id="T1543",
                                           mitre_tactic="Persistence", is_suspicious=True)
                except:
                    pass

    def _hash_file(self, path: str) -> Optional[dict]:
        """Get file hash and metadata."""
        try:
            stat = os.stat(path)
            # Only hash files under 10MB
            if stat.st_size > 10 * 1024 * 1024:
                h = f"too_large_{stat.st_size}"
            else:
                sha = hashlib.sha256()
                with open(path, 'rb') as f:
                    for chunk in iter(lambda: f.read(8192), b''):
                        sha.update(chunk)
                h = sha.hexdigest()

            try:
                owner = pwd.getpwuid(stat.st_uid).pw_name
            except:
                owner = str(stat.st_uid)

            return {
                "hash": h,
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "owner": owner,
                "perms": oct(stat.st_mode)[-3:],
            }
        except:
            return None


# ══════════════════════════════════════════════════════════════════════════════
#  5. SESSION MONITOR — Active SSH/TTY sessions
# ══════════════════════════════════════════════════════════════════════════════

class SessionMonitor:
    """Tracks active user sessions."""

    def __init__(self):
        self._known_sessions = {}  # key -> session_info

    async def start(self):
        log.info("Session monitor started")
        while _running:
            try:
                self._scan()
            except Exception as e:
                log.error(f"Session monitor error: {e}")
            await asyncio.sleep(SESSION_POLL_SEC)

    def _scan(self):
        """Check active sessions via who/w."""
        sessions = {}
        try:
            out = subprocess.run(["who", "-u"], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) < 5:
                    continue
                user = parts[0]
                tty = parts[1]
                date_str = " ".join(parts[2:4])
                idle = parts[4] if len(parts) > 4 else "."
                src = parts[5].strip("()") if len(parts) > 5 else ""

                key = f"{user}:{tty}"
                sessions[key] = {
                    "user": user, "tty": tty, "login_time": date_str,
                    "idle": idle, "source": src,
                }
        except:
            pass

        # Detect new sessions
        for key, info in sessions.items():
            if key not in self._known_sessions:
                data = {
                    "user": info["user"],
                    "tty": info["tty"],
                    "source": info["source"],
                    "login_time": info["login_time"],
                    "description": f"New session: {info['user']} on {info['tty']}" + (f" from {info['source']}" if info["source"] else ""),
                }
                queue_event("session_start", data, severity="low",
                           risk_score=10, source_ip=info["source"],
                           user=info["user"])

        # Detect ended sessions
        for key, info in self._known_sessions.items():
            if key not in sessions:
                data = {
                    "user": info["user"],
                    "tty": info["tty"],
                    "source": info["source"],
                    "description": f"Session ended: {info['user']} on {info['tty']}",
                }
                queue_event("session_end", data, severity="info",
                           risk_score=5, user=info["user"])

        self._known_sessions = sessions


# ══════════════════════════════════════════════════════════════════════════════
#  6. SYSTEM INVENTORY — Periodic collection
# ══════════════════════════════════════════════════════════════════════════════

class SystemInventory:
    """Collects system inventory periodically."""

    async def start(self):
        log.info("System inventory collector started")
        await asyncio.sleep(10)  # Wait for agent to settle
        while _running:
            try:
                self._collect()
            except Exception as e:
                log.error(f"Inventory error: {e}")
            await asyncio.sleep(INVENTORY_SEC)

    def _collect(self):
        """Collect system information."""
        data = {
            "hostname": HOSTNAME,
            "os": f"{platform.system()} {platform.release()}",
            "kernel": platform.release(),
            "arch": platform.machine(),
            "uptime": self._get_uptime(),
            "users": self._get_users(),
            "cron_jobs": self._get_cron_jobs(),
            "listening_ports": self._get_listeners(),
            "loaded_modules": self._get_modules(),
            "description": f"System inventory for {HOSTNAME}",
        }
        queue_event("inventory", data, severity="info", risk_score=0)

    def _get_uptime(self) -> str:
        try:
            with open("/proc/uptime") as f:
                secs = float(f.read().split()[0])
                days = int(secs // 86400)
                hours = int((secs % 86400) // 3600)
                return f"{days}d {hours}h"
        except:
            return "unknown"

    def _get_users(self) -> list:
        """Get local users with shells."""
        users = []
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        shell = parts[6]
                        if shell not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"):
                            users.append({
                                "name": parts[0],
                                "uid": int(parts[2]),
                                "gid": int(parts[3]),
                                "home": parts[5],
                                "shell": shell,
                            })
        except:
            pass
        return users

    def _get_cron_jobs(self) -> list:
        """Get system and user cron jobs."""
        jobs = []
        # System crontab
        try:
            with open("/etc/crontab") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        jobs.append({"source": "/etc/crontab", "line": line[:200]})
        except:
            pass
        # User crontabs
        cron_dir = "/var/spool/cron/crontabs"
        if os.path.isdir(cron_dir):
            try:
                for entry in os.scandir(cron_dir):
                    if entry.is_file():
                        try:
                            with open(entry.path) as f:
                                for line in f:
                                    line = line.strip()
                                    if line and not line.startswith("#"):
                                        jobs.append({"source": entry.name, "line": line[:200]})
                        except:
                            pass
            except:
                pass
        return jobs

    def _get_listeners(self) -> list:
        try:
            out = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=5).stdout
            return [line.strip() for line in out.splitlines()[1:] if line.strip()]
        except:
            return []

    def _get_modules(self) -> list:
        try:
            out = subprocess.run(["lsmod"], capture_output=True, text=True, timeout=5).stdout
            return [line.split()[0] for line in out.splitlines()[1:]][:50]
        except:
            return []


# ══════════════════════════════════════════════════════════════════════════════
#  EVENT SENDER — Batches events to server API
# ══════════════════════════════════════════════════════════════════════════════

class EventSender:
    """Sends queued events to Cibervault server in batches."""

    def __init__(self):
        self._session = None
        self._consecutive_failures = 0

    async def start(self):
        log.info("Event sender started")
        while _running:
            try:
                await self._send_batch()
            except Exception as e:
                log.error(f"Event sender error: {e}")
                self._consecutive_failures += 1
                if self._consecutive_failures > 10:
                    await asyncio.sleep(30)
            await asyncio.sleep(EVENT_BATCH_SEC)

    async def _send_batch(self):
        if _event_queue.empty():
            return

        batch = []
        while not _event_queue.empty() and len(batch) < EVENT_BATCH_SIZE:
            try:
                event = _event_queue.get_nowait()
                batch.append(event)
            except:
                break

        if not batch:
            return

        url = f"{SERVER_URL}/api/v1/agent/events"
        headers = {
            "Authorization": f"Bearer {AGENT_TOKEN}",
            "Content-Type": "application/json",
        }
        body = {
            "agent_id": AGENT_ID,
            "events": batch,
        }

        try:
            if HAS_AIOHTTP:
                if not self._session:
                    self._session = aiohttp.ClientSession()
                async with self._session.post(url, json=body, headers=headers,
                                              ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        self._consecutive_failures = 0
                        log.debug(f"Sent {len(batch)} events")
                    else:
                        log.warning(f"Event send failed: HTTP {resp.status}")
                        self._consecutive_failures += 1
            else:
                # Fallback to subprocess curl
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                    json.dump(body, f)
                    tmp = f.name
                result = subprocess.run(
                    ["curl", "-s", "-X", "POST", url,
                     "-H", f"Authorization: Bearer {AGENT_TOKEN}",
                     "-H", "Content-Type: application/json",
                     "-d", f"@{tmp}", "--max-time", "10", "-k"],
                    capture_output=True, text=True, timeout=15
                )
                os.unlink(tmp)
                if '"ok":true' in result.stdout or '"ok": true' in result.stdout:
                    self._consecutive_failures = 0
                    log.debug(f"Sent {len(batch)} events (curl)")
                else:
                    log.warning(f"Event send failed: {result.stdout[:200]}")
        except Exception as e:
            log.warning(f"Event send error: {e}")
            # Re-queue events on failure
            for ev in batch:
                try:
                    _event_queue.put_nowait(ev)
                except:
                    break


# ══════════════════════════════════════════════════════════════════════════════
#  HEARTBEAT
# ══════════════════════════════════════════════════════════════════════════════

async def heartbeat_loop():
    """Send periodic heartbeats to server."""
    while _running:
        try:
            url = f"{SERVER_URL}/api/v1/agent/heartbeat"
            body = {
                "agent_id": AGENT_ID,
                "hostname": HOSTNAME,
                "os": f"Linux {platform.release()}",
                "agent_version": VERSION,
                "ip_address": _get_primary_ip(),
                "uptime_secs": _get_uptime_secs(),
                "events_queued": _event_queue.qsize() if _event_queue else 0,
            }
            headers = {
                "Authorization": f"Bearer {AGENT_TOKEN}",
                "Content-Type": "application/json",
            }

            if HAS_AIOHTTP:
                async with aiohttp.ClientSession() as session:
                    async with session.post(url, json=body, headers=headers,
                                           ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200:
                            log.debug("Heartbeat OK")
                        else:
                            log.debug(f"Heartbeat: HTTP {resp.status}")
            else:
                subprocess.run(
                    ["curl", "-s", "-X", "POST", url,
                     "-H", f"Authorization: Bearer {AGENT_TOKEN}",
                     "-H", "Content-Type: application/json",
                     "-d", json.dumps(body), "--max-time", "5", "-k"],
                    capture_output=True, timeout=8
                )
        except Exception as e:
            log.debug(f"Heartbeat error: {e}")
        await asyncio.sleep(HEARTBEAT_SEC)


# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _get_primary_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def _get_uptime_secs() -> int:
    try:
        with open("/proc/uptime") as f:
            return int(float(f.read().split()[0]))
    except:
        return 0


# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG & ENROLLMENT
# ══════════════════════════════════════════════════════════════════════════════

def load_config():
    global SERVER_URL, AGENT_SECRET, AGENT_ID, AGENT_TOKEN
    """Load config from agent.conf and state file."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    k, v = k.strip(), v.strip()
                    if k == "CV_SERVER":
                        SERVER_URL = v
                    elif k == "CV_SECRET":
                        AGENT_SECRET = v

    # Load state (agent_id, token)
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                state = json.load(f)
                AGENT_ID = state.get("agent_id", "")
                AGENT_TOKEN = state.get("token", "")
        except:
            pass


def save_state():
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        json.dump({"agent_id": AGENT_ID, "token": AGENT_TOKEN}, f)


async def enroll():
    global AGENT_ID, AGENT_TOKEN
    """Enroll with the Cibervault server."""
    url = f"{SERVER_URL}/api/v1/agent/enroll"
    body = {
        "hostname": HOSTNAME,
        "os": f"Linux {platform.release()}",
        "arch": platform.machine(),
        "agent_secret": AGENT_SECRET,
        "agent_version": VERSION,
        "ip_address": _get_primary_ip(),
    }

    try:
        if HAS_AIOHTTP:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=body, ssl=False,
                                       timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        AGENT_ID = data.get("agent_id", "")
                        AGENT_TOKEN = data.get("token", "")
                        save_state()
                        log.info(f"Enrolled: agent_id={AGENT_ID}")
                        return True
                    else:
                        text = await resp.text()
                        log.error(f"Enrollment failed: HTTP {resp.status} — {text[:200]}")
        else:
            result = subprocess.run(
                ["curl", "-s", "-X", "POST", url,
                 "-H", "Content-Type: application/json",
                 "-d", json.dumps(body), "--max-time", "10", "-k"],
                capture_output=True, text=True, timeout=15
            )
            data = json.loads(result.stdout)
            AGENT_ID = data.get("agent_id", "")
            AGENT_TOKEN = data.get("token", "")
            save_state()
            log.info(f"Enrolled: agent_id={AGENT_ID}")
            return True
    except Exception as e:
        log.error(f"Enrollment error: {e}")
    return False


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

async def main():
    global _running, _event_queue
    _event_queue = asyncio.Queue(maxsize=10000)

    log.info(f"Cibervault Linux Agent v{VERSION} starting on {HOSTNAME}")
    load_config()

    if not SERVER_URL or not AGENT_SECRET:
        log.error("Missing config. Run: cibervault-linux-agent --setup")
        return

    # Enroll if needed
    if not AGENT_ID or not AGENT_TOKEN:
        log.info("Enrolling with server...")
        for attempt in range(5):
            if await enroll():
                break
            log.warning(f"Enrollment attempt {attempt+1} failed, retrying in 10s...")
            await asyncio.sleep(10)
        if not AGENT_ID:
            log.error("Could not enroll. Check server URL and secret.")
            return

    log.info(f"Agent active: id={AGENT_ID}, server={SERVER_URL}")
    log.info(f"Monitors: auth, process, network, file integrity, sessions, inventory")

    # Signal handler
    def stop(sig, frame):
        global _running
        log.info(f"Signal {sig} received, shutting down...")
        _running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    # Start all monitors
    auth = AuthMonitor()
    proc = ProcessMonitor()
    net = NetworkMonitor()
    fim = FileIntegrityMonitor()
    sess = SessionMonitor()
    inv = SystemInventory()
    sender = EventSender()

    tasks = [
        asyncio.create_task(auth.start()),
        asyncio.create_task(proc.start()),
        asyncio.create_task(net.start()),
        asyncio.create_task(fim.start()),
        asyncio.create_task(sess.start()),
        asyncio.create_task(inv.start()),
        asyncio.create_task(sender.start()),
        asyncio.create_task(heartbeat_loop()),
    ]

    log.info("All monitors running. Collecting telemetry...")

    # Wait until stopped
    while _running:
        await asyncio.sleep(1)

    # Cleanup
    for task in tasks:
        task.cancel()
    log.info("Agent stopped.")


def setup():
    """Interactive setup."""
    print(f"\n  Cibervault Linux Agent v{VERSION} — Setup\n")
    server = input(f"  Server URL [{SERVER_URL}]: ").strip() or SERVER_URL
    secret = input("  Agent Secret: ").strip()
    if not secret:
        print("  Secret is required!")
        return

    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        f.write(f"CV_SERVER={server}\nCV_SECRET={secret}\n")
    print(f"\n  Config saved to {CONFIG_FILE}")
    print(f"  Start with: systemctl start cibervault-agent\n")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--setup", "-s", "setup"):
        setup()
    else:
        asyncio.run(main())
