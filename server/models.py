"""Pydantic models for Cibervault EDR Server."""

from typing import Optional, Any
from pydantic import BaseModel


# ─── Enrollment ───────────────────────────────────────────────────────────────

class EnrollRequest(BaseModel):
    hostname:         str
    os:               str
    ip_address:       str
    os_version:       Optional[str] = ""
    arch:             Optional[str] = ""
    agent_version:    Optional[str] = "1.0"
    group:            Optional[str] = "default"
    agent_secret:     Optional[str] = None
    enrollment_token: Optional[str] = None

class EnrollResponse(BaseModel):
    agent_id:    str
    token:       str
    server_time: str


# ─── Event ingestion ──────────────────────────────────────────────────────────

class EventBatch(BaseModel):
    agent_id:       str
    schema_version: str = "1.0"
    events:         list[dict[str, Any]]


# ─── Heartbeat ────────────────────────────────────────────────────────────────

class HeartbeatPayload(BaseModel):
    agent_id:      str
    agent_version: str
    uptime_secs:   int = 0
    cpu_pct:       float = 0.0
    mem_pct:       float = 0.0
    disk_pct:      float = 0.0
    events_queued: int = 0
    status:        str = "ok"


# ─── Commands ─────────────────────────────────────────────────────────────────

class CommandPollResponse(BaseModel):
    commands: list[dict[str, Any]]

class CommandResult(BaseModel):
    command_id: str
    agent_id:   Optional[str] = None
    outcome:    Optional[str] = "success"
    result:     Optional[dict[str, Any]] = {}   # agent sends {output, error, exit_code}
    details:    Optional[dict[str, Any]] = {}   # alternate field name

class IssueCommand(BaseModel):
    agent_id:     str
    command_type: str            # "kill_process" | "isolate_host" | "collect_file" | ...
    parameters:   Optional[dict[str, Any]] = {}
    issued_by:    Optional[str] = "dashboard"


# ─── Dashboard ────────────────────────────────────────────────────────────────

class DashboardEvent(BaseModel):
    event_id:     str
    agent_id:     str
    event_type:   str
    event_time:   str
    hostname:     str
    payload:      str
    is_suspicious: bool
    severity:     str

class AgentStatus(BaseModel):
    agent_id:      str
    hostname:      str
    os:            str
    ip_address:    str
    agent_version: str
    last_seen:     str
    status:        str
    cpu_pct:       float
    mem_pct:       float
    disk_pct:      float


# ─── SMTP Configuration ───────────────────────────────────────────────────────

class SmtpConfigModel(BaseModel):
    host:            str
    port:            int = 587
    username:        Optional[str] = ""
    password:        Optional[str] = ""
    from_addr:       str
    from_name:       str = "Cibervault EDR"
    use_tls:         bool = False
    use_starttls:    bool = True
    recipients:      list[str] = []
    enabled:         bool = True
    notify_critical: bool = True
    notify_high:     bool = True
    notify_medium:   bool = False


# ─── False Positive Exclusion ─────────────────────────────────────────────────

class FpExclusionModel(BaseModel):
    name:             str
    description:      Optional[str] = ""
    hostname:         Optional[str] = None
    process_name:     Optional[str] = None
    cmdline_contains: Optional[str] = None
    event_type:       Optional[str] = None
    source_event_id:  Optional[str] = None
    created_by:       Optional[str] = "analyst"


class FpVerdictModel(BaseModel):
    verdict:          str
    marked_by:        Optional[str] = "analyst"
    create_exclusion: bool = False
    scope:            str = "global"
    match_process:    bool = True
    match_event_type: bool = False
    cmdline_pattern:  Optional[str] = None


# ─── Auth ─────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class CreateUserRequest(BaseModel):
    username:  str
    email:     str
    password:  str
    role:      str = "viewer"
    full_name: Optional[str] = ""

class UpdateUserRequest(BaseModel):
    email:     Optional[str] = None
    role:      Optional[str] = None
    full_name: Optional[str] = None
    active:    Optional[int] = None
    password:  Optional[str] = None
