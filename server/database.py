"""SQLite database setup for Cibervault EDR Server."""

import aiosqlite
import os

DB = "/opt/cibervault/data/cibervault.db"


async def init_db():
    """Create all tables if they don't exist."""
    import os
    os.makedirs(os.path.dirname(DB), exist_ok=True)

    async with aiosqlite.connect(DB) as db:
        await db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;

            -- Users (dashboard auth)
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE,
                email         TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'viewer',
                full_name     TEXT,
                active        INTEGER DEFAULT 1,
                created_at    TEXT NOT NULL,
                last_login    TEXT
            );

            -- Enrolled agents
            CREATE TABLE IF NOT EXISTS agents (
                agent_id      TEXT PRIMARY KEY,
                hostname      TEXT NOT NULL,
                os            TEXT NOT NULL,
                os_version    TEXT,
                ip_address    TEXT,
                arch          TEXT,
                agent_version TEXT,
                group_name    TEXT DEFAULT 'default',
                enrolled_at   TEXT NOT NULL,
                last_seen     TEXT NOT NULL,
                status        TEXT DEFAULT 'offline',
                cpu_pct       REAL DEFAULT 0,
                mem_pct       REAL DEFAULT 0,
                disk_pct      REAL DEFAULT 0
            );

            -- Telemetry events
            CREATE TABLE IF NOT EXISTS events (
                event_id        TEXT PRIMARY KEY,
                agent_id        TEXT NOT NULL,
                event_type      TEXT NOT NULL,
                event_time      TEXT NOT NULL,
                hostname        TEXT,
                payload         TEXT NOT NULL,
                is_suspicious   INTEGER DEFAULT 0,
                severity        TEXT DEFAULT 'info',
                risk_score      REAL DEFAULT 0,
                score_breakdown TEXT,        -- JSON breakdown dict
                is_fp           INTEGER DEFAULT 0,
                fp_verdict      TEXT,        -- "true_positive"|"false_positive"|"benign"
                fp_marked_by    TEXT,
                fp_marked_at    TEXT,
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                mitre_id        TEXT,
                mitre_tactic    TEXT,
                rule_id         TEXT,
                rule_name       TEXT,
                win_event_id    INTEGER,
                source_ip       TEXT,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            );

            -- Response commands
            CREATE TABLE IF NOT EXISTS commands (
                command_id   TEXT PRIMARY KEY,
                agent_id     TEXT NOT NULL,
                command_type TEXT NOT NULL,
                parameters   TEXT,             -- JSON
                issued_by    TEXT,
                status       TEXT DEFAULT 'pending',  -- pending|delivered|completed|failed|expired
                result       TEXT,             -- JSON result from agent
                created_at   TEXT NOT NULL,
                expires_at   TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            );

            -- Audit log (immutable)


            CREATE TABLE IF NOT EXISTS vt_cache (
                hash        TEXT PRIMARY KEY,
                result      TEXT,
                scanned_at  TEXT
            );

            CREATE TABLE IF NOT EXISTS settings (
                key         TEXT PRIMARY KEY,
                value       TEXT,
                updated_at  TEXT
            );

            CREATE TABLE IF NOT EXISTS ueba_baselines (
                user_id     TEXT PRIMARY KEY,
                profile     TEXT,
                updated_at  TEXT
            );

            CREATE TABLE IF NOT EXISTS detection_rules (
                rule_id      TEXT PRIMARY KEY,
                name         TEXT NOT NULL,
                description  TEXT,
                event_types  TEXT,          -- JSON list
                severity     TEXT DEFAULT 'medium',
                mitre_id     TEXT,
                mitre_tactic TEXT,
                base_score   INTEGER DEFAULT 50,
                match_field  TEXT,
                match_pattern TEXT,
                enabled      INTEGER DEFAULT 1,
                is_override  INTEGER DEFAULT 0,  -- 1 = builtin override
                created_by   TEXT,
                created_at   TEXT,
                hit_count    INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                actor       TEXT NOT NULL,
                action      TEXT NOT NULL,
                target      TEXT,
                outcome     TEXT DEFAULT 'success',
                ip_address  TEXT,
                detail      TEXT,
                created_at  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(created_at DESC);

            -- Add scoring columns to events (may already exist on re-run)
            -- These are added via ALTER TABLE if not present

            -- SMTP configuration (single row)
            CREATE TABLE IF NOT EXISTS smtp_config (
                id           INTEGER PRIMARY KEY,
                host         TEXT NOT NULL,
                port         INTEGER DEFAULT 587,
                username     TEXT,
                password     TEXT,
                from_addr    TEXT NOT NULL,
                from_name    TEXT DEFAULT 'Cibervault EDR',
                use_tls      INTEGER DEFAULT 0,
                use_starttls INTEGER DEFAULT 1,
                recipients   TEXT,   -- JSON array of email strings
                enabled      INTEGER DEFAULT 1,
                notify_critical INTEGER DEFAULT 1,
                notify_high     INTEGER DEFAULT 1,
                notify_medium   INTEGER DEFAULT 0,
                updated_at   TEXT NOT NULL
            );

            -- False positive exclusions (analyst feedback → suppression rules)
            CREATE TABLE IF NOT EXISTS fp_exclusions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT NOT NULL,
                description     TEXT,
                hostname        TEXT,       -- match on hostname (partial)
                process_name    TEXT,       -- match on process name (partial)
                cmdline_contains TEXT,      -- match on cmdline substring
                event_type      TEXT,       -- match on specific event type
                source_event_id TEXT,       -- original event that was marked FP
                active          INTEGER DEFAULT 1,
                created_by      TEXT DEFAULT 'analyst',
                created_at      TEXT NOT NULL,
                match_count     INTEGER DEFAULT 0   -- how many times this rule has suppressed
            );

            -- Indexes
            CREATE INDEX IF NOT EXISTS idx_events_agent    ON events(agent_id);
            CREATE INDEX IF NOT EXISTS idx_events_time     ON events(event_time DESC);
            CREATE INDEX IF NOT EXISTS idx_events_susp     ON events(is_suspicious, severity);
            CREATE INDEX IF NOT EXISTS idx_events_hostname ON events(hostname);
            CREATE INDEX IF NOT EXISTS idx_commands_agent  ON commands(agent_id, status);
            CREATE INDEX IF NOT EXISTS idx_fp_active       ON fp_exclusions(active);
        """)
        await db.commit()
