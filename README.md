# Cibervault EDR/SIEM Platform

**Self-hosted Endpoint Detection & Response + Security Information & Event Management platform with AI-powered threat analysis.**

Built from scratch — no commercial dependencies. Runs on a single server, monitors Windows and Linux endpoints, integrates with Wazuh SIEM, and uses local AI (Ollama) for intelligent threat detection.

## Features

### Core Platform
- Real-time Dashboard with Chart.js visualizations, MITRE ATT&CK heatmap
- Incident Management with severity scoring and investigation workflow
- Detection Rules Engine — 15+ built-in MITRE rules + custom rule builder
- Threat Hunting — natural language search across all events

### AI Security Analyst
- Conversational SOC assistant with live SIEM context
- Auto-Triage for critical/high alerts
- AI Rule Generator — describe attacks, get detection rules
- Alert Correlation — groups related alerts into incidents
- Event Analysis — deep-dive with AI explanation

### SOAR (Security Orchestration & Response)
- 5 default auto-response rules (brute force, malware, lateral movement)
- Approval-based blocking, cooldown system, full audit log

### UEBA (User & Entity Behavior Analytics)
- AI behavioral baselines from 30 days of history
- Risk scoring, peer group analysis, login heatmaps
- User investigation with AI verdict

### Entity Resolution
- Maps users across SSH, Wazuh, Windows, sudo into unified identities
- Cross-platform unified timeline
- AI entity investigation

### Intelligence Layer
- Session reconstruction (auth → commands → files)
- Lateral movement detection
- Data exfiltration scoring

### Firewall Management
- Server-side iptables blocking with audit trail
- Fail2ban integration, IP enrichment, auto-expire

### Agents
- **Windows Agent** (C# .NET 8) — Process trees, Sysmon, Network, Auth (Event Log 4624/4625/4648/4720), Defender, File Integrity, Registry monitoring
- **Linux Agent** (Python) — Auth, Process, Network, FIM (437+ files), Sessions, System Inventory
- **Wazuh Integration** — Full JSON preservation, API proxy, unified view

## Architecture
```
Cibervault Server (FastAPI + SQLite + Ollama AI)
├── AI Analyst, SOAR, UEBA, Entity Resolution, Firewall
├── Windows Agent (C# .NET 8) ← endpoints
├── Linux Agent (Python) ← servers
└── Wazuh SIEM ← log collection
```

## Quick Start

### Server
```bash
git clone https://github.com/sayysen/cibervault.git
cd cibervault
sudo bash install.sh
```

### Windows Agent
Download from Dashboard → Settings → Agent Downloads, run INSTALL.bat as Administrator.

### Linux Agent
```bash
cd linux-agent-installer
sudo bash install.sh
# Prompts for: Server URL, Agent Secret
```

### Wazuh Integration
Add to /var/ossec/etc/ossec.conf:
```xml
<integration>
  <name>custom-cibervault</name>
  <hook_url>http://SERVER_IP:8081/api/v1/wazuh/alert</hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

## Tech Stack
- Server: FastAPI, SQLite, nginx, Let's Encrypt
- AI: Ollama (phi3:mini, qwen2.5-coder:7b) or Claude API
- Windows Agent: C# .NET 8
- Linux Agent: Python 3 asyncio
- SIEM: Wazuh + Cibervault
- Dashboard: Single-page HTML/JS, Chart.js

## License
MIT
