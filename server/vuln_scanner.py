"""
Cibervault Vulnerability Scanner
- Checks installed software against known CVE database (local subset)
- CIS Benchmark checks (Linux + Windows)
- Security Configuration Assessment
"""
import re
import json
import logging
from datetime import datetime, timezone

log = logging.getLogger("vuln")

# ── Lightweight CVE database (critical/high only) ─────────────────────────────
# Format: {package_name: [(version_pattern, cve_id, severity, score, description)]}
KNOWN_VULNS = {
    "openssh": [
        (r"^[1-8]\.", "CVE-2023-38408", "critical", 9.8, "OpenSSH agent remote code execution"),
        (r"^9\.[0-2]", "CVE-2024-6387", "critical", 8.1, "RegreSSHion - OpenSSH sshd race condition RCE"),
    ],
    "openssl": [
        (r"^1\.0\.", "CVE-2022-0778", "high", 7.5, "OpenSSL infinite loop in BN_mod_sqrt"),
        (r"^3\.0\.[0-6]", "CVE-2022-3602", "critical", 9.8, "OpenSSL X.509 buffer overflow"),
    ],
    "apache2": [
        (r"^2\.4\.(0|[1-4]\d|5[0-4])$", "CVE-2021-41773", "critical", 9.8, "Apache path traversal and RCE"),
        (r"^2\.4\.(0|[1-4]\d|5[0-4])$", "CVE-2021-42013", "critical", 9.8, "Apache path traversal (bypass)"),
    ],
    "nginx": [
        (r"^1\.(1[0-7]|[0-9])\.", "CVE-2021-23017", "critical", 9.4, "nginx off-by-one heap write"),
    ],
    "log4j": [
        (r"^2\.(0|1[0-4])\.", "CVE-2021-44228", "critical", 10.0, "Log4Shell - JNDI injection RCE"),
        (r"^2\.1[0-5]\.", "CVE-2021-45046", "critical", 9.0, "Log4j2 Thread Context lookup pattern RCE"),
    ],
    "python3": [
        (r"^3\.(6|7|8)\.", "CVE-2023-24329", "high", 7.5, "Python urllib.parse bypass"),
    ],
    "sudo": [
        (r"^1\.(8|9\.[0-9])\.", "CVE-2021-3156", "critical", 7.8, "Sudo Baron Samedit heap overflow"),
        (r"^1\.8\.", "CVE-2019-14287", "high", 8.8, "Sudo privilege escalation with user #-1"),
    ],
    "curl": [
        (r"^7\.[0-7]\d\.", "CVE-2023-38545", "critical", 9.8, "curl SOCKS5 heap overflow"),
    ],
    "bash": [
        (r"^4\.[0-3]", "CVE-2014-6271", "critical", 10.0, "Shellshock - bash environment variable injection"),
    ],
    "wordpress": [
        (r"^[1-5]\.", "CVE-2023-2745", "high", 6.5, "WordPress path traversal"),
    ],
    "php": [
        (r"^7\.", "CVE-2019-11043", "critical", 9.8, "PHP-FPM underflow RCE"),
        (r"^8\.0\.[0-9]$|^8\.1\.[0-9]$", "CVE-2023-3823", "high", 8.6, "PHP XML external entity injection"),
    ],
}

# ── CIS Benchmark Checks ───────────────────────────────────────────────────────
CIS_CHECKS_LINUX = [
    {
        "id": "CIS-1.1",
        "title": "Filesystem: /tmp is separate partition",
        "check": "findmnt /tmp",
        "expected": "tmp",
        "severity": "medium",
    },
    {
        "id": "CIS-1.7",
        "title": "Ensure AIDE is installed (file integrity)",
        "check": "which aide",
        "expected": "aide",
        "severity": "medium",
    },
    {
        "id": "CIS-2.1",
        "title": "Ensure time synchronization is in use",
        "check": "systemctl is-active chronyd || systemctl is-active ntp || systemctl is-active systemd-timesyncd",
        "expected": "active",
        "severity": "low",
    },
    {
        "id": "CIS-3.1",
        "title": "Ensure IPv6 is disabled (if not used)",
        "check": "sysctl net.ipv6.conf.all.disable_ipv6",
        "expected": "0",
        "severity": "low",
    },
    {
        "id": "CIS-3.2",
        "title": "Ensure packet redirect sending is disabled",
        "check": "sysctl net.ipv4.conf.all.send_redirects",
        "expected": "0",
        "severity": "medium",
    },
    {
        "id": "CIS-3.3",
        "title": "Ensure source routed packets are not accepted",
        "check": "sysctl net.ipv4.conf.all.accept_source_route",
        "expected": "0",
        "severity": "medium",
    },
    {
        "id": "CIS-4.1",
        "title": "Ensure auditing is enabled (auditd)",
        "check": "systemctl is-active auditd",
        "expected": "active",
        "severity": "high",
    },
    {
        "id": "CIS-5.1",
        "title": "Ensure cron daemon is enabled",
        "check": "systemctl is-enabled cron || systemctl is-enabled crond",
        "expected": "enabled",
        "severity": "low",
    },
    {
        "id": "CIS-5.2",
        "title": "Ensure SSH root login is disabled",
        "check": "grep '^PermitRootLogin' /etc/ssh/sshd_config",
        "expected": "no",
        "severity": "critical",
    },
    {
        "id": "CIS-5.3",
        "title": "Ensure SSH MaxAuthTries is set to 4 or less",
        "check": "grep '^MaxAuthTries' /etc/ssh/sshd_config",
        "expected": "[1-4]",
        "severity": "medium",
    },
    {
        "id": "CIS-5.4",
        "title": "Ensure SSH Protocol is 2",
        "check": "grep '^Protocol' /etc/ssh/sshd_config",
        "expected": "2",
        "severity": "high",
    },
    {
        "id": "CIS-6.1",
        "title": "Ensure password expiration is 365 days or less",
        "check": "grep '^PASS_MAX_DAYS' /etc/login.defs",
        "expected": r"\d{1,3}",
        "severity": "medium",
    },
    {
        "id": "CIS-6.2",
        "title": "Ensure root is the only UID 0 account",
        "check": "awk -F: '($3 == 0) {print $1}' /etc/passwd",
        "expected": "^root$",
        "severity": "critical",
    },
    {
        "id": "CIS-6.3",
        "title": "Ensure no accounts have empty passwords",
        "check": "awk -F: '($2 == \"\") {print $1}' /etc/shadow",
        "expected": "^$",
        "severity": "critical",
    },
    {
        "id": "CIS-6.4",
        "title": "Ensure firewall is active (ufw/iptables)",
        "check": "ufw status | grep active || iptables -L | head -1",
        "expected": "active|Chain",
        "severity": "high",
    },
]


def scan_vulnerabilities(inventory: list) -> list:
    """
    Scan installed software against known CVEs.
    inventory: list of {"name": str, "version": str}
    Returns list of vulnerability dicts.
    """
    findings = []

    for pkg in inventory:
        name    = (pkg.get("name","") or "").lower()
        version = (pkg.get("version","") or "").strip()

        # Match against known vulnerable packages
        for vuln_name, vuln_list in KNOWN_VULNS.items():
            if vuln_name not in name:
                continue

            for ver_pattern, cve, sev, score, desc in vuln_list:
                if re.search(ver_pattern, version):
                    findings.append({
                        "package":     pkg.get("name",""),
                        "version":     version,
                        "cve":         cve,
                        "severity":    sev,
                        "cvss_score":  score,
                        "description": desc,
                        "detected_at": datetime.now(timezone.utc).isoformat(),
                    })

    return findings


def run_cis_checks() -> list:
    """Run CIS benchmark checks on Linux."""
    import subprocess
    results = []

    for check in CIS_CHECKS_LINUX:
        try:
            out = subprocess.check_output(
                check["check"], shell=True, timeout=10,
                stderr=subprocess.DEVNULL
            ).decode(errors="ignore").strip()

            passed = bool(re.search(check["expected"], out, re.IGNORECASE))

            results.append({
                "id":       check["id"],
                "title":    check["title"],
                "passed":   passed,
                "output":   out[:200],
                "severity": check["severity"],
                "status":   "pass" if passed else "fail",
            })
        except Exception as e:
            results.append({
                "id":       check["id"],
                "title":    check["title"],
                "passed":   False,
                "output":   f"Error: {e}",
                "severity": check["severity"],
                "status":   "error",
            })

    return results


def compliance_summary(cis_results: list) -> dict:
    """Generate compliance score from CIS checks."""
    if not cis_results:
        return {}

    total   = len(cis_results)
    passed  = sum(1 for r in cis_results if r["passed"])
    failed  = [r for r in cis_results if not r["passed"]]
    critical_fails = [r for r in failed if r["severity"] == "critical"]
    high_fails     = [r for r in failed if r["severity"] == "high"]

    score = round(passed / total * 100, 1) if total else 0

    return {
        "total_checks":     total,
        "passed":           passed,
        "failed":           len(failed),
        "critical_fails":   len(critical_fails),
        "high_fails":       len(high_fails),
        "compliance_score": score,
        "grade":            "A" if score>=90 else "B" if score>=80 else "C" if score>=70 else "D" if score>=60 else "F",
        "failed_checks":    failed[:20],
    }
