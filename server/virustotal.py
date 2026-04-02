"""
Cibervault VirusTotal Integration
- File hash scanning
- IP/URL reputation
- Auto-scan on file events
- Results cached in DB
"""
import asyncio
import aiohttp
import hashlib
import json
import logging
import os
from datetime import datetime, timezone

log = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"

async def vt_scan_hash(api_key: str, file_hash: str) -> dict:
    """Query VirusTotal for a file hash (MD5, SHA1, or SHA256)."""
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    url = f"{VT_BASE}/files/{file_hash}"
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 404:
                    return {"found": False, "hash": file_hash}
                if r.status == 429:
                    return {"error": "Rate limited", "hash": file_hash}
                if r.status != 200:
                    return {"error": f"HTTP {r.status}", "hash": file_hash}
                data = await r.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "found":      True,
                    "hash":       file_hash,
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "harmless":   stats.get("harmless", 0),
                    "total":      sum(stats.values()),
                    "name":       attrs.get("meaningful_name", ""),
                    "type":       attrs.get("type_description", ""),
                    "size":       attrs.get("size", 0),
                    "first_seen": attrs.get("first_submission_date", 0),
                    "last_seen":  attrs.get("last_analysis_date", 0),
                    "permalink":  f"https://www.virustotal.com/gui/file/{file_hash}",
                    "verdict":    "malicious" if stats.get("malicious",0) >= 3
                                  else "suspicious" if stats.get("suspicious",0) >= 2
                                  else "clean",
                }
    except asyncio.TimeoutError:
        return {"error": "Timeout", "hash": file_hash}
    except Exception as e:
        return {"error": str(e), "hash": file_hash}

async def vt_scan_ip(api_key: str, ip: str) -> dict:
    """Query VirusTotal for IP reputation."""
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    url = f"{VT_BASE}/ip_addresses/{ip}"
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status != 200:
                    return {"error": f"HTTP {r.status}", "ip": ip}
                data = await r.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "found":      True,
                    "ip":         ip,
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "country":    attrs.get("country", ""),
                    "asn":        attrs.get("asn", ""),
                    "as_owner":   attrs.get("as_owner", ""),
                    "permalink":  f"https://www.virustotal.com/gui/ip-address/{ip}",
                    "verdict":    "malicious" if stats.get("malicious",0) >= 3
                                  else "suspicious" if stats.get("suspicious",0) >= 1
                                  else "clean",
                }
    except Exception as e:
        return {"error": str(e), "ip": ip}

async def vt_scan_url(api_key: str, url_to_scan: str) -> dict:
    """Submit URL to VirusTotal for scanning."""
    headers = {"x-apikey": api_key, "Accept": "application/json",
               "Content-Type": "application/x-www-form-urlencoded"}
    try:
        async with aiohttp.ClientSession() as s:
            # Submit URL
            async with s.post(f"{VT_BASE}/urls", headers=headers,
                               data=f"url={url_to_scan}",
                               timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status not in (200, 201):
                    return {"error": f"Submit failed: HTTP {r.status}"}
                sub = await r.json()
                analysis_id = sub.get("data", {}).get("id", "")
            # Get results
            await asyncio.sleep(3)
            async with s.get(f"{VT_BASE}/analyses/{analysis_id}",
                              headers={"x-apikey": api_key},
                              timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status != 200:
                    return {"error": f"Analysis failed: HTTP {r.status}"}
                data = await r.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("stats", {})
                return {
                    "url":        url_to_scan,
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless":   stats.get("harmless", 0),
                    "verdict":    "malicious" if stats.get("malicious",0) >= 3 else "clean",
                    "permalink":  f"https://www.virustotal.com/gui/url/{analysis_id}",
                }
    except Exception as e:
        return {"error": str(e)}

def hash_file_bytes(data: bytes) -> dict:
    """Compute MD5, SHA1, SHA256 for file bytes."""
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
