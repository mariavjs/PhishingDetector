# src/sync_utils.py
import os
import requests
from urllib.parse import urlparse
from db import SessionLocal, add_blacklist_entry

# ---------- helpers ----------
def _normalize_domain_from_line(line):
    ln = (line or "").strip()
    if not ln:
        return None
    if ln.startswith("#"):
        return None
    if ln.startswith("http://") or ln.startswith("https://"):
        try:
            return (urlparse(ln).hostname or ln).lower()
        except Exception:
            return ln.lower()
    return ln.lower()

# ---------- sync generic ----------
def sync_list_from_url(feed_url: str, source: str = "external", timeout: int = 20, max_lines: int | None = None):
    added = 0
    tried = 0
    errors = []
    try:
        r = requests.get(feed_url, timeout=timeout)
        if r.status_code != 200:
            return 0, 0, [f"HTTP {r.status_code}"]
        lines = r.text.splitlines()
        if max_lines:
            lines = lines[:max_lines]
        with SessionLocal() as s:
            for ln in lines:
                dom = _normalize_domain_from_line(ln)
                if not dom:
                    continue
                tried += 1
                try:
                    add_blacklist_entry(s, dom, source=source, comment=f"sync from {feed_url}")
                    added += 1
                except Exception as e:
                    errors.append(str(e))
        return added, tried, errors
    except Exception as ex:
        return 0, 0, [str(ex)]

# ---------- phishtank bulk ----------
def sync_phishtank_bulk(api_key: str | None = None, max_lines: int | None = 5000):
    if api_key:
        url = f"https://data.phishtank.com/data/{api_key}/online-valid.csv"
    else:
        url = "https://data.phishtank.com/data/online-valid.csv"
    return sync_list_from_url(url, source="phishtank", max_lines=max_lines)

# ---------- google safe browsing single-lookup ----------
def check_google_safebrowsing(url: str, api_key: str):
    """
    Faz a requisição para Google Safe Browsing API v4 (threatMatches.find).
    Retorna dicionário com keys: match (bool), detail (raw json) ou error.
    """
    if not api_key:
        return {"match": False, "error": "no_api_key_provided"}
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    body = {
        "client": {"clientId": "phish-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        r = requests.post(endpoint, json=body, timeout=10)
        if r.status_code != 200:
            return {"match": False, "error": f"http_{r.status_code}", "resp_text": r.text}
        data = r.json()
        if data and "matches" in data and data["matches"]:
            return {"match": True, "detail": data}
        return {"match": False, "detail": data}
    except Exception as e:
        return {"match": False, "error": str(e)}
