# ── src/core/lookup_ip_threat.py ──────────────────────────────────────

import os, time, requests
from dotenv import load_dotenv
from functools import lru_cache

load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_KEY = os.getenv("OTX_API_KEY")

# ── Simple cache to prevent API spam (TTL = 1hr per IP) ────────────────
_ip_cache = {}

def lookup_ip_threat(ip: str) -> dict:
    # Return cached result if fresh
    if ip in _ip_cache and time.time() - _ip_cache[ip]['ts'] < 3600:
        return _ip_cache[ip]['data']

    abuse = fetch_abuseipdb(ip)
    otx = fetch_otx(ip)

    result = {
        "ip": ip,
        "abuseipdb": abuse,
        "otx": otx,
        "verdict": generate_verdict(abuse, otx)
    }

    _ip_cache[ip] = {"ts": time.time(), "data": result}
    return result

# ── AbuseIPDB integration ─────────────────────────────────────────────
def fetch_abuseipdb(ip: str) -> dict:
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        )
        data = resp.json().get("data", {})
        return {
            "confidence_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", "N/A"),
            "isp": data.get("isp", ""),
            "usage_type": data.get("usageType", ""),
            "domain": data.get("domain", ""),
            "total_reports": data.get("totalReports", 0),
            "last_reported": data.get("lastReportedAt", None)
        }
    except Exception as e:
        return {"error": str(e)}

# ── AlienVault OTX integration ────────────────────────────────────────
def fetch_otx(ip: str) -> dict:
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": OTX_KEY}
        )
        data = resp.json()
        return {
            "reputation": data.get("reputation", 0),
            "pulse_info": {
                "count": data.get("pulse_info", {}).get("count", 0),
                "names": [p["name"] for p in data.get("pulse_info", {}).get("pulses", [])]
            }
        }
    except Exception as e:
        return {"error": str(e)}

# ── Verdict generator ─────────────────────────────────────────────────
def generate_verdict(abuse: dict, otx: dict) -> str:
    abuse_score = abuse.get("confidence_score", 0)
    otx_count = otx.get("pulse_info", {}).get("count", 0)

    if abuse_score > 70 or otx_count > 0:
        return "HIGH RISK"
    elif abuse_score > 20:
        return "SUSPICIOUS"
    else:
        return "LIKELY BENIGN"
