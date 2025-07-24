#src/core/threat_intel.py

import requests
import os
import ipinfo

import requests
import os
import ipinfo

def lookup_ip_threat(ip: str) -> dict:
    """Query IPQualityScore API to get fraud and abuse risk for an IP, plus AI insight."""
    api_key = os.getenv("IPQS_API_KEY")
    if not api_key:
        return {"error": "Missing IPQS_API_KEY in environment", "ip": ip}

    url = f"https://ipqualityscore.com/api/json/ip/{api_key}/{ip}"

    try:
        
        response = requests.get(url, timeout=10)
        data = response.json()

        fraud_score     = data.get("fraud_score", 0)
        abuse_velocity  = data.get("abuse_velocity", "low")
        recent_abuse    = data.get("recent_abuse", False)
        isp             = data.get("ISP", "Unknown ISP")
        country         = data.get("country_code", "Unknown location")

        # ── Adjusted Score Logic ───────────────────────────────────────────────
        adjusted_score = fraud_score

        if recent_abuse:
            adjusted_score = max(adjusted_score, 70)
        if abuse_velocity == "medium":
            adjusted_score = max(adjusted_score, 60)
        elif abuse_velocity == "high":
            adjusted_score = max(adjusted_score, 85)

        # ── NEW: Suspicious Heuristic (borderline + shady context) ─────────────
        suspicious_context = False
        if 30 <= fraud_score < 60:
            if any([
                abuse_velocity in ("medium", "high"),
                recent_abuse,
                isp.lower() in ["unknown", "", "private", "simoresta.lt"],
                data.get("proxy") or data.get("vpn") or data.get("tor")
            ]):
                suspicious_context = True
                adjusted_score = max(adjusted_score, 60)

        # ── Summary Label ───────────────────────────────────────────────────────
        summary = (
            "High Risk" if adjusted_score >= 85 else
            "Suspicious" if adjusted_score >= 60 else
            "Caution: Unknown or Unverified"
        )


        # ── AI Insight Text ─────────────────────────────────────────────────────
        abuse_flags = []
        if data.get("vpn"):
            abuse_flags.append("VPN")
        if data.get("tor"):
            abuse_flags.append("TOR node")
        if data.get("proxy"):
            abuse_flags.append("Proxy")
        if data.get("is_crawler"):
            abuse_flags.append("Bot/Crawler")
        if recent_abuse:
            abuse_flags.append("recent abuse activity")

        abuse_text = (
            "It was also flagged for: " + ", ".join(abuse_flags) + "."
            if abuse_flags else
            "No major abuse flags were detected."
        )

        ai_insight = (
            f"The IP address {ip}, associated with {isp} in {country}, "
            f"has an adjusted risk score of {adjusted_score}. It is classified as **{summary}**. "
            f"{abuse_text}"
        )

        # ── RETURN BLOCK (scan_engine-compatible) ─────────────────────────────
        return {
            # Required for scan_engine scoring
            "avg": adjusted_score,
            "high": 1 if adjusted_score >= 70 else 0,
            "medium": 1 if 40 <= adjusted_score < 70 else 0,
            "count": 1,

            # Extended metadata for PDF/AI/reporting
            "ip": ip,
            "fraud_score": fraud_score,
            "adjusted_score": adjusted_score,
            "summary": summary,
            "ai_insight": ai_insight,
            "is_vpn": data.get("vpn"),
            "is_tor": data.get("tor"),
            "is_proxy": data.get("proxy"),
            "is_crawler": data.get("is_crawler"),
            "recent_abuse": recent_abuse,
            "abuse_velocity": abuse_velocity,
            "country": country,
            "ISP": isp,

            # NEW: Suspicious heuristic flagging
            "suspicious_context": suspicious_context,
            "flag_reason": (
                "Borderline fraud score with suspicious signals"
                if suspicious_context else ""
            ),
        }
    except Exception as e:
        return {"error": str(e), "ip": ip}



# ── IPINFO GEO-LOCATION LOOKUP ───────────────────────────────────

_ipinfo_handler = ipinfo.getHandler(os.getenv("IPINFO_TOKEN"))

def get_ip_location(ip: str) -> dict:
    """
    Return city, region, country, and lat/long for an IP.
    Falls back to empty strings if the lookup fails.
    """
    try:
        details = _ipinfo_handler.getDetails(ip)
        loc = details.loc.split(",") if details.loc else [None, None]
        return {
            "ip":       ip,
            "city":     details.city or "",
            "region":   details.region or "",
            "country":  details.country or "",
            "lat":      float(loc[0]) if loc[0] else None,
            "lon":      float(loc[1]) if loc[1] else None,
            "asn":      details.org or ""
        }
    
    except Exception:
        return {"ip": ip, "city": "", "region": "", "country": "", "lat": None, "lon": None}

def virustotal_lookup(sha256: str) -> dict:
    key = os.getenv("VT_API_KEY")
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": key}
    try:
        r = requests.get(url, headers=headers, timeout=8)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def upload_to_hybrid(file_bytes: bytes, filename: str = "file") -> dict:
    url = "https://www.hybrid-analysis.com/api/v2/submit/file"
    headers = {
        "api-key": os.getenv("HYBRID_API_KEY"),
        "User-Agent": "NichoSec"
    }
    files = {"file": (filename, file_bytes)}
    data = {"environment_id": 300}  # Windows 10 64-bit
    try:
        resp = requests.post(url, headers=headers, files=files, data=data, timeout=12)
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

def get_hybrid_report(sha256: str) -> dict:
    url = f"https://www.hybrid-analysis.com/api/v2/overview/{sha256}"
    headers = {
        "api-key": os.getenv("HYBRID_API_KEY"),
        "User-Agent": "NichoSec"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        return resp.json()
    except Exception as e:
        return {"error": str(e)}
