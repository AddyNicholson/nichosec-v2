"""
core/utils.py
Shared helper utilities (JSON parsing, keyword heuristics, …).
Pure Python – no Streamlit imports so unit-tests stay fast.
"""

from __future__ import annotations

import json
import re
import os
import requests
from typing import List, Tuple

from .constants import PHISH_PATTERNS
from openai import OpenAI
from src.core.thresholds import TRUSTED_HOSTING_PROVIDERS

client = OpenAI()

# ── public helpers ──────────────────────────────────────────────────────

def parse_json(s: str) -> dict:
    """
    Best-effort JSON parse for LLM responses.

    • Strips markdown fences (```json … ```)
    • Falls back to a YELLOW verdict dict on malformed JSON
    """
    s = s.strip()
    if s.startswith("```"):
        # Remove leading ```
        s = re.sub(r"^```[\w]*", "", s).rstrip("```").strip()

    try:
        return json.loads(s)
    except Exception:
        return {
            "level":   "YELLOW",
            "summary": (s[:150] + "…") if s else "Model reply not JSON",
            "reasons": ["Fallback parse"],
        }
#keywords

def keyword_analysis(text: str) -> Tuple[int, List[str]]:
    """
    Score *text* against PHISH_PATTERNS.

    Returns:
        score   - cumulative risk points
        reasons - list of human-readable reason strings
    """
    score   = 0
    reasons: List[str] = []
    lower   = text.lower()

    for pattern, weight in PHISH_PATTERNS.items():
        if re.search(pattern, lower):
            # Strip the word-boundary markers for display
            reasons.append(f"Matched '{pattern.replace(r'\\b', '')}' (+{weight})")
            score += weight

    return score, reasons

#abuseip
def abuseip_lookup(ip: str) -> dict | None:
    """Query AbuseIPDB for threat reputation of a given IP."""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        print("[AbuseIPDB] No API key found in environment.")
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        res = requests.get(url, headers=headers, params=params)
        res.raise_for_status()
        raw = res.json()

        print(f"[AbuseIPDB] Lookup for {ip} → status: {res.status_code}")
        print(f"[AbuseIPDB] Raw response:\n{json.dumps(raw, indent=2)}")

        data = raw.get("data")
        if not data:
            print(f"[AbuseIPDB] No data returned for IP {ip}")
            return {
                "abuseConfidenceScore": 0,
                "usageType": "Unknown",
                "domain": "Unknown"
            }

        return data

    except Exception as e:
        print(f"[AbuseIPDB] Request failed for {ip}: {e}")
        return {
            "abuseConfidenceScore": 0,
            "usageType": "Unknown",
            "domain": "Unknown"
        }



def ai_threat_summary(ip: str, abuse_data: dict, geo: dict) -> str:
    """Use GPT to generate a 1-liner threat summary for this IP."""
    prompt = f"""
You are a cybersecurity analyst. Based on the following data, write a one-line summary of the IP's risk:

IP: {ip}
Fraud Score: {abuse_data.get("abuseConfidenceScore", "N/A")}
Usage Type: {abuse_data.get("usageType", "Unknown")}
ISP: {geo.get("isp", "N/A")}
City: {geo.get("city", "N/A")}
Country: {geo.get("country", "N/A")}
Categories: {abuse_data.get("domain", "N/A")}
    """.strip()

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=60,
            temperature=0.4
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"(AI summary error: {e})"



def smarten_ip_verdict(ip_data: dict, email_sender: str = "") -> tuple[str, int]:
    """
    Returns verdict + score using `adjusted_score` instead of avg/high/medium counts.
    """
    score = ip_data.get("adjusted_score", 0)

    if score >= 85:
        verdict = "High Risk IP detected - significant threat activity"
    elif score >= 60:
        verdict = "Suspicious IP activity - moderate risk"
    elif score >= 30:
        verdict = "Low risk IP - some minor signals"
    else:
        verdict = "Likely safe - no indicators detected"

    return verdict, score

# Exportable symbols for “from core.utils import *”
__all__ = ["parse_json", "keyword_analysis", "abuseip_lookup", "ai_threat_summary", "smarten_ip_verdict"]