# ── helpers --------------------------------------------------------------
import re, time, ipaddress, urllib.parse as up
from datetime import datetime
from pathlib import Path

import requests
from openai import OpenAI, APIError, RateLimitError

# 🔽 FIX THIS LINE
from src.core.openai_client import client      # absolute path from project root
# or, if you prefer a relative import inside the same package:
# from .openai_client import client

from .utils      import parse_json, keyword_analysis   # helpers in same pkg
from .constants  import PHISH_PATTERNS                # patterns live here

def is_valid_ip(inp: str) -> bool:
    try:
        ipaddress.ip_address(inp)
        return True
    except ValueError:
        return False


# ── main public function ────────────────────────────────────────────────
def scan(raw: str, purge: bool = False) -> dict:
    """Return a dict with level, summary, reasons, ips, etc."""
    # 0️⃣ basic IP harvest ----------------------------------------------
    ips = sorted({
        w.strip(".,;:")
        for w in raw.split()
        if is_valid_ip(w.strip(".,;:"))
    })

    # split headers/body once so we don’t scan headers twice
    body = raw.split("\n\n", 1)[-1]

    # 1️⃣ keyword-pattern heuristics ------------------------------------
    kw_score, kw_reasons = keyword_analysis(body)
    kw_score, kw_reasons = keyword_analysis(body)
    print("🔍 BODY PREVIEW →", body[:400])      # first 400 chars
    print("⚡ KW SCORE →", kw_score)
    print("📋 KW REASONS →", kw_reasons)

    if kw_score >= 8:
        kw_level = "RED"
    elif kw_score >= 4:
        kw_level = "YELLOW"
    else:
        kw_level = "GREEN"

    heur_reasons: list[str] = kw_reasons.copy()

    # 2️⃣ other static heuristics ---------------------------------------
    if "<script" in body.lower():
        heur_reasons.append("Inline <script> tag")

    b64_parts = re.findall(r"Content-Type:[^\n]+\n(?:.+\n)*?base64", raw, flags=re.I)
    for part in b64_parts:
        if not re.search(r'filename="?.+\.(pdf|docx?|xlsx?|pptx?|png|jpe?g|gif)"?', part, flags=re.I):
            heur_reasons.append("Suspicious base-64 payload")
            break

    # 3️⃣ pull visible links for the LLM prompt -------------------------
    links = re.findall(r'href=[\'"]?([^\'" >]+)', raw, flags=re.I)
    link_list = "\n".join(f"- {up.unquote(l)[:120]}" for l in links[:20]) or "None"

    # 4️⃣ ask GPT for a second opinion ----------------------------------
    prompt = f"""
You are **NichoSec**, a senior phishing-analysis AI.
Flag **RED** for strong indicators, **YELLOW** if uncertain, else **GREEN**.

Links extracted from the message:
{link_list}

Return STRICT JSON only:
```json
{{"level":"","summary":"","reasons":[]}}
```"""

    try:
        t0   = time.perf_counter()
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt + "\n\n" + body[:15_000]}],
            temperature=0.1,
        )
        data = parse_json(resp.choices[0].message.content)
        data["scan_time"] = round(time.perf_counter() - t0, 2)
    except (RateLimitError, APIError) as e:
        data = {
            "level":   "YELLOW",
            "summary": f"LLM unavailable – {e.__class__.__name__}",
            "reasons": ["Fallback – service error"],
            "scan_time": 0.0,
        }

    # 5️⃣ merge static heuristics with LLM verdict ----------------------
    if heur_reasons:
        data["reasons"] = heur_reasons + data.get("reasons", [])
        # escalate only if static verdict is worse than LLM’s
        if kw_level == "RED" and data["level"] != "RED":
            data["level"] = "RED"
        elif kw_level == "YELLOW" and data["level"] == "GREEN":
            data["level"] = "YELLOW"

    data["ips"] = ips

    # 6️⃣ optional purge plugin ----------------------------------------
    if purge and data["level"] != "GREEN":
        cleaned = "\n".join(
            l for l in raw.splitlines()
            if not any(t in l.lower() for t in ("seed phrase", "wire transfer", "password"))
        )
        data["cleaned"] = cleaned[:10_000]

    return data
