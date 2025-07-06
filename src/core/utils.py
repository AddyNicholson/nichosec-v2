"""
core/utils.py
Shared helper utilities (JSON parsing, keyword heuristics, …).
Pure Python – no Streamlit imports so unit-tests stay fast.
"""

from __future__ import annotations

import json
import re
from typing import List, Tuple

from .constants import PHISH_PATTERNS


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


def keyword_analysis(text: str) -> Tuple[int, List[str]]:
    """
    Score *text* against PHISH_PATTERNS.

    Returns:
        score   – cumulative risk points
        reasons – list of human-readable reason strings
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


# Exportable symbols for “from core.utils import *”
__all__ = ["parse_json", "keyword_analysis"]
