"""
src/core/extractors.py
Turn common document/file formats into plain UTF-8 text.

Pure-Python helpers - zero Streamlit imports, so they can be unit-tested
or reused in non-UI contexts.
"""

from __future__ import annotations

# ── std-lib ─────────────────────────────────────────────────────────────
from email import policy
from email.parser import BytesParser
from io import BytesIO
from pathlib import Path

# ── third-party ─────────────────────────────────────────────────────────
import fitz                      # PyMuPDF
import pandas as pd
from bs4 import BeautifulSoup
from docx import Document        # pip install python-docx

# ── public API (filled at bottom) ───────────────────────────────────────
__all__: list[str]

# ════════════════════════════════════════════════════════════════════════
# Individual extractors
# ════════════════════════════════════════════════════════════════════════
def extract_pdf(buf: bytes) -> str:
    """Return text from a PDF file (all pages)."""
    with fitz.open(stream=buf, filetype="pdf") as doc:
        return "\n".join(page.get_text() for page in doc)


def extract_docx(buf: bytes) -> str:
    """Return text from a DOCX document."""
    return "\n".join(p.text for p in Document(BytesIO(buf)).paragraphs)


def extract_csv(buf: bytes) -> str:
    """Return CSV contents as comma-separated text (first 2 000 rows)."""
    return pd.read_csv(BytesIO(buf), nrows=2_000).to_csv(index=False)


def extract_xlsx(buf: bytes) -> str:
    """Return all sheets from an XLS/XLSX as CSV-style text (1 000 rows per sheet)."""
    frames = pd.read_excel(BytesIO(buf), sheet_name=None, nrows=1_000)
    return "\n\n".join(f"### {name}\n" + df.to_csv(index=False) for name, df in frames.items())


def extract_html(buf: bytes) -> str:
    """Return visible text from an HTML file (tags stripped)."""
    return BeautifulSoup(buf, "html.parser").get_text(" ", strip=True)


def extract_eml(buf: bytes) -> str:
    """
    Return headers + visible text from an .eml email.

    • Pulls plain-text parts
    • Strips HTML parts to text
    • Recurses into forwarded messages
    • Ignores attachments (let scan engine handle them if needed)
    """
    msg = BytesParser(policy=policy.default).parsebytes(buf)

    header_bits = [
        f"Subject: {msg.get('subject', '')}",
        f"From:    {msg.get('from', '')}",
        f"To:      {msg.get('to', '')}",
        f"Date:    {msg.get('date', '')}",
    ]

    body_chunks: list[str] = []
    for part in msg.walk():
        ctype = part.get_content_type()
        disp  = part.get_content_disposition()   # attachment / inline / None

        if ctype == "text/plain" and disp != "attachment":
            body_chunks.append(part.get_content())

        elif ctype == "text/html" and disp != "attachment":
            html = part.get_content()
            body_chunks.append(
                BeautifulSoup(html, "html.parser").get_text(" ", strip=True)
            )

        elif ctype == "message/rfc822":          # forwarded email
            try:
                nested = part.get_payload(0)
                body_chunks.append(
                    "\n--- Forwarded message ---\n" + extract_eml(nested.as_bytes())
                )
            except Exception:
                pass   # keep extractor resilient

    return "\n".join(header_bits + [""] + body_chunks).strip()


# ════════════════════════════════════════════════════════════════════════
# Dispatcher – one entry point Streamlit can call
# ════════════════════════════════════════════════════════════════════════
def _decode_text(buf: bytes) -> str:
    """Helper for .txt / .log etc."""
    return buf.decode(errors="ignore")


_DISPATCH = {
    ".pdf":  extract_pdf,
    ".docx": extract_docx,
    ".csv":  extract_csv,
    ".xlsx": extract_xlsx,
    ".xls":  extract_xlsx,
    ".html": extract_html,
    ".htm":  extract_html,
    ".txt":  _decode_text,
    ".log":  _decode_text,
    ".eml":  extract_eml,
}


def extract_text(uploaded) -> str:   # type: ignore[valid-type]
    """
    Streamlit-friendly wrapper: accept an `uploaded_file` and
    return UTF-8 text, or "" if the format isn't supported.
    """
    if uploaded is None:
        return ""

    suffix = Path(uploaded.name).suffix.lower()
    data   = uploaded.read()

    return _DISPATCH.get(suffix, lambda _b: "")(data)


# ── expose public symbols ───────────────────────────────────────────────
__all__ = list(_DISPATCH.values()) + ["extract_text"]
