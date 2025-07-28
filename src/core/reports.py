from fpdf import FPDF
from datetime import datetime
from pathlib import Path
import re
import pandas as pd
import json
DOMAIN_RE = re.compile(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,4}$")

# 🔑 1.  Bullet-proof asset paths (case-safe, project-root safe)

HERE    = Path(__file__).resolve().parent          
ASSETS  = (HERE / ".." / ".." / "assets").resolve()  

FONT_PATH = ASSETS / "DejaVuSans.ttf"
LOGO_PATH = ASSETS / "shield_pulse_dark.png"

##############################################################################
HISTORY_DIR = Path(__file__).resolve().parents[2] / "history"
HISTORY_DIR.mkdir(parents=True, exist_ok=True)

def save_result(filename: str, result: dict):
    """Save a scan result to local history folder as JSON."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = filename.replace(" ", "_").replace("/", "_")
    output_path = HISTORY_DIR / f"{timestamp}__{safe_name}.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

def _safe(txt: str) -> str:
    return (txt.replace("–", "-").replace("—", "-")
               .replace("“", '"').replace("”", '"')
               .replace("‘", "'").replace("’", "'"))

def make_pdf(report: dict) -> bytes:
    pdf = FPDF(unit="pt", format="A4")
    pdf.set_auto_page_break(auto=True, margin=50)
    pdf.add_page()

    try:
        pdf.add_font("DejaVu", "", str(FONT_PATH), uni=True)
        pdf.set_font("DejaVu", "", 10)
    except RuntimeError:
        pdf.set_font("Helvetica", "", 10)

    try:
        pdf.image(str(LOGO_PATH), x=40, y=30, w=40)
    except RuntimeError:
        pass

    pdf.set_font_size(20)
    pdf.set_xy(90, 35)
    pdf.cell(0, 20, "NichoSec V2 Threat Report", ln=1)

    pdf.set_font_size(10)
    pdf.set_xy(90, 58)
    pdf.cell(0, 14, f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}", ln=1)
    pdf.ln(20)

    epw = pdf.w - pdf.l_margin - pdf.r_margin

    # -- Verdict Banner --
    level   = report.get("level", "YELLOW").upper()
    summary = report.get("summary", "")
    r, g, b = {"RED": (220, 53, 69), "YELLOW": (255, 193, 7), "GREEN": (40, 167, 69)}.get(level, (108, 117, 125))

    left_pad = 12
    inner_w = epw - 2 * left_pad
    line_h = 24

    for size in (16, 14, 12):
        pdf.set_font_size(size)
        lines = pdf.multi_cell(inner_w, line_h, f"{level} – {summary}", 0, "L", split_only=True)
        if len(lines) <= 3:
            break

    y_start = pdf.get_y()
    banner_height = len(lines) * line_h
    pdf.set_fill_color(r, g, b)
    pdf.rect(pdf.l_margin, y_start, epw, banner_height, 'F')
    pdf.set_text_color(255, 255, 255)
    pdf.set_y(y_start)

    for line in lines:
        pdf.set_x(pdf.l_margin + left_pad)
        pdf.cell(0, line_h, line, ln=1)

    pdf.ln(6)
    pdf.set_text_color(0, 0, 0)

    pdf.set_font_size(12)
    source = report.get("source", "unknown").lower()

    if source in ("eml", "gmail", "email"):
        pdf.cell(0, 14, f"From:    {report.get('from', '—')}", ln=1)
        pdf.cell(0, 14, f"To:      {report.get('to', '—')}", ln=1)
        pdf.cell(0, 14, f"Subject: {report.get('subject', '—')}", ln=1)
        pdf.cell(0, 14, f"Date:    {report.get('date', '—')}", ln=1)
    elif source in ("docx", "pdf", "txt"):
        pdf.cell(0, 14, f"Filename: {report.get('filename', '—')}", ln=1)
        if "word_count" in report:
            pdf.cell(0, 14, f"Words: {report['word_count']}", ln=1)
        if "page_count" in report:
            pdf.cell(0, 14, f"Pages: {report['page_count']}", ln=1)
    else:
        pdf.cell(0, 14, f"Source: {source}", ln=1)

    pdf.ln(8)


    spf   = report.get("spf", "none").upper()
    dkim  = report.get("dkim", "none").upper()
    dmarc = report.get("dmarc", "none").upper()
    pdf.cell(0, 14, f"SPF: {spf}    DKIM: {dkim}    DMARC: {dmarc}", ln=1)
    pdf.ln(8)

    # -- AI One-liner Threat Summary --
    pdf.set_font_size(12)
    pdf.cell(0, 16, "Threat Summary (AI-Generated):", ln=1)
    pdf.multi_cell(epw, 14, report.get("threat_summary", "N/A"), 0, "L")
    pdf.ln(6)

    # -- Component Scores --
    pdf.cell(0, 14, "Component Scores:", ln=1)
    components = report.get("components", {})
    for comp in ("auth", "ip", "content", "llm"):
        value = components.get(comp, 0)
        pdf.cell(0, 14, f"{comp.upper():<8}: {value:.1f}", ln=1)
    pdf.ln(8)

    # -- Reasons --
    pdf.set_font_size(12)
    pdf.cell(0, 16, "Reasons:", ln=1)
    bullet_gap, line_h = 6, 14
    for r in report.get("reasons", []):
        pdf.set_x(pdf.l_margin)
        pdf.cell(bullet_gap, line_h, "•", ln=0)
        pdf.set_x(pdf.l_margin + bullet_gap)
        pdf.multi_cell(epw - bullet_gap, line_h, _safe(r), 0, "L")
    pdf.ln(8)

    # -- IPs with optional scores --
    ip_details = report.get("ip_details", [])
    pdf.set_font_size(12)
    pdf.cell(0, 16, "IP Reputation Details:", ln=1)
    if ip_details:
        for ip in ip_details:
            line = f"{ip.get('ip', '—')} → score: {ip.get('score', '—')}"
            pdf.cell(0, 14, line, ln=1)
    else:
        # fallback: raw IP list
        raw_ips = report.get("ips", [])
        if raw_ips:
            pdf.multi_cell(epw, 14, ", ".join(raw_ips), 0, "L")
        else:
            pdf.cell(0, 14, "—", ln=1)
    pdf.ln(8)
    
    # -- Domains -- 
    raw_domains = report.get("domains", [])
    clean_domains = []
    bad_domains = {"badsite.com", "phishy.biz", "known-scam.co"}  # match engine

    for d in raw_domains:
        d2 = d.strip().rstrip("=?")
        if DOMAIN_RE.fullmatch(d2) and d2 not in clean_domains:
            clean_domains.append(d2)

    if clean_domains:
        pdf.set_font_size(12)
        pdf.cell(0, 14, "Domains:", ln=1)
        for domain in clean_domains:
            color = (220, 53, 69) if domain in bad_domains else (0, 0, 0)
            pdf.set_text_color(*color)
            pdf.set_x(pdf.l_margin)
            pdf.cell(bullet_gap, line_h, "•", ln=0)
            pdf.set_x(pdf.l_margin + bullet_gap)
            pdf.cell(0, line_h, domain, ln=1)
        pdf.set_text_color(0, 0, 0)  # reset after
        pdf.ln(4)


    # -- URLs --
    raw_urls = report.get("urls", [])
    clean_urls = []
    for u in raw_urls:
        u2 = u.strip().rstrip("=?")
        if u2 and u2 not in clean_urls:
            clean_urls.append(u2)

    if clean_urls:
        pdf.set_font_size(12)
        pdf.cell(0, 14, "URLs:", ln=1)
        for u in clean_urls:
            pdf.set_x(pdf.l_margin)
            pdf.cell(bullet_gap, line_h, "•", ln=0)
            pdf.set_x(pdf.l_margin + bullet_gap)
            pdf.multi_cell(epw - bullet_gap, line_h, u, 0, "L")
        pdf.ln(4)

    # -- Scan Time --
    pdf.set_font_size(10)
    pdf.cell(0, 12, f"Scan time: {report.get('scan_time', 0):.2f} s", ln=1)

    # -- Export bytes --
    raw = pdf.output(dest="S")
    if raw is None:
        raise RuntimeError("PDF build failed – verify FONT_PATH and LOGO_PATH")

    if isinstance(raw, str):
        raw = raw.encode("latin-1")

    assert isinstance(raw, (bytes, bytearray)), type(raw)
    return raw
