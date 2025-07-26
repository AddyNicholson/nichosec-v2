# ── bootstrap: make project root importable ────────────────────────────
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]   # …/NichoSec
if str(PROJECT_ROOT) not in sys.path:                # avoid duplicates
    sys.path.insert(0, str(PROJECT_ROOT))            # prepend to be safe
# ────────────────────────────────────────────────────────────────────────

# ── standard / third-party libs ───────────────────────────────────────
import os, json, re, base64, ipaddress, imaplib, tempfile, time
from io import BytesIO
import urllib.parse as up
import email as email_lib

import fitz                     # PyMuPDF   
import pandas as pd
import requests
from bs4 import BeautifulSoup
from docx import Document
import streamlit as st
from openai import APIError, RateLimitError
from dotenv import load_dotenv   # ← add
from zipfile import ZipFile
load_dotenv()                    # ← pulls NICHOSEC_APP_KEY from .env

# ── NEW: Safelist persistence + known-org mapping ─────────────────────

from src.core.constants import SAFE_IPS as DEFAULT_SAFE_IPS

SAFE_IPS_FILE = "safe_ips.json"

def load_safe_ips():
    try:
        with open(SAFE_IPS_FILE) as f:
            return set(json.load(f))
    except FileNotFoundError:
        return set()

def save_safe_ips(safe_set):
    with open(SAFE_IPS_FILE, "w") as f:
        json.dump(list(safe_set), f)

# Start with your on-disk list, then union in the shipped defaults
SAFE_IPS = load_safe_ips()

# Your known-org mapping lives here too
ORG_IPS = {
    "203.36.205.14": "Fulton Hogan",
    # …add more here
}
# ── project modules ───────────────────────────────────────────────────

from src.core.prompting     import NCHOSEC_SYSTEM_PROMPT
from src.core.openai_client import client
from src.core.scan_engine   import scan
from src.core.extractors    import extract_text
from src.core.reports       import make_pdf
from src.core.threat_intel  import lookup_ip_threat, get_ip_location
from src.core.utils         import abuseip_lookup, ai_threat_summary
from src.core.thresholds    import THREAT_THRESHOLDS
from src.core.utils         import smarten_ip_verdict
from src.core.reports       import save_result
from urllib.parse import urlencode
from login import login, logout
from src.core.lookup_ip_threat import lookup_ip_threat
from src.core import gmail_loader 
from src.core.threat_intel import (
    lookup_ip_threat,
    virustotal_lookup,
    upload_to_hybrid,
    get_hybrid_report,
    get_ip_location
)


if not st.session_state.get("user"):
    login()
else:
    st.sidebar.markdown(f"**{st.session_state.user}** ({st.session_state.role})")
    if st.sidebar.button("Log out"):
        logout()


# ── UTILITIES ─────────────────────────────────────────────────────────────

def to_base64(path: str) -> str:
    """Return base‑64 of a local file or empty string if not found."""
    p = Path(path)
    
    return base64.b64encode(p.read_bytes()).decode() if p.exists() else ""

bg_b64 = to_base64("assets/circuit_dark_bg.png")

def parse_json(s: str) -> dict:            # safe‑parse GPT output
    s = s.strip()
    if s.startswith("```"):
        s = re.sub(r"^```[\w]*", "", s).rstrip("```").strip()
    try:
        return json.loads(s)
    except Exception:
        return {
            "level": "YELLOW",
            "summary": (s[:150] + "…") if s else "Model reply not JSON",
            "reasons": ["Fallback parse"],
        }

# ── NETWORK HELPERS ───────────────────────────────────────────────────────

@st.cache_data(ttl=3600)  # ← cache for 1 hour
def lookup_ip(ip: str, timeout: int = 6) -> dict:
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=timeout)
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}

@st.cache_data(ttl=3600)
def abuseip_lookup(ip: str) -> dict:
    headers = {
        "Key": os.getenv("ABUSEIPDB_KEY"),
        "Accept": "application/json"
    }
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    try:
        resp = requests.get(url, headers=headers, timeout=6)
        return resp.json().get("data", {}) if resp.status_code == 200 else {}
    except Exception as e:
        return {"error": str(e)}


# ── UI CONFIG ─────────────────────────────────────────────────────────────
st.set_page_config(page_title="NichoSec | Local Threat Scanner",
                   page_icon="assets/shield_pulse_dark.png", layout="centered")

# ── AUTHENTICATION + ROLES ─────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()                                          # .env → env vars

# ── SIDEBAR NAVIGATION + BACKGROUND IMAGE ────────────────────────────────
st.sidebar.title(" NichoSec")
page = st.sidebar.radio("Navigate", ["Scan", "Dashboard"])

# right above bg_b64
HERE = Path(__file__).parent          # folder that contains this .py file
bg_path = HERE / "NichoSec brain.png"  # → ui/NichoSec brain.png
bg_b64  = to_base64(bg_path)


st.markdown(
    f"""
    <style>
      .stApp {{
        background: url("data:image/png;base64,{bg_b64}") no-repeat center center fixed;
        background-size: cover;
      }}
      .stApp:before {{
        content: ""; position: fixed; inset: 0;
        background: rgba(0,0,0,0.85); backdrop-filter: blur(4px); z-index: -1;
      }}
      .card {{
        background: rgba(255,255,255,0.70); padding: 2rem 1.5rem; border-radius: 12px;
        margin-bottom: 2rem; box-shadow: 0 4px 12px rgba(0,0,0,0.45); color: #111;
      }}
      .card * {{ color: #111 !important; }}
      .nichosec-header {{ display:flex; justify-content:center; align-items:center; gap:0.6rem; margin:0.4rem 0 1.0rem; }}
      .nichosec-header h1 {{ margin:0; font-size:2rem; font-weight:600; }}
    </style>
    """,
    unsafe_allow_html=True,
)


 # GMAIL LOADER

with st.sidebar.expander("📧 Gmail Loader", expanded=False):
    st.info("Securely scan emails from your Gmail inbox.")

    if st.button("🔐 Connect Gmail"):
        try:
            st.session_state.gmail_msgs = gmail_loader.get_recent_emails(10)
            st.success(f"{len(st.session_state.gmail_msgs)} messages loaded.")
        except Exception as e:
            st.error(f"Gmail load failed: {e}")

    if "gmail_msgs" in st.session_state:
        for msg_id, subject in st.session_state.gmail_msgs:
            if st.button(f"Scan: {subject[:40]}...", key=f"gmail-scan-{msg_id}"):
                raw = gmail_loader.fetch_email_raw(msg_id)
                result = scan(raw)
                st.session_state.threat = result
                st.success("Scan complete. See main panel.")


# ────────────────────────────────────────────────────────────────────────────────

with st.sidebar.expander("💬  Ask NichoSec AI", expanded=False):
    # Step 0: Clear input box after response if flagged
    if st.session_state.pop("_reset_box", False):
        st.session_state.pop("chat_box", None)

    # Step 1: Initialize chat history
    if "chat" not in st.session_state:
        st.session_state.chat = [
            {"role": "system", "content": NCHOSEC_SYSTEM_PROMPT},
            {"role": "assistant", "content":
                "Welcome to NichoSec AI. I'm here to assist with threat analysis for emails, files, and IPs."},
        ]

    # Step 2: Model selector
    model_name = st.radio(
        "Select AI Model:",
        ["gpt-3.5-turbo", "gpt-4o-mini"],
        index=1, horizontal=True,
        format_func=lambda m: "GPT-3.5" if m.startswith("gpt-3.5") else "GPT-4o Mini",
    )

    # Step 3: Clear chat history
    if st.button("Reset Conversation"):
        st.session_state.pop("chat", None)
        st.rerun()

    # Step 4: Display message history (excluding system prompt)
    for msg in st.session_state.chat:
        if msg["role"] != "system":
            st.markdown(msg["content"])

    # Step 5: User input prompt
    prompt = st.text_input(
        "Ask a Security Question:",
        key="chat_box",
        placeholder="e.g., Does this email look suspicious?",
    )

    # Step 6: Submit and process response
    if st.button("Send", key="chat_send") and prompt.strip():
        # Append user input
        st.session_state.chat.append({"role": "user", "content": prompt})

        # Limit memory for efficiency
        trimmed_history = [st.session_state.chat[0]] + st.session_state.chat[-10:]

        try:
            resp = client.chat.completions.create(
                model=model_name,
                messages=trimmed_history,
                temperature=0.3,
                stream=True,
            )

            placeholder, assistant_reply = st.empty(), ""
            with st.spinner("Analyzing..."):
                for chunk in resp:
                    assistant_reply += chunk.choices[0].delta.content or ""
                    placeholder.markdown(assistant_reply)

            # Store assistant reply
            st.session_state.chat.append({"role": "assistant", "content": assistant_reply})
            st.session_state.chat = [st.session_state.chat[0]] + st.session_state.chat[-10:]
            st.session_state._reset_box = True

        except (RateLimitError, APIError) as e:
            st.error(f"OpenAI API Error: {e.__class__.__name__}: {e}")

def show_scan_ui():
      
        # ── HEADER ─────────────────────────────────────────────────────
    logo_b64 = to_base64("assets/shield_pulse_dark.png")
    st.markdown(f"""
        <div style="background:rgba(255,255,255,0.05); padding:1rem; border-radius:8px; margin-bottom:1.5rem;">
            <div class="nichosec-header" style="text-align:center;">
                <img src="data:image/png;base64,{logo_b64}" width="250" style="margin-bottom:0.5rem;" />
                <h2 style="margin:0; color:#fff;">NichoSec V2 – AI Security Tool</h2>
                <p style="font-size:0.9rem; color:#ccc; margin-top:0.25rem;">
                    Local analysis. Private results. No cloud storage.
                </p>
            </div>
        </div>
    """, unsafe_allow_html=True)


    # ── IP THREAT INTELLIGENCE LOOKUP ───────────────────────────────
    with st.expander("IP Threat Intelligence Lookup", expanded=False):
        ip_input = st.text_input("Enter an IP address to check:", placeholder="e.g. 185.220.101.1")
        if st.button("Lookup IP") and ip_input:
            st.session_state.ip_result = lookup_ip_threat(ip_input)
            st.session_state.ip_geo    = get_ip_location(ip_input)

        if "ip_result" in st.session_state:
            result = st.session_state.ip_result
            geo    = st.session_state.ip_geo
            if "error" in result:
                st.error(result["error"])
            else:
                verdict, score = smarten_ip_verdict(result)
                st.markdown(f"### `{result['ip']}` → **{verdict}**")
                st.write(f"**Fraud Score:** `{score}`")
                with st.expander("Raw IP Data"):
                    st.json(result)


                # ── location + map ────────────────────────────────
                if geo.get("lat") and geo.get("lon"):
                    show_map = st.checkbox("📍 Show on map", key="ip_map_toggle")
                    if show_map:
                        st.map(
                            pd.DataFrame([{
                                "lat": float(geo["lat"]),
                                "lon": float(geo["lon"])
                            }]),
                            zoom=3, use_container_width=True
                        )
                        st.caption(f"ISP: {geo.get('asn') or geo.get('isp','')}")
                else:
                    # fallback text if we have city/country but no coords
                    if geo.get("city") or geo.get("country"):
                        st.write(f"**Location:** {geo.get('city','')} {geo.get('country','')}")
                    else:
                        st.caption("📍 No geo-location available for this IP.")

                # ── AbuseIPDB threat enrichment ─────────────────────────────────────
                abuse_data = abuseip_lookup(result['ip'])

                if abuse_data:
                    abuse_score = abuse_data.get("abuseConfidenceScore", 0)
                    categories = abuse_data.get("usageType", "") or "Unknown"

                    st.markdown(f"🔎 **AbuseIPDB Score:** `{abuse_score}`")
                    st.caption(f"🗂 Usage Type: {categories}")

                    if abuse_score >=70:
                        st.error("🚨 This IP is likely malicious.")
                    elif abuse_score >= 40:
                        st.warning("⚠️ Suspicious activity reported.")
                    elif abuse_score:
                        st.success("✅ No major abuse detected.")
                    # 🔍 AI single-line threat summary
                    summary = ai_threat_summary(result["ip"], abuse_data, geo)
                    st.caption(f"🧠 AI Insight: {summary}")
                else:
                    st.caption("No data from AbuseIPDB.")

    # ░░ UPLOAD / PASTE CARD ░░
    with st.container():
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        scan_clicked = False  

        uploaded = st.file_uploader(
            "Upload documents (bulk supported)",
            type=["pdf","txt","log","docx","csv","xlsx","xls","html","htm","eml"],
            key="uploader",
            accept_multiple_files=True
        )
        
        if uploaded:
            # Option to clear uploads
            if st.button("Clear uploaded files"):
                st.rerun()  #  Correct rerun method
            
            # If only one file was uploaded, offer single scan mode
            if len(uploaded) == 1:
                single_file = uploaded[0]
                st.success(f"Ready to scan: {single_file.name}")
                # maybe let them hit “Run Scan” and download PDF after that
            else:
                st.info(f"{len(uploaded)} files ready for bulk scan.")
            
        text_in = st.text_area("…or paste raw email / text here", height=150)
        scan_clicked = st.button("Run Scan", type="primary")
        
        st.markdown("</div>", unsafe_allow_html=True)

    # ── PHASE 1: Trigger the scan ─────────────────────────────────────────
    if scan_clicked:
        if not uploaded and not text_in.strip():
            st.warning("Please upload one or more files.")
        else:
            st.session_state.bulk_threats = []
            st.session_state.bulk_reports = []
            with st.spinner("Scanning all uploaded files…"):
                for file in uploaded:
                    name = file.name.lower()
                    st.session_state["last_raw"] = raw_input
        
                    save_result(name, report)
                    st.session_state.threat = report

                    pdf = make_pdf(report)
                    st.session_state.bulk_threats.append((name, report))
                    st.session_state.bulk_reports.append((f"{report['level']}_{name}.pdf", pdf))
            st.success(f"Scanned {len(st.session_state.bulk_threats)} files.")
    
    if st.session_state.get("bulk_threats"):
        st.write("### Bulk Scan Results")
        for name, report in st.session_state.bulk_threats:
            verdict = report.get("level", "YELLOW")
            summary = report.get("summary", "No summary provided.")
            color = {"GREEN":"#28a745","YELLOW":"#ffc107","RED":"#dc3545"}.get(verdict, "#6c757d")
            st.markdown(f"""
                <div style='border-left:6px solid {color}; padding:0.5rem 1rem; margin:0.75rem 0; background:rgba(255,255,255,0.06); border-radius:6px;'>
                <b>{name}</b> → <span style='color:{color}; font-weight:600;'>{verdict}</span><br>
                {summary}
                </div>
            """, unsafe_allow_html=True)

        
        zip_buffer = BytesIO()

        with ZipFile(zip_buffer, "w") as zipf:
            for fname, pdf_bytes in st.session_state.bulk_reports:
                zipf.writestr(fname, pdf_bytes)

        zip_data = zip_buffer.getvalue()

        # Only show ZIP download if multiple reports
        if len(st.session_state.bulk_reports) > 1:
            st.download_button(
                "⬇️ Download All Reports (ZIP)",
                data=zip_data,
                file_name="NichoSec_BulkReports.zip",
                mime="application/zip"
            )



    # ── PHASE 2: Always show results + export if we've scanned once ──
    threat = st.session_state.get("threat")
    if not threat:
        st.info("Run a scan first ⬆️")
        return
    # Basic unpack
    level     = threat.get("level", "YELLOW").upper()
    summary   = threat.get("summary", "No summary provided.")
    reasons   = threat.get("reasons", [])
    ips       = threat.get("ips", [])
    ip_scores = threat.get("ip_scores", {})
    t_sec     = threat.get("scan_time", 0.0)

    
    # Record into history
    history = st.session_state.get("history", [])
    history.append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "file": uploaded[0].name if uploaded and len(uploaded) > 0 else "pasted-text",
        "level":     level,
        "summary":   summary,
        "reasons":   " | ".join(reasons),
        "ips":       " | ".join(ips),
        "scan_time": t_sec,
        "full_json": threat,
    })
    st.session_state.history = history

    risk_label, color = {
        "GREEN":  ("Low Risk", "#28a745"),
        "YELLOW": ("Moderate Risk", "#ffc107"),
        "RED":    ("High Risk", "#dc3545"),
    }.get(level, ("Unknown Risk", "#6c757d"))

    if threat:   
        st.markdown(f"""
            <div style="
                border-left: 6px solid {color};
                padding: 0.75rem 1rem;
                margin: 0.5rem 0 1rem;
                background: rgba(255,255,255,0.08);
                border-radius: 6px;">
            <h4 style="margin-top:0;">
                <span style="color:{color};">{risk_label}</span> - {summary}
            </h4>

            <b>Reasons:</b>
            <ul>{''.join(f'<li>{r}</li>' for r in threat['reasons'])}</ul>
            <div style="font-size:0.85rem; margin-top:0.5rem;">
                ⏱ Scan time: {threat['scan_time']:.2f}s
            </div>
            <div style="font-size:0.9rem; margin-top:0.75rem; line-height:1.5;">
                <span style="font-weight:600; color:#ff66c4;">🧠 Threat Summary:</span>
                <span style="display:inline-block; margin-top:0.4rem;">
                    {re.sub(r'(?i)(misleading sender information|deceptive subject lines|suspicious links|storage service|unrealistic claims)', r'<b>\1</b>', threat.get("threat_summary", "N/A"))}
                </span>
            </div>
            </div>
        """, unsafe_allow_html=True)
        st.text_area(
            "📋 Copyable Threat Summary",
            value=threat.get("threat_summary", "N/A"),
            height=100,
            key="copy_threat_summary",
            help="You can copy and paste this into reports or tickets.",
            disabled=False
        )
        #MITRE TECHNIQUES
        if isinstance(threat.get("mitre_techniques"), list):
            st.write("### 🧩 MITRE ATT&CK Techniques")
            for m in threat["mitre_techniques"]:
                st.markdown(f"- `{m.get('id', '—')}` — {m.get('technique', '—')} (*{m.get('tactic', '—')}*)")
        
        if "hashes" in threat:
            st.write("### File Hashes")
            st.json(threat["hashes"])

            if st.button("🔎 Lookup in VirusTotal"):
                vt_result = virustotal_lookup(threat["hashes"]["sha256"])
                if "error" in vt_result:
                    st.error(f"VirusTotal error: {vt_result['error']}")
                else:
                    st.json(vt_result)
        
        if st.button("💣 Upload to Hybrid Analysis"):
            hybrid_result = upload_to_hybrid(raw, "file.eml")
            st.json(hybrid_result)

        if st.button("📥 Get Hybrid Report"):
            sha256 = threat.get("hashes", {}).get("sha256")
            if sha256:
                report = get_hybrid_report(sha256)
                st.json(report)


    st.write("### IP Reputation Details")

    for ip in ips:
        cols = st.columns([2, 1, 1, 2])
        cols[0].code(ip)

        # 🔄 Live threat lookup
        threat_info = lookup_ip_threat(ip)
        verdict = threat_info.get("verdict", "UNKNOWN")

        cols[1].write(verdict)

        ip_key = ip.replace(".", "-")

        if ip in SAFE_IPS:
            if cols[2].button("❌ Remove", key=f"remove-{ip_key}"):
                SAFE_IPS.remove(ip)
                save_safe_ips(SAFE_IPS)
                st.success(f"{ip} removed from safelist")
                st.rerun()
        else:
            if cols[2].button("➕ Safelist", key=f"safelist-{ip_key}"):
                SAFE_IPS.add(ip)
                save_safe_ips(SAFE_IPS)
                st.success(f"{ip} added to safelist")
                st.rerun()

        if org := ORG_IPS.get(ip):
            cols[3].caption(f"Used internally by **{org}**")

        # ⬇️ Optional: Show full live feed data
        with st.expander(f"ℹ️ More on {ip}", expanded=False):
            st.json(threat_info)



    # PDF bytes for export
    pdf_bytes = make_pdf(threat)
    if isinstance(pdf_bytes, bytearray):
        pdf_bytes = bytes(pdf_bytes)

    # Raw JSON expander
    with st.expander("Full raw JSON"):
        st.json(threat)

    # ── Consolidated Export ────────────────────────────────────────────────
    export_type = st.selectbox("Export as", ["PDF report","Latest scan JSON","Full history CSV"])
    # ➊  Create a timestamp once per export click
    timestamp = time.strftime("%Y%m%d_%H%M%S")     
    # pick your data + filename + mime based on the selection
    if export_type == "PDF report":
        data, fn, mime = pdf_bytes, f"{level}_{timestamp}.pdf", "application/pdf"
    elif export_type == "Latest scan JSON":
        data, fn, mime = json.dumps(threat, indent=2), "latest_scan.json", "application/json"
    else:
        df = pd.DataFrame(st.session_state.history)
        data, fn, mime = df.to_csv(index=False).encode(), "scan_history.csv", "text/csv"
    st.download_button(f"⬇️ Download {export_type}", data=data, file_name=fn, mime=mime)

    if st.button("⬇️ Download"):
        if export_type == "PDF report":
            st.download_button(
                "Download PDF report",
                data=pdf_bytes,
                file_name=f"{level}_{time.strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf",
            )
        elif export_type == "Latest scan JSON":
            st.download_button(
                "Download latest scan JSON",
                data=json.dumps(threat, indent=2),
                file_name="nch_latest_scan.json",
                mime="application/json",
            )
        else:  # Full history CSV
            df = pd.DataFrame(st.session_state.history)
            csv_bytes = df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "Download full history CSV",
                data=csv_bytes,
                file_name="nch_scan_history.csv",
                mime="text/csv",
            )

        
# ── DASHBOARD PAGE ─────────────────────────────────────────────────────
def show_dashboard():
    """Quick KPI + history table pulled from st.session_state.history."""
    st.title(" NichoSec – Dashboard")

    history = st.session_state.get("history", [])
    if not history:
        st.info("No scans yet – switch to *Scan* and run one.")
        return

    # 1️⃣ history → DataFrame
    df = pd.DataFrame(history)

    # 2️⃣ sort newest-first  ← ADD THIS LINE
    df = df.sort_values("timestamp", ascending=False).reset_index(drop=True)
    
    # KPI cards now use the sorted df
    reds   = int((df.level == "RED").sum())
    yells  = int((df.level == "YELLOW").sum())
    greens = int((df.level == "GREEN").sum())
    col1, col2, col3 = st.columns(3)
    col1.metric("🔴 Red",     reds)
    col2.metric("🟡 Yellow",  yells)
    col3.metric("🟢 Green",   greens)

    st.divider()

    # Recent scans table
    st.subheader("Recent Scans")
    st.dataframe(
        df[["timestamp", "file", "level", "summary", "scan_time"]],
        use_container_width=True,
        hide_index=True,
    )

    # drill-down dropdown – preselect row 0 (latest)
    idx = st.selectbox("View full report (row #)", df.index[::-1], index=0)
    row = df.loc[idx]

    st.markdown(f"### {row.file} — {row.level}")
    st.write("**Summary:**", row.summary)
    st.write("**Reasons:**")
    for r in row.reasons.split(" | "):
        st.write("•", r)
    st.write("**IPs:**", (row.ips or "—").replace(" | ", ", "))

# ── ROUTER (must be flush-left) ─────────────────────────────────────────
if page == "Dashboard":
    show_dashboard()
else:
    show_scan_ui()    

# FOOTER -----------------------------------------------------------
st.caption(
    "🔒 NichoSec V2 - Secure AI Threat Intelligence Tool | Local Scans, Private Results | ©2025 Addy Nicholson"
)
  
