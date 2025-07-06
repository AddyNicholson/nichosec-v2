# ── Bootstrap (keep this) ─────────────────────────────
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

print("🔍 NICHODEBUG:", __file__, "PROJECT_ROOT in path?", PROJECT_ROOT in map(Path, map(Path, sys.path)))

# ── Imports ────────────────────────────────────────────────────────────────
import os
import re
import base64
import socket
import ipaddress
import time
from datetime import datetime
from pathlib import Path

import fitz  # PyMuPDF
import requests
import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI

from fpdf import FPDF
from src.core.scan_engine import scan, Threat
import sys
print("PYTHONPATH:", sys.path)

# ── Session-state defaults ─────────────────────────────
if "shield_glow" not in st.session_state:
    st.session_state.shield_glow = False

if "scanning" not in st.session_state:        # new
    st.session_state.scanning = False         # new

if "run_scan_done" not in st.session_state:   # new
    st.session_state.run_scan_done = False    # new


# ── Paths -------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent.parent  # /project root
ASSETS_DIR = BASE_DIR / "assets"

# ── ENV / OpenAI -------------------------------------------------------------
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ── Helper functions ---------------------------------------------------------

def lookup_ip(ip: str) -> dict:
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8)
        return res.json() if res.status_code == 200 else {"error": f"Status {res.status_code}"}
    except Exception as exc:
        return {"error": str(exc)}

def extract_text_from_pdf(uploaded_file) -> str:
    try:
        with fitz.open(stream=uploaded_file.read(), filetype="pdf") as doc:
            return "".join(p.get_text() for p in doc)
    except Exception as exc:
        return f"[PDF error] {exc}"

def set_bg_from_local(img_path: Path):
    if not img_path.exists():
        return
    encoded = base64.b64encode(img_path.read_bytes()).decode()
    st.markdown(
        f"<style>.stApp::before{{content:'';position:fixed;inset:0;background:url(data:image/png;base64,{encoded}) center/22% no-repeat;opacity:0.05;z-index:-1;pointer-events:none}}</style>",
        unsafe_allow_html=True,
    )

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def valid_public_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback)
    except ValueError:
        return False

def extract_ips(text: str):
    return {ip for ip in IPV4_RE.findall(text) if valid_public_ip(ip)}

@st.cache_data(ttl=3600)
def cached_lookup(addr: str):
    return lookup_ip(addr)
from email import policy
from email.parser import BytesParser

def extract_text_from_eml(uploaded_file) -> str:
    """
    Parse a .eml email file and return the plain-text body.
    """
    try:
        msg = BytesParser(policy=policy.default).parse(uploaded_file)
        body = msg.get_body(preferencelist=("plain",))
        return body.get_content() if body else msg.get_content()
    except Exception as exc:
        return f"[EML parse error] {exc}"

#   NEW HELPER BLOCK 

import re, urllib.parse, tldextract

SAFE_HEADERS = {
    "delivered-to","received","x-received","arc-seal","arc-message-signature",
    "arc-authentication-results","return-path","authentication-results",
    "received-spf","dkim-signature","x-google-dkim-signature",
    "x-gm-","x-google-","x-sg-","x-feedback-id","x-mailer",
    "list-unsubscribe","list-unsubscribe-post","errors-to",
    "content-type","content-transfer-encoding","mime-version",
    "boundary=","content-id","message-id"
}

PHISH_RE   = re.compile(r"(confirm|verify)\s+(your|my)\s+(account|identity)", re.I)
MONEY_RE   = re.compile(r"\$\s?\d{1,3}(?:[,.\d]{3,})", re.I)
SUSP_LINK  = re.compile(r"https?://[^\s]*(linodeobjects|s3\.amazonaws|bit\.ly|tinyurl)\.", re.I)
SCRIPT_RE  = re.compile(r"(?:<script|javascript:|document\.getelementsby)", re.I)
BASE64_RE  = re.compile(r"data:image/.+;base64", re.I)
WORD_RE    = re.compile(r"\b(unauthorized|malicious|exploit|ransomware)\b", re.I)

def header_value(full: str, name: str):
    m = re.search(rf"^{name}:\s*(.+)$", full, re.I | re.M)
    return m.group(1).strip() if m else ""

def scan_email(text: str, ip_hint: str | None = None):
    flagged, found_ips = [], extract_ips(text)
    if ip_hint:
        found_ips.add(ip_hint.strip())

    # ----- spoofed-sender / reply-to checks  (needs tldextract)
    from_hdr  = header_value(text, "from")
    reply_hdr = header_value(text, "reply-to")

    sender_addr  = re.sub(r".*<|>.*", "", from_hdr)            # user@gmail.com
    display_name = re.sub(r"<.*",   "", from_hdr).strip()      # ieeexplore[ieee]org

    def reg_domain(addr_or_url: str) -> str:
        host = re.sub(r".*@", "", addr_or_url)                 # strip user@
        return tldextract.extract(host).registered_domain      # gmail.com, ieee.org …

    sender_dom  = reg_domain(sender_addr)
    display_dom = reg_domain(display_name)
    reply_dom   = reg_domain(reply_hdr) if reply_hdr else ""

    if sender_dom and display_dom and sender_dom != display_dom:
        flagged.append("🔴 [High] Display-name domain ≠ sender address domain")

    if reply_dom and reply_dom != sender_dom:
        flagged.append("🟡 [Medium] Reply-To domain differs from From address")

    # ----- line-by-line inspection
    for ln in text.splitlines():
        ll = ln.lower().lstrip(": \t")

        if any(ll.startswith(h) for h in SAFE_HEADERS):
            continue
        if BASE64_RE.search(ll) and len(ll) > 200:
            continue
        if ll.startswith(("--=_mimepart", "--_")):
            continue

        if SCRIPT_RE.search(ll) or SUSP_LINK.search(ll) or PHISH_RE.search(ll):
            flagged.append(f"🔴 [High] {ln.strip()}")
            continue
        if MONEY_RE.search(ll) and "cashapp" in ll:
            flagged.append(f"🔴 [High] {ln.strip()}")
            continue
        if WORD_RE.search(ll):
            flagged.append(f"🟡 [Medium] {ln.strip()}")

    # ----- IP reputation look-ups
    ip_results = {}
    for ip in found_ips:
        info = cached_lookup(ip)
        rep  = info.get("reputation", "unknown")
        info["risk"] = "bad" if rep == "bad" else "warn" if rep in ("suspicious","unknown") else "ok"
        ip_results[ip] = info

    counts = (
        sum(l.startswith("🔴") for l in flagged),
        sum(l.startswith("🟡") for l in flagged),
        0   # not collecting lows
    )
    return flagged, ip_results, counts, datetime.now().strftime("%Y-%m-%d %H:%M:%S")



# ── UI setup -----------------------------------------------------------------
st.set_page_config("NichoSec", layout="wide", initial_sidebar_state="expanded")
set_bg_from_local(ASSETS_DIR / "nichosec_bg.png")

css_path = ASSETS_DIR / "styles.css"
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)

# ── Sidebar ------------------------------------------------------------------
st.sidebar.markdown("### NichoSec Security Panel")

shield_path = ASSETS_DIR / "shield.png"           # brain-in-shield cut-out
if shield_path.exists():
    import base64, textwrap, pathlib
    b64 = base64.b64encode(shield_path.read_bytes()).decode()

    # one div → relative; two <img> stacked
    st.sidebar.markdown(
        textwrap.dedent(f"""
        <style>
          /* wrapper keeps overlay aligned */
          #nichosecLogoWrap {{ position:relative; width:140px; margin:0 auto 1rem; }}

          /* base (static) layer */
          #nichosecLogoWrap .shield-base {{
              width:140px; height:auto; display:block;
              filter:brightness(1);          /* normal */
          }}

          /* animated glow / scan layer */
          #nichosecLogoWrap .shield-anim {{
              position:absolute; top:0; left:0;
              width:140px; height:auto;
              animation: glowSweep 2s linear infinite;
          }}

          /* key-frames pulled from your CSS file */
          @keyframes glowSweep {{
              0%   {{ box-shadow:0 0 5px rgba(255,255,255,.6); }}
              50%  {{ box-shadow:0 0 20px rgba(255,255,255,1); }}
              100% {{ box-shadow:0 0 5px rgba(255,255,255,.6); }}
          }}
        </style>

        <div id="nichosecLogoWrap">
            <!-- base icon -->
            <img src="data:image/png;base64,{b64}" class="shield-base" alt="NichoSec Shield" />
            <!-- overlay / glow -->
            <img src="data:image/png;base64,{b64}" class="shield-anim" alt="NichoSec Shield Scan" />
        </div>
        """),
        unsafe_allow_html=True
    )


# ── Sidebar controls ───────────────────────────────────────
model         = st.sidebar.selectbox("AI model", ["gpt-4o", "gpt-3.5-turbo"])
uploaded_file = st.sidebar.file_uploader("Upload file", type=["pdf", "txt", "log", "docx"])
user_text     = st.sidebar.text_area("Paste email / text")
ip_input      = st.sidebar.text_input("IP / domain")
custom_cmd    = st.sidebar.text_input("Custom command")

# ── ONE run-scan button (this fires the scan AND the glow) ─
run_btn = st.sidebar.button("Run Scan", key="run_scan_btn")
if run_btn and not st.session_state.get("scanning", False):
    st.session_state.do_scan   = True      # ← triggers the scan block
    st.session_state.scanning  = True      # ← tells the UI to glow
    st.session_state.shield_glow = True
    st.rerun()                             # redraw sidebar so glow starts


# ── Glow / flash JS hooks  (UI only, no reruns) ─────────────
if st.session_state.get("scanning"):
    # glow while scan is running
    st.markdown(
        """
        <script>
          const logo = document.querySelector('.shield-anim');
          if (logo) logo.classList.add('scanning');
        </script>
        """,
        unsafe_allow_html=True,
    )

elif st.session_state.get("run_scan_done"):
    # one-off flash after scan finishes
    st.markdown(
        """
        <script>
          const logo = document.querySelector('.shield-anim');
          if (logo) {
            logo.classList.add('shield-flash');
            setTimeout(() => logo.classList.remove('shield-flash'), 600);
          }
        </script>
        """,
        unsafe_allow_html=True,
    )
    # reset so next scan can flash again
    st.session_state.run_scan_done = False

    st.markdown("""
    <script>
      const logo = document.querySelector('.shield-anim');
      if (logo) {
        logo.classList.remove('scanning');      // stop the loop
        logo.classList.add('shield-flash');     // play one-off flash
        setTimeout(()=>logo.classList.remove('shield-flash'), 600);
      }
    </script>
    """, unsafe_allow_html=True)


import time
import streamlit as st
# … your other imports …

# ── 0️⃣  RUN-SCAN BUTTON ─────────────────────────────────────────
run_btn = st.button("Run Scan", key="run_scan_btn")
if run_btn:
    st.session_state.do_scan = True            # single source of truth


# ── 1️⃣  SCAN + STORE (fires once per click) ────────────────────
if st.session_state.get("do_scan"):

    # pull raw text from upload / textbox
    raw_text = get_input_text(uploaded_file, user_text)   # ← keep your helper

    # run the scan
    with st.spinner("🛡️ Running threat analysis…"):
        t0 = time.perf_counter()
        threat: Threat = scan(raw_text, ip_input)
        elapsed = round(time.perf_counter() - t0, 3)

    # stash everything for later renders
    st.session_state.last_threat  = threat
    st.session_state.last_elapsed = elapsed
    st.session_state.flagged      = getattr(
        threat, "flagged", getattr(threat, "details", [])
    )

    # grow history list
    history = st.session_state.get("scan_history", [])
    history.append({
        "timestamp": threat.metadata.get("timestamp", "—"),
        "risk":      threat.risk,
        "sha256":    threat.sha256,
        "elapsed":   elapsed,
    })
    st.session_state.scan_history = history

    # reset flag so scan doesn’t rerun on every redraw
    st.session_state.do_scan = False


# ── 2️⃣  DISPLAY (runs every rerun, needs stored result) ─────────
if "last_threat" in st.session_state:
    threat  = st.session_state.last_threat
    elapsed = st.session_state.last_elapsed
    flagged = st.session_state.flagged

    st.success(f"⏱️ Scan completed in {elapsed}s")

    st.markdown(
        f"#### <Threat {threat.risk.upper()} sha={threat.sha256[:7]}>",
        unsafe_allow_html=True,
    )
    st.json({
        "risk":        threat.risk,
        "campaign_id": threat.campaign_id,
        "sha256":      threat.sha256,
        "timestamp":   threat.metadata.get("timestamp"),
    })

    # flagged indicators
    if flagged:
        st.error("🚨 Potential threats detected:")
        text = flagged if isinstance(flagged, str) else "\n".join(map(str, flagged))
        st.code(text)
    else:
        st.success("✅ No obvious threats found.")

# ── Tabs ---------------------------------------------------------------------
TAB_DASH, TAB_CHAT, TAB_LOGS, TAB_IP, TAB_REPORTS = st.tabs(
    ["Dashboard", "Chat", "Logs", "IP Lookup", "Reports"]
)
# ── Outside / below the scan-block ──────────────────────────
if "last_threat" in st.session_state:
    threat   = st.session_state["last_threat"]
    elapsed  = st.session_state["last_elapsed"]

    st.success(f"⏱️ Scan completed in {elapsed}s")
    st.markdown(
        f"#### <Threat {threat.risk.upper()} sha={threat.sha256[:7]}>",
        unsafe_allow_html=True,
    )
    st.json({
        "risk":        threat.risk,
        "campaign_id": threat.campaign_id,
        "sha256":      threat.sha256,
        "timestamp":   threat.metadata.get("timestamp"),
    })

# --- Dashboard ---------------------------------------------------------------
with TAB_DASH:
    st.subheader("Threat Summary")
    st.markdown("""
#### 🛡️ Severity Legend
- 🔴 **High** – Known threats, malware, unauthorized access, ransomware indicators  
- 🟡 **Medium** – Failed logins, denied access, error messages  
- 🟢 **Low** – Info-only, no known threat keywords
""")

# ── First render: no scan yet ────────────────────────────────────────────
if "scan_text" not in st.session_state:
    st.info("Upload a file and click **Run Scan**.")
else:
    # Pull everything from session safely (fallbacks avoid NameErrors)
    flagged    = st.session_state.get("flagged", [])
    ip_results = st.session_state.get("ip_results", {})
    last_chk   = st.session_state.get("last_checked", "—")

    # Card colour depends on whether anything was flagged
    css_cls = "threat" if flagged else "safe"
    st.markdown(f'<div class="card {css_cls}">', unsafe_allow_html=True)

    # Flagged lines (or a clean bill of health)
    if flagged:
        st.error("🚨 Potential threats detected:")

        # Normalise flagged → multiline string
        if isinstance(flagged, str):                        # single summary string
            text = flagged.strip()
        elif isinstance(flagged, (list, tuple, set)):       # list/tuple of hits
            text = "\n".join(map(str, flagged))
        else:                                               # any other object
            text = str(flagged)

        st.code(text)  # or st.text_area(text, height=200)
    else:
        st.success("✅ No obvious threats found.")

    st.markdown("</div>", unsafe_allow_html=True)   # ← closes the card div


# --- Chat ---------------------------------------------------------------
with TAB_CHAT:
    st.subheader("NichoSec GPT")

    # Ensure the chat list exists (avoids NameError on first run)
    if "messages" not in st.session_state:
        st.session_state.messages = [
            {"role": "assistant", "content": "How can I help today?"}
        ]

    # Render chat history
    for m in st.session_state.messages:
        st.chat_message(m["role"]).markdown(m["content"])

    # 🗣️ 1)  get new user text (None if nothing entered)
    user_msg = st.chat_input(placeholder="Type a prompt…")

    # 🏷️ 2)  only run the API call if the user actually typed something
    if user_msg:
        st.session_state.messages.append({"role": "user", "content": user_msg})

        with st.spinner("Thinking…"):
            try:
                resp = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "system",
                               "content": "You are a concise cybersecurity assistant."}]
                             + st.session_state.messages[-15:]
                )
                assistant_reply = resp.choices[0].message.content
            except Exception as e:
                assistant_reply = f"⚠️ OpenAI error: {e}"

        st.session_state.messages.append({"role": "assistant", "content": assistant_reply})

        # ⬇️ 3)  show the new assistant answer immediately (no rerun needed)
        st.chat_message("assistant").markdown(assistant_reply)

# --- Logs --------------------------------------------------------------------
with TAB_LOGS:
    st.subheader("Log Scanner (manual paste)")
    pasted_logs = st.text_area("Paste logs here", height=200)
    if st.button("Analyze Logs"):
        if not pasted_logs.strip():
            st.warning("No log data pasted.")
        else:
            st.code(pasted_logs[:600])

# --- IP lookup ---------------------------------------------------------------
with TAB_IP:
    st.subheader("🌐 IP / Domain Lookup")
    prefill = ""
    if "ip_results" in st.session_state and st.session_state.ip_results:
        bads = [ip for ip, d in st.session_state.ip_results.items() if d["risk"] == "bad"]
        prefill = bads[0] if bads else next(iter(st.session_state.ip_results))

    raw_input = st.text_input("Enter IP or domain", value=prefill)
    lookup_trigger = st.button("🔎 Lookup") or (raw_input and prefill and raw_input == prefill)

    if lookup_trigger and raw_input:
        try:
            ip_addr = raw_input if ipaddress.ip_address(raw_input) else socket.gethostbyname(raw_input)
        except Exception as exc:
            st.error(f"❌ Invalid address: {exc}")
            st.stop()

        data = cached_lookup(ip_addr)

        if "ip" in data:
            rep = data.get("reputation", "unknown")
            rep_icon = {"good": "✅", "suspicious": "🟡", "bad": "🔴", "unknown": "❔"}.get(rep, "❔")
            lat, lon = map(float, data.get("loc", "0,0").split(",")[:2])

            st.markdown(f"""
            **IP**: `{data['ip']}` {rep_icon}  
            **Location**: {data.get('country')}, {data.get('region')}, {data.get('city')}  
            **Org**: {data.get('org','N/A')}  
            **Coords**: {lat}, {lon}
            """)
            st.map([{"lat": lat, "lon": lon}])
        else:
            st.error("❌ Could not fetch IP details.")

# ▸ Reports Tab
with TAB_REPORTS:
    st.subheader("📑 Scan History & Reports")

    if not st.session_state.get("scan_history"):
        st.info("No past scans yet.")
    else:
        for idx, scan in enumerate(reversed(st.session_state["scan_history"]), 1):
            with st.expander(f"🔍 Scan #{idx} — {scan['timestamp']}"):
                flags = scan.get("flagged", [])
                st.code("\n".join(flags) if flags else "✅ No threats found")

                # Download buttons
                col1, col2, col3 = st.columns(3)
                col1.download_button("⬇ TXT", scan["raw_text"], file_name=f"nichosec_scan_{idx}.txt")
                col2.download_button("⬇ CSV", "\n".join(scan["flagged"]), file_name=f"nichosec_scan_{idx}.csv")
                col3.download_button("⬇ JSON", str(scan), file_name=f"nichosec_scan_{idx}.json")


# --- Status bar --------------------------------------------------------------
st.markdown('<div class="status-bar"></div>', unsafe_allow_html=True)
