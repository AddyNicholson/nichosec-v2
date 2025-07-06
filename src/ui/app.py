# ── bootstrap: make project root importable ────────────────────────────
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]   # …/NichoSec
if str(PROJECT_ROOT) not in sys.path:                # avoid duplicates
    sys.path.insert(0, str(PROJECT_ROOT))            # prepend to be safe
# ────────────────────────────────────────────────────────────────────────

# ── standard / third-party libs ───────────────────────────────────────
import os, json, re, base64, ipaddress, imaplib, email, tempfile, time
from io import BytesIO
import urllib.parse as up

import fitz                     # PyMuPDF
import pandas as pd
import requests
from bs4 import BeautifulSoup
from docx import Document
import streamlit as st
from openai import APIError, RateLimitError
from dotenv import load_dotenv   # ← add

load_dotenv()                    # ← pulls NICHOSEC_APP_KEY from .env

# ── project modules ───────────────────────────────────────────────────

from src.core.prompting   import NCHOSEC_SYSTEM_PROMPT
from src.core.openai_client import client
from src.core.scan_engine   import scan
from src.core.extractors    import extract_text
from src.core.reports       import make_pdf
  


# ── UTILITIES ─────────────────────────────────────────────────────────────

def to_base64(path: str) -> str:
    """Return base‑64 of a local file or empty string if not found."""
    p = Path(path)
    return base64.b64encode(p.read_bytes()).decode() if p.exists() else ""


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


# ── UI CONFIG ─────────────────────────────────────────────────────────────
st.set_page_config(page_title="NichoSec | Local Threat Scanner",
                   page_icon="assets/shield_logo_exact.png", layout="centered")

# ── AUTHENTICATION + ROLES ─────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()                                          # .env → env vars

################################################################################
# 1)  Credentials + roles
#     Either hard-code here *or* keep only the keys and read the passwords
#     from environment variables so nothing sensitive sits in git.
################################################################################
USERS = {
    #  user      : (password                      , role )
    "addy"      : (os.getenv("PWD_addy")   or "EmeelaNich022025", "admin"),
    "tester"    : (os.getenv("PWD_tester") or "Test123",          "user"),
    # add more…
}

def authenticate(u: str, p: str):
    """Return the user’s role if credentials match, else None."""
    creds = USERS.get(u.lower().strip())
    if creds and p == creds[0]:
        return creds[1]              # e.g. "admin"
    return None

################################################################################
# 2)  Persist auth info in Session State
################################################################################
st.session_state.setdefault("auth" , False)
st.session_state.setdefault("user" , None)
st.session_state.setdefault("role" , None)

if not st.session_state.auth:
    st.title("🔐 NichoSec Login")

    c1, c2 = st.columns(2)
    u = c1.text_input("Username")
    p = c2.text_input("Password", type="password")

    if st.button("Unlock"):
        role = authenticate(u, p)
        if role:                                   # ✔ valid
            st.session_state.update(
                {"auth": True, "user": u, "role": role}
            )
            st.rerun()
        else:                                      # ✘ invalid
            st.error("❌ Invalid credentials")
            st.stop()
    else:
        st.stop()

################################################################################
# 3)  Sidebar badge + Logout
################################################################################
with st.sidebar:
    st.markdown(f"👤 **{st.session_state.user}**  ({st.session_state.role})")
    if st.button("🔓 Log out"):
        for k in ("auth", "user", "role"):
            st.session_state.pop(k, None)
        st.rerun()

# ── SIDEBAR NAVIGATION + BACKGROUND IMAGE ────────────────────────────────
st.sidebar.title("🛡️ NichoSec")
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
# ── 3️⃣  Email Loader sidebar (beta) ──────────────────────────────────────
def list_emails(host, user, pw, num=20):
    box = imaplib.IMAP4_SSL(host)
    box.login(user, pw); box.select("INBOX")
    _, data = box.search(None, "ALL")
    uids = data[0].split()[-num:]
    rows = []
    for uid in reversed(uids):
        _, msg_data = box.fetch(uid, "(RFC822.HEADER)")
        msg = email.message_from_bytes(msg_data[0][1])
        rows.append((uid, msg["Subject"], msg["From"], msg["Date"]))
    box.logout()
    return rows

def fetch_email(host, user, pw, uid):
    box = imaplib.IMAP4_SSL(host)
    box.login(user, pw); box.select("INBOX")
    _, msg_data = box.fetch(uid, "(RFC822)")
    box.logout()
    return email.message_from_bytes(msg_data[0][1])

with st.sidebar.expander("📥  Email Loader (beta)"):
    st.info(
        "📥 **Email Loader is in beta** – Currently supports Gmail only via IMAP and App Passwords. "
        "You'll need to enable IMAP in your Gmail settings and [generate an App Password]"
        "(https://support.google.com/accounts/answer/185833). "
        "We're exploring simpler, more secure login options like OAuth in future versions.",
        icon="ℹ️"
    )

    host = st.text_input("IMAP host", "imap.gmail.com")
    user = st.text_input("Email address")
    pw   = st.text_input("Password / App-PW", type="password")

    if st.button("Connect"):
        try:
            st.session_state.email_list = list_emails(host, user, pw)
            st.session_state.imap_creds = (host, user, pw)
            st.success(f"Fetched {len(st.session_state.email_list)} messages")
        except Exception as e:
            st.error(f"IMAP error: {e}")

    if "email_list" in st.session_state:
        for uid, subj, sender, date in st.session_state.email_list:
            if st.button(f"🛡️ Scan: {subj[:60]}", key=uid):
                host, user, pw = st.session_state.imap_creds
                msg = fetch_email(host, user, pw, uid)

                # --- extract plain text + attachments ---------------------
                raw_text, attachments = "", []
                for part in msg.walk():
                    ctype = part.get_content_type()
                    if ctype == "text/plain":
                        raw_text += part.get_payload(decode=True).decode(errors="ignore")
                    elif part.get_filename():
                        tmp = tempfile.NamedTemporaryFile(delete=False)
                        tmp.write(part.get_payload(decode=True)); tmp.close()
                        attachments.append(tmp.name)

                # --- call your existing scan() routine --------------------
                data = scan(raw_text, purge=False)     # keep purge toggle
                st.write(data)                         # replace with pretty UI
                # You can loop over attachments and call scan_file(...) here

# ░░  SIDEBAR – AI helper  ░░───────────────────────────────────────────────
with st.sidebar.expander("🤖  Ask NichoSec AI", expanded=False):

    # 0️⃣  Reset input box if last run asked for it
    if st.session_state.pop("_reset_box", False):
        st.session_state.pop("chat_box", None)

    # 1️⃣  Initialise chat history (only once)
    if "chat" not in st.session_state:
        st.session_state.chat = [
            {"role": "system",    "content": NCHOSEC_SYSTEM_PROMPT},
            {"role": "assistant", "content":
                "Hello! I'm here to help with any email- or file-threat analysis. "
                "Paste a suspicious email, file or IP and I’ll assess the risk."},
        ]

    # 2️⃣  Model picker
    model_name = st.radio(
        "Model", ["gpt-3.5-turbo", "gpt-4o-mini"],
        index=1, horizontal=True,
        format_func=lambda m: "GPT-3.5" if m.startswith("gpt-3.5") else "GPT-4o-mini",
    )

    # 3️⃣  Clear-chat button
    if st.button("🗑️  Clear chat"):
        st.session_state.pop("chat", None)
        st.rerun()

    # 4️⃣  Show history (skip system message)
    for msg in st.session_state.chat:
        if msg["role"] == "system":
            continue
        icon = "🧑‍💻" if msg["role"] == "user" else "🤖"
        st.markdown(f"**{icon}** {msg['content']}")

    # 5️⃣  Prompt box
    prompt = st.text_input(
        "Ask NichoSec AI:",
        key="chat_box",
        placeholder="Your security question…",
    )

    # 6️⃣  Send button ─ all code below **must** stay indented!
    if st.button("Send", key="chat_send") and prompt.strip():
        # 6-a  Append user turn
        st.session_state.chat.append({"role": "user", "content": prompt})

        # 6-b  MEMORY MODE → keep first system turn + last ≤10 non-system turns
        trimmed_history = [st.session_state.chat[0]] + st.session_state.chat[-10:]

        try:
            resp = client.chat.completions.create(
                model=model_name,
                messages=trimmed_history,
                temperature=0.3,
                stream=True,
            )

            placeholder, assistant_reply = st.empty(), ""
            with st.spinner("NichoSec is thinking…"):
                for chunk in resp:
                    assistant_reply += chunk.choices[0].delta.content or ""
                    placeholder.markdown(f"**🤖** {assistant_reply}")

            # 6-c  Store reply, trim master history the same way
            st.session_state.chat.append(
                {"role": "assistant", "content": assistant_reply}
            )
            st.session_state.chat = [st.session_state.chat[0]] + st.session_state.chat[-10:]

            # Tell next run to clear the textbox
            st.session_state._reset_box = True

        except (RateLimitError, APIError) as e:
            st.error(f"OpenAI error – {e.__class__.__name__}: {e}")
# ── SCAN PAGE (wrap everything) ────────────────────────────────────────
def show_scan_ui():
    st.write("🟢 scan ui fired")
    
    # ── HEADER ----------------------------------------------------------------
    logo_b64 = to_base64("assets/shield_logo_exact.png")
    st.markdown(
        f"""
        <div class="nichosec-header">
          <img src="data:image/png;base64,{logo_b64}" width="64" />
          <h1>NichoSec V1 - Local Threat Scanner</h1>
        </div>
        """,
        unsafe_allow_html=True
    )

    # ░░ UPLOAD / PASTE CARD ░░
    with st.container():
        st.markdown("<div class='card'>", unsafe_allow_html=True)

        uploaded = st.file_uploader(
            "Upload document",
            type=["pdf","txt","log","docx","csv","xlsx","xls","html","htm","eml"],
            key="uploader",
        )

        text_in  = st.text_area("…or paste raw email / text here", height=150)
        purge_on = st.checkbox("🔌 Enable Purge Plugin (experimental)")

        if purge_on:
            st.caption(
                "The purge plug-in removes lines containing sensitive keywords like "
                "`seed phrase`, `wire transfer`, or `password` from the text before exporting."
            )

        # 👉 scan button lives inside the same <div class='card'>
        scan_clicked = st.button("🛡️ Run Scan", type="primary")

        st.markdown("</div>", unsafe_allow_html=True)   # ← close card here

    # 🚦 handle click
    if scan_clicked:
        if not uploaded and not text_in.strip():
            st.warning("Please upload a file or paste some text.")
        else:
            with st.spinner("Scanning…"):
                raw_text = extract_text(uploaded) if uploaded else text_in
                st.session_state.threat = scan(raw_text, purge_on)

    # ── OUTPUT AREA ──────────────────────────────────────────────────
    threat = st.session_state.get("threat")
    if threat:
        # ------- colour + icon by level ------------------------------
        level = threat.get("level", "YELLOW").upper()
        icon, color = {
            "GREEN":  ("🟢", "#28a745"),
            "YELLOW": ("🟡", "#ffc107"),
            "RED":    ("🔴", "#dc3545"),
        }.get(level, ("❔", "#6c757d"))

        summary = threat.get("summary", "No summary provided.")
        reasons = threat.get("reasons", [])
        ips     = threat.get("ips", [])
        t_sec   = threat.get("scan_time", 0)

        # ░░ RECORD SCAN IN SESSION HISTORY ░░
        history = st.session_state.get("history", [])
        history.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "file": uploaded.name if uploaded else "pasted-text",
            "level": level,
            "summary": summary,
            "reasons": " | ".join(reasons),
            "ips": " | ".join(ips),
            "scan_time": t_sec,
            "full_json": threat,
        })
        st.session_state.history = history

        # ------------ pretty result card -----------------------------
        st.markdown(f"""
        <div style="
            border-left: 6px solid {color};
            padding: 0.75rem 1rem;
            margin: 0.5rem 0 1rem 0;
            background: rgba(255,255,255,0.08);
            border-radius: 6px;">
            <h4 style="margin-top:0;">
                {icon} <span style="color:{color};">{level}</span> – {summary}
            </h4>

            <b>Reasons:</b>
            <ul>{''.join(f'<li>{r}</li>' for r in reasons) or '<li>—</li>'}</ul>

            <b>IPs:</b><br>
            {('<br>'.join(
                f'<a href="https://ipinfo.io/{ip}" target="_blank"><code>{ip}</code></a>'
                for ip in ips) if ips else '—')}

            <div style="font-size:0.85rem; margin-top:0.5rem;">
                ⏱ Scan time: {t_sec:.2f}s
            </div>
        </div>
        """, unsafe_allow_html=True)
      
       # ⬇️ PDF DOWNLOAD BUTTON --------------------------------------
        try:
            pdf_bytes = make_pdf(threat)
            if isinstance(pdf_bytes, bytearray):
                pdf_bytes = bytes(pdf_bytes)

            # 🔑 convert bytearray → bytes
            if not isinstance(pdf_bytes, bytes):
                raise TypeError("PDF data is not valid binary")

            st.download_button(
                "⬇️ Download PDF report",
                data=pdf_bytes,
                file_name=f"{level}_{time.strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf",
            )
       
        except Exception as e:
            st.error(f"PDF generation failed: {e}")

        # 👉 Raw JSON behind an expander
        with st.expander("📑 Full raw JSON"):
            st.json(threat)
       
        # Purged text download
        if purge_on and "cleaned" in threat:
            st.download_button(
                "⬇️ Download Purged Text",
                threat["cleaned"],
                file_name="nichosec_purged.txt",
                mime="text/plain",
            )

        # IP details
        if ips:
            with st.expander(f"🌐 IP info ({len(ips)})"):
                for ip in ips:
                    st.write(ip, lookup_ip(ip).get("org", ""))
         # FOOTER -----------------------------------------------------------
    st.caption(
        "NichoSec V1 – Local security, zero cloud storage. ©2025 Addy Nicholson"
    )
# ── DASHBOARD PAGE ─────────────────────────────────────────────────────
def show_dashboard():
    """Quick KPI + history table pulled from st.session_state.history."""
    import pandas as pd
    st.title("📊 NichoSec – Dashboard")

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

   
