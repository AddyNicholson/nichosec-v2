import os, time, json, re, base64, mimetypes, ipaddress, imaplib, email, tempfile, io
from pathlib import Path
import urllib.parse as up
import requests
import fitz           # PyMuPDF
from streamlit.components.v1 import html           
from docx import Document
import pandas as pd                              
from bs4 import BeautifulSoup                    
import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI, APIError, RateLimitError

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
import base64

def to_base64(path):
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()
# put this somewhere near the top of the file
uri = "ui/background.png"   # make sure the file exists

# ── PAGE CONFIG & BACKGROUND ───────────────────────────────────────────────
st.set_page_config(
    page_title="NichoSec | Local Threat Scanner",
    page_icon="assets/shield_logo_exact.png",
    layout="centered"
)
from pathlib import Path
import imaplib, email, tempfile, io

# ── 2️⃣  Key-features list ────────────────────────────────────────────────
st.markdown(
    """
    <div style='text-align:center; font-size:0.95rem; line-height:1.45;'>
      • <b>Upload&nbsp;file</b> <i>or</i> paste text → one-click scan<br>
      • Secure GPT-4o-mini analysis using a hardened AI prompt
      
      • Heuristic keyword pre-filter (<span style='color:#ff5252;'>instant RED</span>)<br>
      • Optional purge plug-in<br>
      • Email Loader (beta) for scanning Gmail messages directly
      • Runs 100 % locally — no cloud storage
    </div>
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

    # --- clear the input if last run told us to ------------------
    if st.session_state.get("_reset_box"):
        st.session_state.chat_box = ""
        st.session_state._reset_box = False    # toggle back

    # 1️⃣  init chat history
    if "chat" not in st.session_state:
        st.session_state.chat = [
            {"role": "system",
             "content": "You are NichoSec, a concise cybersecurity assistant."}
        ]

    # 2️⃣  model picker
    model_name = st.radio(
        "Model", ["gpt-3.5-turbo", "gpt-4o-mini"],
        index=1, horizontal=True,
        format_func=lambda m: "GPT-3.5" if m.startswith("gpt-3.5") else "GPT-4o-mini",
    )

    # 3️⃣  clear-chat button
    if st.button("🗑️  Clear chat"):
        st.session_state.pop("chat", None)
        st.session_state.pop("chat_box", None)
        st.rerun()

    # 4️⃣  show history
    for m in st.session_state.chat[1:]:
        icon = "🧑‍💻" if m["role"] == "user" else "🤖"
        st.markdown(f"**{icon}** {m['content']}")

    # 5️⃣  prompt box
    prompt = st.text_input(
        "Ask about phishing, threats, logs …",
        key="chat_box",
        placeholder="e.g. How do I spot a spoofed domain?",
    )

    # 6️⃣  send button
    if st.button("Send", key="chat_send") and prompt.strip():
        st.session_state.chat.append({"role": "user", "content": prompt})

        from openai import APIError, RateLimitError

        try:
            resp = client.chat.completions.create(
                model=model_name,
                messages=st.session_state.chat,
                temperature=0.3,
                stream=True,
            )

            placeholder = st.empty()
            answer = ""
            with st.spinner("NichoSec is thinking…"):
                for chunk in resp:
                    delta = chunk.choices[0].delta.content or ""
                    answer += delta
                    placeholder.markdown(f"**🤖** {answer}")

            st.session_state.chat.append({"role": "assistant", "content": answer})
            st.session_state._reset_box = True   # ← tell next run to clear box
            st.rerun()

        except (RateLimitError, APIError) as e:
            st.error(f"OpenAI error – {e.__class__.__name__}: {e}")


# ── IMPORTS & ENV ──────────────────────────────────────────────────────────
import os, time, json, re, base64, mimetypes, fitz, requests, streamlit as st
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI
from openai import RateLimitError, APIError

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

PHISH_KEYWORDS = [
    "bonus", "credit", "jackpot", "confirm transfer", "confirm now",
    "verify account", "$", "usd", "eu-central-1.linodeobjects"
]

# ---------------------------------------------------------------- JSON safe-parse
def parse_json(s: str) -> dict:
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

# ---------------------------------------------------------------- file extractors
def extract_pdf(buf: bytes) -> str:
    with fitz.open(stream=buf, filetype="pdf") as doc:
        return "\n".join(p.get_text() for p in doc)

def extract_docx(buf: bytes) -> str:
    doc = Document(BytesIO(buf))
    return "\n".join(p.text for p in doc.paragraphs)

def extract_csv(buf: bytes) -> str:
    return pd.read_csv(BytesIO(buf), nrows=2_000).to_csv(index=False)

def extract_xlsx(buf: bytes) -> str:
    frames = pd.read_excel(BytesIO(buf), sheet_name=None, nrows=1_000)
    return "\n\n".join(f"### {name}\n" + df.to_csv(index=False)
                       for name, df in frames.items())

def extract_html(buf: bytes) -> str:
    soup = BeautifulSoup(buf, "html.parser")
    return soup.get_text(" ", strip=True)

def extract_eml(buf: bytes) -> str:
    msg = email.message_from_bytes(buf)
    parts = [part.get_payload(decode=True).decode(errors="ignore")
             for part in msg.walk()
             if part.get_content_type() == "text/plain"]
    return "\n".join(parts)

def extract_text(uploaded) -> str:
    """Return UTF-8 text for any supported upload, else empty string."""
    if uploaded is None:
        return ""
    suffix = Path(uploaded.name).suffix.lower()
    data   = uploaded.read()           # read once

    match suffix:
        case ".pdf":                   return extract_pdf(data)
        case ".docx":                  return extract_docx(data)
        case ".csv":                   return extract_csv(data)
        case ".xlsx" | ".xls":         return extract_xlsx(data)
        case ".html" | ".htm":         return extract_html(data)
        case ".txt" | ".log":          return data.decode(errors="ignore")
        case ".eml":                   return extract_eml(data)
        case _:
            return ""   # unsupported → caller shows warning

# ---------------------------------------------------------------- IP lookup
def lookup_ip(ip: str, timeout=6) -> dict:
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=timeout)
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}



uri = "ui/nichosec brain.png"   # notice the space is fine because it’s quoted

st.markdown(
    f"""
    <style>
      .stApp {{
        background: url('{uri}') no-repeat center center fixed;
        background-size: cover;
      }}
      /* …rest unchanged… */
    </style>
    """,
    unsafe_allow_html=True,
)


     


# ── OPENAI CLIENT – one-time setup  ───────────────────────────────────────
from openai import OpenAI, APIError, RateLimitError
from dotenv import load_dotenv
import time, os, re, ipaddress, urllib.parse as up

load_dotenv()                                   # loads .env in project root
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ── Helper constants ─────────────────────────────────────────────────────
PHISH_KEYWORDS = [
    "bonus", "credit", "jackpot", "confirm transfer", "confirm now",
    "verify account", "$", "usd", "eu-central-1.linodeobjects"
]

# ── scan() ────────────────────────────────────────────────────────────────
import ipaddress, re, urllib.parse as up, time                     # top-of-file is fine

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def scan(raw: str, purge: bool = False) -> dict:
    """Return dict with level, summary, reasons, ips, [cleaned], scan_time."""
    # de-dupe + validate IPs ------------------------------------------------
    ips = sorted({
        w for w in raw.split()
        if "." in w and w.replace(".", "").isdigit() and is_valid_ip(w)
    })

    # 1️⃣  Heuristic keyword guard -----------------------------------------
    body = raw.split("\n\n", 1)[-1]            # drop headers for the heuristics
    if any(k in body.lower() for k in PHISH_KEYWORDS):
        return {
            "level": "RED",
            "summary": "Heuristic phishing keywords detected.",
            "reasons": ["Keyword match"],
            "ips": ips,
            "scan_time": 0.0,
        }

    # 2️⃣  Inline <script> tag ---------------------------------------------
    if "<script" in body.lower():
        return {
            "level": "RED",
            "summary": "Inline <script> tag detected.",
            "reasons": ["HTML script tag"],
            "ips": ips,
            "scan_time": 0.0,
        }

    # 3️⃣  Suspicious base-64 blocks ---------------------------------------
    b64_parts = re.findall(
        r"Content-Type:[^\n]+\n(?:.+\n)*?base64",
        raw,
        flags=re.I,
    )

    unusual_b64 = [
        p for p in b64_parts
        if not re.search(
            r'filename="?.+\.(pdf|docx?|xlsx?|pptx?|png|jpe?g|gif)"?',
            p,
            flags=re.I,
        )
    ]

    if unusual_b64:
        snippet = unusual_b64[0][:120].replace("\n", " ") + "…"
        return {
            "level": "RED",
            "summary": "Inline base-64 payload detected.",
            "reasons": [snippet],
            "ips": ips,
            "scan_time": 0.0,
        }

    # 4️⃣  Extract links for GPT -------------------------------------------
    links = re.findall(r'href=[\'"]?([^\'" >]+)', raw, flags=re.I)
    link_list = "\n".join(f"- {up.unquote(l)[:120]}" for l in links[:20]) or "None"

    # 5️⃣  Build hardened prompt & call GPT --------------------------------
    prompt = f"""
You are **NichoSec**, a senior phishing-analysis AI.
Analyse the email/text below. Flag **RED** if any strong indicator is present,
**YELLOW** if uncertain, else **GREEN**.

Links extracted from the message:
{link_list}

Return STRICT JSON only:
```json
{{{{"level":"","summary":"","reasons":[]}}}}
"""
    try:
        t0 = time.perf_counter()
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt + "\n\n" + body[:15_000]}],
            temperature=0.1,
        )
        data = parse_json(resp.choices[0].message.content)
        data["scan_time"] = round(time.perf_counter() - t0, 2)

    except (RateLimitError, APIError) as e:
        data = {
            "level": "YELLOW",
            "summary": f"LLM unavailable: {e.__class__.__name__}",
            "reasons": ["Fallback – service error"],
            "scan_time": 0.0,
        }

    data["ips"] = ips                                        # attach IP list

    # 6️⃣  Purge plug-in ----------------------------------------------------
    if purge and data.get("level") != "GREEN":
        cleaned = "\n".join(
            l for l in raw.splitlines()
            if not any(t in l.lower() for t in ["seed phrase",
                                                "wire transfer",
                                                "password"])
        )
        data["cleaned"] = cleaned[:10_000]

    return data

# -------------------------------------------------------------------- header
logo_b64 = to_base64("assets/shield_logo_exact.png")   # ← your trimmed PNG

st.markdown(
    f"""
    <style>
      .nichosec-header {{
        display:flex;
        justify-content:center;
        align-items:center;
        gap:0.6rem;                   /* space between logo + title */
        margin:0.4rem 0 1.0rem;
      }}
      .nichosec-header h1 {{
        margin:0;
        font-size:2rem;               /* tweak if you want larger */
        font-weight:600;
      }}
    </style>

    <div class="nichosec-header">
        <img src="data:image/png;base64,{logo_b64}" width="64" />
        <h1>NichoSec V1 - Local Threat Scanner</h1>
    </div>
    """,
    unsafe_allow_html=True,
)



# ░░ INPUT CARD ░░──────────────────────────────────────────────────────────
with st.container():
    st.markdown("<div class='card'>", unsafe_allow_html=True)

    uploaded = st.file_uploader(
        "Upload document",
        type=["pdf", "txt", "log", "docx", "csv", "xlsx", "xls", "html", "htm"],
        key="uploader"
    )

    text_in  = st.text_area("…or paste raw email / text here", height=150)
    purge_on = st.checkbox("🔌 Enable Purge Plugin (experimental)")

    if purge_on:
        st.caption(
            "The purge plug-in will remove lines containing keywords like "
            "`seed phrase`, `wire transfer`, or `password` from the text before "
            "exporting. Attachments aren’t modified."
        )

    st.markdown("</div>", unsafe_allow_html=True)  # close the translucent panel


    # inside your <div class='card'> container
scan_clicked = st.button("🛡️ Run Scan", type="primary")   # 👈 brighter, always visible

if scan_clicked:
    if not uploaded and not text_in.strip():
        st.warning("Please upload a file or paste some text.")
    else:
        with st.spinner("Scanning…"):
            raw_text = extract_text(uploaded) if uploaded else text_in
            st.session_state.threat = scan(raw_text, purge_on)

st.markdown("</div>", unsafe_allow_html=True)   # leave this as-is


# ── OUTPUT AREA ─────────────────────────────────────────────────────────────
threat = st.session_state.get("threat")
if threat:
    # ------- color + icon by level ----------
    level      = threat.get("level", "YELLOW").upper()
    icon, color = {
        "GREEN" : ("🟢", "#28a745"),
        "YELLOW": ("🟡", "#ffc107"),
        "RED"   : ("🔴", "#dc3545"),
    }.get(level, ("❔", "#6c757d"))

    summary = threat.get("summary", "No summary provided.")
    reasons = threat.get("reasons", [])
    ips     = threat.get("ips", [])
    t_sec   = threat.get("scan_time", 0)

    # ------------ pretty card ---------------
    st.markdown(f"""
    <div style="
        border-left: 6px solid {color};
        padding: 0.75rem 1rem;
        margin: 0.5rem 0 1rem 0;
        background: rgba(255,255,255,0.08);
        border-radius: 6px;
    ">
        <h4 style="margin-top:0;">
            {icon} <span style="color:{color};">{level}</span> – {summary}
        </h4>

        <b>Reasons:</b>
        <ul>
            {''.join(f'<li>{r}</li>' for r in reasons)}
        </ul>

        <b>IPs:</b>
        {"<br>".join(f'<code>{ip}</code>' for ip in ips) or "—"}

        <div style="font-size:0.85rem; margin-top:0.5rem;">
            ⏱ Scan time: {t_sec:.2f}s
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 👉 still offer raw JSON behind an expander
    with st.expander("📑 Full raw JSON"):
        st.json(threat)


    if purge_on and "cleaned" in threat:
        st.download_button("⬇️ Download Purged Text", threat["cleaned"],
                           "nichosec_purged.txt", "text/plain")

    if threat.get("ips"):
        with st.expander(f"🌐 IP info ({len(threat['ips'])})"):
            for ip in threat["ips"]:
                st.write(ip, lookup_ip(ip).get("org", ""))

st.caption("NichoSec V1 - Local security, zero cloud storage. ©2025 Addy Nicholson")
