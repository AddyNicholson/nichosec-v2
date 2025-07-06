"""
NichoSec V1 – Local Threat Scanner
Clean, de‑duplicated Streamlit script.
Tested with Streamlit 1.33 and openai==1.30.
"""

# ── Imports ──────────────────────────────────────────────────────────────
import os, re, io, time, json, base64, mimetypes, imaplib, email, tempfile
from pathlib import Path
from typing import List, Tuple
import ipaddress
import urllib.parse as up

import fitz              # PyMuPDF
import requests
import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI, APIError, RateLimitError


# ── Config / ENV ─────────────────────────────────────────────────────────
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# must be the FIRST Streamlit call
st.set_page_config(
    page_title="NichoSec | Local Threat Scanner",
    page_icon="🛡️",          # favicon only
    layout="centered",
)


# ── Branding assets ──────────────────────────────────────────────────────
ASSETS = Path(__file__).with_name("assets")
logo_path = ASSETS / "shield_logo_exact.png"
logo_b64 = base64.b64encode(logo_path.read_bytes()).decode()

def hero_background():
    """Apply the blurred‑dark hero bg if the PNG is next to the .py."""
    bg_path = Path(__file__).with_name("NichoSec brain.png")
    if not bg_path.exists():
        return
    mime = mimetypes.guess_type(bg_path.name)[0] or "image/png"
    uri  = f"data:{mime};base64," + base64.b64encode(bg_path.read_bytes()).decode()
    st.markdown(f"""
    <style>
      .stApp {{
        background: url('{uri}') no-repeat center center fixed;
        background-size: cover;
      }}
      .stApp:before {{
        content:"";position:fixed;inset:0;
        background:rgba(0,0,0,0.85);backdrop-filter:blur(4px);z-index:-1;
      }}
      .card {{background:rgba(255,255,255,0.70);padding:2rem 1.5rem;
              border-radius:12px;margin-bottom:2rem;
              box-shadow:0 4px 12px rgba(0,0,0,0.45);color:#111;}}
      .card * {{color:#111!important;}}
    </style>""", unsafe_allow_html=True)

def header():
    st.markdown(f"""
    <style>
      .nichosec-header{{display:flex;justify-content:center;align-items:center;
                        gap:0.6rem;margin:0.6rem 0 1.2rem;}}
      .nichosec-header h1{{margin:0;font-size:2rem;font-weight:600;}}
    </style>
    <div class='nichosec-header'>
      <img src='data:image/png;base64,{logo_b64}' width='64'/>
      <h1>NichoSec V1 – Local Threat Scanner</h1>
    </div>""", unsafe_allow_html=True)

def feature_list():
    st.markdown("""
    <div style='text-align:center;font-size:0.95rem;line-height:1.45;'>
      • <b>Upload file</b> <i>or</i> paste text → one‑click scan<br>
      • GPT‑4o‑mini analysis with hardened prompt<br>
      • Heuristic keyword pre‑filter (<span style='color:#ff5252;'>instant RED</span>)<br>
      • Optional purge plug‑in<br>
      • Full‑page hero background (<code>NichoSec brain.png</code>)<br>
      • 100 % local — no cloud storage
    </div>""", unsafe_allow_html=True)


# ── Helper functions ─────────────────────────────────────────────────────
PHISH_KEYWORDS = [
    "bonus","credit","jackpot","confirm transfer","confirm now",
    "verify account","$","usd","eu-central-1.linodeobjects",
]

def parse_json(s:str)->dict:
    s=s.strip()
    if s.startswith("```"): s=re.sub(r"^```[\w]*","",s).rstrip("```").strip()
    try:return json.loads(s)
    except Exception:
        return {"level":"YELLOW","summary":(s[:150]+"…") if s else "Model not JSON","reasons":["Fallback parse"]}

def extract_text(uploaded)->str:
    if not uploaded:return""
    name=uploaded.name.lower()
    if name.endswith((".txt",".log")):
        return uploaded.read().decode(errors="ignore")
    if name.endswith(".pdf"):
        with fitz.open(stream=uploaded.read(),filetype="pdf") as doc:
            return "".join(p.get_text() for p in doc)
    return "[Unsupported format]"

def is_valid_ip(ip:str)->bool:
    try: ipaddress.ip_address(ip); return True
    except ValueError: return False

def lookup_ip(ip:str,timeout=6)->dict:
    try:
        r=requests.get(f"https://ipinfo.io/{ip}/json",timeout=timeout)
        return r.json() if r.status_code==200 else {}
    except Exception: return {}

# ── Core scan engine ─────────────────────────────────────────────────────
DEF_PROMPT_TEMPLATE = """You are **NichoSec**, a senior phishing‑analysis AI.\nAnalyse the email/text below. Flag **RED** if any strong indicator is present, **YELLOW** if uncertain, else **GREEN**.\n\nLinks extracted from the message:\n{links}\n\nReturn STRICT JSON only:\n```json\n{{{{\n  \"level\": \"...\",\n  \"summary\": \"...\",\n  \"reasons\": [\"...\"]\n}}}}\n```"""

def scan(raw:str,purge:bool=False)->dict:
    ips=sorted({w for w in raw.split() if "." in w and w.replace(".","").isdigit() and is_valid_ip(w)})

    body=raw.split("\n\n",1)[-1]  # ignore headers for heuristics
    if any(k in body.lower() for k in PHISH_KEYWORDS):
        return {"level":"RED","summary":"Heuristic phishing keywords detected.","reasons":["Keyword match"],"ips":ips,"scan_time":0.0}
    if "<script" in body.lower() or "base64" in body.lower():
        return {"level":"RED","summary":"Inline <script>/base64 detected.","reasons":["Script/base64"],"ips":ips,"scan_time":0.0}

    links=re.findall(r'href=[\'\"]?([^\'\" >]+)',raw,flags=re.I)
    link_list="\n".join(f"- {up.unquote(l)[:120]}" for l in links[:20]) or "None"
    prompt=DEF_PROMPT_TEMPLATE.format(links=link_list)

    try:
        t0=time.perf_counter()
        resp=client.chat.completions.create(model="gpt-4o-mini",messages=[{"role":"user","content":prompt}],temperature=0.1)
        data=parse_json(resp.choices[0].message.content)
        data["scan_time"]=round(time.perf_counter()-t0,2)
    except (RateLimitError,APIError) as e:
        data={"level":"YELLOW","summary":f"LLM unavailable: {e.__class__.__name__}","reasons":["Service error"],"scan_time":0.0}

    data["ips"]=ips
    if purge and data.get("level")!="GREEN":
        cleaned="\n".join(l for l in raw.splitlines() if not any(t in l.lower() for t in ["seed phrase","wire transfer","password"]))
        data["cleaned"]=cleaned[:10000]
    return data


# ── UI components ────────────────────────────────────────────────────────
hero_background()
header()
feature_list()

# • Email Loader -----------------------------------------------------------

def email_loader():
    def list_emails(host,user,pw,num=20)->List[Tuple[bytes,str,str,str]]:
        box=imaplib.IMAP4_SSL(host); box.login(user,pw); box.select("INBOX")
        _,data=box.search(None,"ALL"); uids=data[0].split()[-num:]
        rows=[]
        for uid in reversed(uids):
            _,msg_data=box.fetch(uid,"(RFC822.HEADER)")
            msg=email.message_from_bytes(msg_data[0][1])
            rows.append((uid,msg["Subject"],msg["From"],msg["Date"]))
        box.logout(); return rows

    def fetch_email(host,user,pw,uid):
        box=imaplib.IMAP4_SSL(host); box.login(user,pw); box.select("INBOX")
        _,msg_data=box.fetch(uid,"(RFC822)"); box.logout()
        return email.message_from_bytes(msg_data[0][1])

    with st.sidebar.expander("📥 Email Loader (beta)"):
        host=st.text_input("IMAP host","imap.gmail.com")
        user=st.text_input("Email address")
        pw  =st.text_input("App Password",type="password")
        if st.button("Connect"):
            try:
                st.session_state.email_list=list_emails(host,user,pw)
                st.session_state.imap_creds=(host,user,pw)
                st.success(f"Fetched {len(st.session_state.email_list)} messages")
            except Exception as e:
                st.error(f"IMAP error: {e}")

        if "email_list" in st.session_state:
            for uid,subj,sender,date in st.session_state.email_list:
                if st.button(f"🛡️ Scan: {subj[:60]}",key=str(uid)):
                    host,user,pw=st.session_state.imap_creds
                    msg=fetch_email(host,user,pw,uid)
                    raw,attachments="",[]
                    for part in msg.walk():
                        ctype=part.get_content_type()
                        if ctype=="text/plain":
                            raw+=part.get_payload(decode=True).decode(errors="ignore")
                        elif part.get_filename():
                            tmp=tempfile.NamedTemporaryFile(delete=False)
                            tmp.write(part.get_payload(decode=True)); tmp.close()
                            attachments.append(tmp.name)
                    st.session_state.threat=scan(raw,purge=False)

def ai_helper():
    with st.sidebar.expander("🤖 Ask NichoSec AI"):
        if "chat" not in st.session_state:
            st.session_state.chat=[{"role":"system","content":"You are NichoSec, a concise cybersecurity assistant."}]

        for m in st.session_state.chat[1:]:
            avatar="🧑‍💻" if m["role"]=="user" else "🤖"
            st.markdown(f"**{avatar}** {m['content']}")

        prompt=st.text_input("Ask about phishing, threats, logs …",key="chat_box")
        # --------------- inside ai_helper() -----------------
        if st.button("Send", key="chat_send") and prompt.strip():
           st.session_state.chat.append({"role": "user", "content": prompt})

    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
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

        # save assistant reply
        st.session_state.chat.append({"role": "assistant", "content": answer})
        st.session_state.chat_box = ""        # clear the input box
        st.experimental_rerun()               # refresh sidebar

    except (RateLimitError, APIError) as e:
        st.error(f"OpenAI error – {e.__class__.__name__}: {e}")

