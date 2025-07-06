import streamlit as st
import os
import re
import requests
import fitz  # PyMuPDF
from dotenv import load_dotenv
from openai import OpenAI

# ---- IP lookup helper ---------------------------------
def lookup_ip(ip: str) -> dict:
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8)
        if res.status_code == 200:
            return res.json()
        return {"error": f"Request failed with {res.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# ---- PDF Text Extract ---------------------------------
def extract_text_from_pdf(uploaded_file):
    text = ""
    try:
        with fitz.open(stream=uploaded_file.read(), filetype="pdf") as doc:
            for page in doc:
                text += page.get_text()
        print("[PDF TEXT PREVIEW]", text[:300])
    except Exception as e:
        text = f"[PDF error] {e}"
    return text

# ---- ENV + OpenAI Init --------------------------------
load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)

st.set_page_config(page_title="NichoSec 🛡️", page_icon="🛡️", layout="wide")

# ---- Style --------------------------------------------
st.markdown("""
<style>
.stTabs [data-baseweb="tab"] {
    font-size: 18px;
    font-weight: 600;
    color: #F0F6FC;
    border: none;
    padding: 0.75rem 1rem;
}
.stTabs [data-baseweb="tab"]:hover {
    color: #58a6ff;
}
.stTabs [aria-selected="true"] {
    background-color: #21262d;
    color: #58a6ff;
    border-bottom: 2px solid #58a6ff;
}
</style>
""", unsafe_allow_html=True)

# ---- Sidebar ------------------------------------------
st.sidebar.title("🛡️ NichoSec")
st.sidebar.markdown("Nicholson Security AI Tools")
st.sidebar.markdown("---")
model = st.sidebar.selectbox("💡 Choose Model", ["gpt-3.5-turbo", "gpt-4"])

if st.sidebar.button("🔁 Reset Conversation"):
    st.session_state.messages = [{
        "role": "assistant",
        "content": "🧠 Fresh session loaded. Drop logs, commands, or suspicious behavior to investigate."
    }]
    st.rerun()

# ---- System Prompt ------------------------------------
SYSTEM_PROMPT = (
    "You are a cybersecurity analyst focused on helping detect, explain, "
    "and investigate system threats in plain language. "
    "Use short, accurate answers. Suggest tools, ask diagnostic questions, "
    "and flag anything suspicious or potentially malicious."
)

# ---- Tabs ---------------------------------------------
tab1, tab2, tab3 = st.tabs(["💬 Chat Console", "📁 Log Scanner", "🌐 IP Lookup"])

# --------------------
# Tab 1: Chat Console
# --------------------
with tab1:
    st.markdown("### 💬 Command Console")
    if "messages" not in st.session_state:
        st.session_state.messages = [{
            "role": "assistant",
            "content": "NichoSec initialized. 🛡️ System standing by for threat analysis or command input."
        }]

    for msg in st.session_state.messages:
        avatar = "👷" if msg["role"] == "user" else "🤖"
        with st.chat_message(msg["role"], avatar=avatar):
            st.markdown(msg["content"])

    prompt = st.chat_input("Enter command or message...")

    if prompt:
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user", avatar="👷"):
            st.markdown(prompt)

        # 🔍 IP Lookup Command
        if prompt.lower().startswith("/lookup"):
            ip_match = re.search(r"/lookup\s+([a-fA-F0-9:.]+)", prompt)
            if ip_match:
                ip = ip_match.group(1)
                data = lookup_ip(ip)

                if "ip" in data:
                    rep_icon = {
                        "good": "✅ Clean",
                        "suspicious": "🟡 Suspicious",
                        "bad": "⚠️ Malicious",
                        "unknown": "❓ Unknown"
                    }.get(data.get("reputation", "unknown"), "❓ Unknown")

                    city, region, country = data.get('city', 'N/A'), data.get('region', 'N/A'), data.get('country', 'N/A')
                    lat, lon = (data.get('loc', "0,0").split(","))[:2]

                    reply = (
                        f"📍 **IP**: `{data['ip']}`\n"
                        f"🌐 **Location**: {country}, {region}, {city}\n"
                        f"🛱 **Coords**: {lat}, {lon}\n"
                        f"🏢 **Org**: {data.get('org', 'N/A')}\n"
                        f"🔖 **Reputation**: {rep_icon}"
                    )
                    st.markdown(reply)
                    st.map([{"lat": float(lat), "lon": float(lon)}])
                else:
                    reply = f"❌ Could not fetch details for `{ip}`"

                st.session_state.messages.append({"role": "assistant", "content": reply})
                st.stop()

        # 🤖 AI Response
        with st.chat_message("assistant", avatar="🤖"):
            with st.spinner("Analyzing..."):
                try:
                    full_messages = [{"role": "system", "content": SYSTEM_PROMPT}] + [
                        {"role": m["role"], "content": m["content"]} for m in st.session_state.messages
                    ]
                    response = client.chat.completions.create(
                        model=model,
                        messages=full_messages
                    )
                    reply = response.choices[0].message.content
                except Exception as e:
                    reply = f"[Error] {e}"

                st.markdown(reply)
                st.session_state.messages.append({"role": "assistant", "content": reply})

# --------------------
# Tab 2: Log Scanner
# --------------------
with tab2:
    st.markdown("### 📁 Log Threat Scanner")
    uploaded_file = st.file_uploader("Upload .log, .txt or .pdf file", type=["txt", "log", "pdf"])
    manual_logs = st.text_area("Paste logs manually:", height=200)

    if st.button("🧪 Scan Now"):
        log_data = ""
        if uploaded_file:
            try:
                if uploaded_file.type == "application/pdf":
                    log_data = extract_text_from_pdf(uploaded_file)
                else:
                    log_data = uploaded_file.read().decode("utf-8")
            except Exception as e:
                st.error(f"❌ Could not read file: {e}")
        elif manual_logs:
            log_data = manual_logs

        if not log_data.strip():
            st.warning("⚠️ No log data provided.")
            st.stop()

        # 🔐 Keyword Scan
        keywords = ["failed login", "unauthorized", "denied", "malicious", "error", "drop", "root access"]
        flagged = [line for line in log_data.splitlines() if any(term in line.lower() for term in keywords)]
        if flagged:
            st.error(f"⚠️ Found {len(flagged)} suspicious entries:")
            st.code("\n".join(flagged), language="text")

        # 🕵️ Fake Email Check
        suspicious_domains = ["gmail.com", "outlook.com", "yahoo.com", "mail.ru", "protonmail.com", ".tk", ".xyz", ".click", ".info", ".top"]
        spoof_indicators = ["noreply@", "billing@", "support@", "admin@", "account@", "login@"]
        fake_flags = []

        for line in log_data.lower().splitlines():
            if "@" in line:
                if any(domain in line for domain in suspicious_domains):
                    fake_flags.append(f"Suspicious domain → {line.strip()}")
                elif "nzta" in line and not line.strip().endswith(".govt.nz"):
                    fake_flags.append(f"⚠️ Possible NZTA spoof → {line.strip()}")
                elif any(k in line for k in spoof_indicators):
                    fake_flags.append(f"Generic spoof keyword → {line.strip()}")

        if fake_flags:
            st.warning(f"🚩 Found {len(fake_flags)} potential fake-sender lines:")
            st.code("\n".join(fake_flags), language="text")

        if not flagged and not fake_flags:
            st.success("✅ No suspicious activity detected.")

# --------------------
# Tab 3: IP Lookup Tool
# --------------------
with tab3:
    st.markdown("### 🌐 IPv4/IPv6 Lookup Tool")
    ip_input = st.text_input("Enter IP address to trace")
    if st.button("🔎 Lookup IP") and ip_input:
        try:
            data = lookup_ip(ip_input)
            if "ip" in data:
                st.markdown(f"""
                **📍 IP Address**: `{data.get('ip')}`  
                **🌐 Location**: {data.get('country')}, {data.get('region')}, {data.get('city')}  
                **🏢 Org**: {data.get('org')}  
                **🛰️ ISP**: {data.get('hostname', 'N/A')}  
                **📡 Coordinates**: {data.get('loc', 'N/A')}  
                """)
                lat, lon = map(float, data.get("loc", "0,0").split(","))
                st.map([{"lat": lat, "lon": lon}])
            else:
                st.error("❌ Could not fetch IP details.")
        except Exception as e:
            st.error(f"❌ Failed to connect: {e}")
