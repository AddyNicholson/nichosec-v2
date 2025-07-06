
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

from datetime import datetime


st.set_page_config(
    page_title="NichoSec 💻",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom CSS for Pro UI ---
st.markdown("""
<style>
    html, body, [class*="css"]  {
        font-family: 'Segoe UI', sans-serif;
        background-color: #0f1117;
        color: #ffffff;
    }
    .stApp {
        padding: 2rem;
        background-color: #0f1117;
    }
    .block-container {
        padding: 2rem 2rem 2rem 2rem;
    }
    .card {
        background-color: #1a1d2a;
        border-radius: 15px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        box-shadow: 0 0 10px rgba(0,255,160,0.1);
    }
    .threat {
        border-left: 5px solid #ff4b4b;
    }
    .safe {
        border-left: 5px solid #00cc66;
    }
    .info {
        border-left: 5px solid #3399ff;
    }
</style>
""", unsafe_allow_html=True)


# --- Sidebar ---
st.sidebar.title("🔧 Control Panel")
model = st.sidebar.selectbox("💡 Choose Model", ["gpt-3.5-turbo", "gpt-4"])
uploaded_file = st.sidebar.file_uploader("📄 Upload File", type=["pdf", "txt", "log", "docx"])
user_text = st.sidebar.text_area("✉️ Paste Email/Message")
ip_input = st.sidebar.text_input("🌐 Enter IP Address or Domain")
command = st.sidebar.text_input("💬 Custom Command")

if uploaded_file and st.button("🚀 Run Scan", key="dashboard_run"):
    if uploaded_file.type == "application/pdf":
        text = extract_text_from_pdf(uploaded_file)
    else:
        text = uploaded_file.read().decode("utf-8", errors="ignore")

    # Basic keyword scan
    keywords = ["unauthorized", "failed", "malicious", "error", "denied"]
    flagged = [line for line in text.splitlines() if any(k in line.lower() for k in keywords)]

    if flagged:
        st.error("⚠️ Potential threats detected:")
        st.code("\n".join(flagged))
    else:
        st.success("✅ No obvious threats found.")

# --- Tabs ---
tab1, tab2, tab3, tab4, tab5 = st.tabs(["📊 Dashboard", "💬 Chat", "📜 Logs", "🌍 IP Lookup", "🧾 Reports"])

# --- Tab: Dashboard ---
with tab1:
    st.subheader("📊 Threat Summary")
    if uploaded_file and st.sidebar.button("🚀 Run Scan"):
        if uploaded_file.type == "application/pdf":
            text = extract_text_from_pdf(uploaded_file)
        else:
            text = uploaded_file.read().decode("utf-8", errors="ignore")
        st.code(text[:500], language="text")
    st.markdown(f"Last checked: 2025-06-17 01:52:58")

# --- Tab: Chat ---
with tab2:
    st.subheader("💬 NichoSec-GPT")
    if "messages" not in st.session_state:
        st.session_state.messages = [{"role": "assistant", "content": "NichoSec ready for analysis input."}]
    for msg in st.session_state.messages:
        st.chat_message(msg["role"]).markdown(msg["content"])
    if command:
        st.session_state.messages.append({"role": "user", "content": command})
        with st.spinner("Thinking..."):
            try:
                messages = [{"role": "system", "content": "You are a cybersecurity AI."}] + [
                    {"role": m["role"], "content": m["content"]} for m in st.session_state.messages
                ]
                response = client.chat.completions.create(model=model, messages=messages)
                reply = response.choices[0].message.content
            except Exception as e:
                reply = f"[ERROR] {e}"
            st.chat_message("assistant").markdown(reply)
            st.session_state.messages.append({"role": "assistant", "content": reply})

# --- Tab: Logs ---
with tab3:
    st.subheader("📜 Log Scanner")
    manual_logs = st.text_area("Paste logs manually:", height=200)
    if st.button("🧪 Analyze Logs"):
        log_data = ""
        if uploaded_file:
            log_data = uploaded_file.read().decode("utf-8")
        elif manual_logs:
            log_data = manual_logs
        if log_data:
            st.code(log_data[:500], language="text")

# --- Tab: IP Lookup ---
with tab4:
    st.subheader("🌍 IP Lookup")
    if ip_input:
        result = lookup_ip(ip_input)
        st.json(result)

# --- Tab: Reports ---
with tab5:
    st.subheader("🧾 Reports")
    st.info("Feature under development.")

# --- Scan Bar ---
st.markdown("<div class='status-bar'></div>", unsafe_allow_html=True)
