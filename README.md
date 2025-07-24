# 🛡️ NichoSec V2 – AI-Powered Threat Scanner

**NichoSec V2** is a secure, private, AI-augmented local threat analysis platform for emails, documents, and IPs. It leverages NLP + threat feeds to detect phishing, malware, and spoofing attempts — all with no cloud storage.

> 🧠 \
Your
inbox
and
documents
deserve
smarter
local
security.\

---

## 🚀 Features

- ✅ **Gmail Integration** – Securely pull and scan your emails
- 🧠 **AI Threat Verdicts** – Phishing and spoofing detection with NLP
- 📥 **Bulk File Scanner** – Upload .eml, .pdf, .txt, .log, .docx, .csv, etc.
- 🌐 **Live IP Reputation Feeds** – AbuseIPDB + AlienVault OTX lookup
- 🧾 **PDF Reports** – Severity verdicts, MITRE mapping, AI summaries
- 🔒 **Fully Local** – No cloud storage, full privacy, runs locally
- 🧰 **Streamlit UI** – Clean, responsive app with scan history + AI assistant
- 🧪 **MITRE ATT&CK Tags** – Each finding is mapped to MITRE tactics/techniques

---

## 📂 How to Run

\\\ash
git clone https://github.com/AddyNicholson/NichoSec-V2.git
cd NichoSec-V2
python -m venv venv
venv\\Scripts\\activate   # or \source venv/bin/activate\ on Mac/Linux
pip install -r requirements.txt
streamlit run nichosec
\\\

> **Optional:** Create a \.env\ file and add your keys:
\\\nv
OPENAI_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
ALIENVAULT_API_KEY=your_key
\\\

---

## 🔑 Gmail Loader Setup

Make sure to enable:
- OAuth credentials (Google Cloud Console)
- Gmail API
- Add your \client_secret.json\ file to the root

---

## 📈 Status

✅ Actively Developed  
📍 V2 released July 2025  
🛠️ V3: Browser extension + safe-link rewriting (coming soon)

---

## 👨‍💻 Author

**Addison Jade Nicholson**  
GitHub: [@AddyNicholson](https://github.com/AddyNicholson)  
Email: mraddison.nicholson@gmail.com

---

## 📜 License

MIT License — free to use, fork, and contribute.

