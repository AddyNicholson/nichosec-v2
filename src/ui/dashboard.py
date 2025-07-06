# src/ui/dashboard.py
from __future__ import annotations
import sys
from pathlib import Path
import streamlit as st
import pandas as pd

# --- add project root so we can import src.core -------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.reports import load_history   # helper you’ll write
from src.core.scan_engine import scan       # reuse if you add re-scan

st.set_page_config(page_title="NichoSec Dashboard", page_icon="🛡️", layout="wide")
st.title("🛡️ NichoSec – Scan Dashboard")

# ── Sidebar upload (optional) -------------------------------------------
st.sidebar.header("New Upload")
uploaded = st.sidebar.file_uploader(
    "Upload document",
    type=["pdf","txt","log","docx","csv","xlsx","xls","html","htm","eml"]
)
if uploaded:
    # call your existing extract_text+scan pipeline
    from src.core.extractors import extract_text
    text = extract_text(uploaded)
    result = scan(text)
    # save to history (JSON/SQLite/whatever)
    from src.core.reports import save_result
    save_result(uploaded.name, result)
    st.sidebar.success("Scanned and saved!")

# ── Pull scan history ----------------------------------------------------
history = load_history()              # returns a list[dict] or DataFrame
if history.empty:
    st.info("No scans yet. Upload a document to get started!")
    st.stop()

# Overview stats
col1, col2, col3 = st.columns(3)
with col1:
    st.metric("🔴 Red",     int((history.level=="RED").sum()))
with col2:
    st.metric("🟡 Yellow",  int((history.level=="YELLOW").sum()))
with col3:
    st.metric("🟢 Green",   int((history.level=="GREEN").sum()))

st.divider()

# Recent scans table
st.subheader("Recent Scans")
st.dataframe(
    history[["timestamp","filename","level","scan_time","summary"]],
    use_container_width=True,
    hide_index=True
)

# Show details when user selects a row
idx = st.selectbox("View full report (row #):", history.index[::-1])
row = history.loc[idx]
st.markdown(f"### {row.filename}  <span style='color:{row.level}'>{row.level}</span>", unsafe_allow_html=True)
st.write("**Summary:**", row.summary)
st.write("**Reasons:**")
for r in row.reasons:
    st.write("•", r)
st.write("**IPs:**", ", ".join(row.ips) if row.ips else "—")
