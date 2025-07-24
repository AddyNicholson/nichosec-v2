# ── dashboard.py (Advanced Threat Dashboard) ───────────────────────────── 
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

st.title("🧠 NichoSec – Dashboard")

history = st.session_state.get("scan_history", [])

if not history:
    st.info("No scan history found. Run a scan to populate the dashboard.")
    st.stop()

df = pd.DataFrame(history)
df["timestamp"] = pd.to_datetime(df["timestamp"])
df["date"] = df["timestamp"].dt.date

st.markdown("### 📊 Threat Breakdown")
col1, col2, col3 = st.columns(3)
col1.metric("🟥 Red", df[df["level"] == "RED"].shape[0])
col2.metric("🟨 Yellow", df[df["level"] == "YELLOW"].shape[0])
col3.metric("🟩 Green", df[df["level"] == "GREEN"].shape[0])

# Plot scans per day
st.markdown("### 📅 Scan Volume Over Time")
scans_per_day = df.groupby("date").size()
fig, ax = plt.subplots()
scans_per_day.plot(kind="line", marker="o", ax=ax)
ax.set_ylabel("Scans")
ax.set_xlabel("Date")
ax.set_title("Scans per Day")
st.pyplot(fig)

# Table view with filters
st.markdown("### 🗂️ Recent Scan Records")
verdict_filter = st.selectbox("Filter by Verdict", ["All", "RED", "YELLOW", "GREEN"])
if verdict_filter != "All":
    df = df[df["level"] == verdict_filter]

st.dataframe(df[["timestamp", "file", "level", "summary"]].sort_values(by="timestamp", ascending=False), use_container_width=True)

# Detail Viewer
st.markdown("### 🔍 View Full Report")
selected_index = st.number_input("Select row #", min_value=0, max_value=len(df)-1, step=1)
selected = df.iloc[selected_index]
st.markdown(f"**{selected['file']}** – **{selected['level']}**")
st.markdown(f"**Summary:** {selected['summary']}")
st.markdown("**Reasons:**")
for r in selected.get("reasons", []):
    st.write(f"- {r}")

if st.button("📥 Export History to CSV"):
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button("Download CSV", csv, "scan_history.csv", "text/csv")
