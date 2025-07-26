import streamlit as st
from authlib.integrations.requests_client import OAuth2Session
import os, base64

# Get credentials from environment
CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
REDIRECT_URI = "http://localhost:8501"  # You can update this if deploying on a custom domain

AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URI = "https://oauth2.googleapis.com/token"
USER_INFO_URI = "https://www.googleapis.com/oauth2/v2/userinfo"

AUTHORIZED_USERS = {
    "mraddison.nicholson@gmail.com": "admin",
}

def add_bg_from_local(image_file):
    with open(image_file, "rb") as f:
        encoded = base64.b64encode(f.read()).decode()
    st.markdown(f"""
        <style>
        .stApp {{
            background-image: url("data:image/png;base64,{encoded}");
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
        }}
        </style>
    """, unsafe_allow_html=True)

def login():
    if "user" not in st.session_state:
        st.session_state.user = None
        st.session_state.role = None

    if st.session_state.user:
        return

    add_bg_from_local("assets/circuit_dark_bg.png")

    if st.query_params.get("code"):
        code = st.query_params["code"]
        oauth = OAuth2Session(CLIENT_ID, CLIENT_SECRET, redirect_uri=REDIRECT_URI)
        token = oauth.fetch_token(TOKEN_URI, code=code)
        
        oauth.token = token
        resp = oauth.get(USER_INFO_URI)
        user_info = resp.json()

        email = user_info.get("email")
        role = AUTHORIZED_USERS.get(email)

        if role:
            st.session_state.user = email
            st.session_state.role = role
            st.success("Logged in successfully")
            st.rerun()
        else:
            st.error("Unauthorized user")
            st.stop()

    oauth = OAuth2Session(CLIENT_ID, CLIENT_SECRET, redirect_uri=REDIRECT_URI, scope="openid email profile")
    auth_url, state = oauth.create_authorization_url(AUTH_URI)
    st.session_state.state = state

    st.markdown('<div class="login-box">', unsafe_allow_html=True)
    st.image("assets/shield_pulse_dark.png", width=150, use_container_width=False)
    st.markdown('<h2 style="color:white; margin-top: 10px;">Welcome to NichoSec</h2>', unsafe_allow_html=True)
    st.markdown('<p style="color:white; font-size: 1.1rem;">Click below to log in</p>', unsafe_allow_html=True)

    st.markdown(f""" 
        <div style="margin-top: 30px;">
            <a href="{auth_url}" target="_self" style="
                background-color: #1a73e8;
                color: white;
                padding: 12px 28px;
                font-size: 1rem;
                border-radius: 8px;
                text-decoration: none;
                font-weight: 500;
                transition: background 0.3s ease;">
                Login with Google
            </a>
        </div>
    """, unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)
    st.stop()

def logout():
    for k in ["user", "role", "auth_code", "auth_token", "state"]:
        st.session_state.pop(k, None)

    for key in list(st.session_state.keys()):
        if key.startswith("email") or key.startswith("upload"):
            st.session_state.pop(key)

    st.toast("Logged out successfully. Redirecting to login...")
    st.query_params.clear()
    st.rerun()
