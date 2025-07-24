# gmail_loader.py
# OAuth Gmail loader for NichoSec V2

import os
import base64
from typing import List, Tuple
from email import message_from_bytes
from email.policy import default
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
TOKEN_FILE = "token.json"
CREDENTIALS_FILE = "credentials.json"

def gmail_authenticate():
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, "w") as token:
            token.write(creds.to_json())
    return creds

def get_recent_emails(max_results=10) -> List[Tuple[str, str]]:
    """
    Returns a list of (message_id, subject) from user's Gmail inbox.
    """
    creds = gmail_authenticate()
    service = build("gmail", "v1", credentials=creds)
    results = service.users().messages().list(userId="me", maxResults=max_results).execute()
    messages = results.get("messages", [])
    items = []
    for msg in messages:
        msg_data = service.users().messages().get(userId="me", id=msg["id"]).execute()
        headers = msg_data.get("payload", {}).get("headers", [])
        subject = next((h["value"] for h in headers if h["name"] == "Subject"), "(No subject)")
        items.append((msg["id"], subject))
    return items

def fetch_email_raw(msg_id: str) -> bytes:
    """
    Downloads a single Gmail message by ID and returns it as raw bytes (.eml-style).
    """
    creds = gmail_authenticate()
    service = build("gmail", "v1", credentials=creds)
    message = service.users().messages().get(userId="me", id=msg_id, format="raw").execute()
    raw_data = base64.urlsafe_b64decode(message["raw"])
    return raw_data

def parse_subject_and_sender(raw_bytes: bytes) -> Tuple[str, str]:
    msg = message_from_bytes(raw_bytes, policy=default)
    return msg.get("subject", "(No Subject)"), msg.get("from", "(Unknown)")
