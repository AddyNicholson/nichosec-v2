# src/core/openai_client.py
import os
from dotenv import load_dotenv          # ← missing import
from openai import OpenAI

load_dotenv()                           # read .env first
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

__all__ = ["client"]                    # optional, but neat