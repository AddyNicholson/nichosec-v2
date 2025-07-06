import hashlib
from datetime import datetime

class Threat:
    def __init__(self, risk: str, details: str, metadata: dict,
                 sha256: str = None, campaign_id: str = None):
        self.risk        = risk
        self.details     = details
        self.metadata    = metadata
        self.sha256      = sha256
        self.campaign_id = campaign_id

    def __repr__(self):
        return f"<Threat {self.risk.upper()} sha={self.sha256[:8]}>"

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def scan(raw_text: str, ip_input: str | None = None) -> Threat:
    risk = "red" if "urgent" in raw_text.lower() else "green"
    details = "Contains 'urgent' keyword → possible phishing" if risk == "red" \
              else "No obvious indicators."

    metadata = {
        "timestamp": datetime.utcnow().isoformat(),
        "length": len(raw_text),
        "ips_checked": bool(ip_input),
    }

    sha = sha256_bytes(raw_text.encode())
    return Threat(risk, details, metadata, sha256=sha)
