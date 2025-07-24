# src/core/email_ioc.py  (updated)

import ipaddress, re, quopri, base64
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse, unquote_plus

from src.core.threat_intel import lookup_ip_threat   # 
from src.core.constants import SAFE_IPS  
from src.core.thresholds import THREAT_THRESHOLDS
from src.core.utils import smarten_ip_verdict
# ── REGEX ---------------------------------------------------------------
IP_RE  = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"(?:https?|hxxp)://[^\s\"'<>]+", re.I)   # hxxp → http later

PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16"
    )
]

# ── helpers -------------------------------------------------------------
def _decode_payload(part) -> str:
    raw = part.get_payload(decode=True)
    charset = part.get_content_charset() or "utf-8"
    try:
        return raw.decode(charset, errors="replace")
    except (LookupError, AttributeError):
        return raw.decode("utf-8", "replace")


def _is_public_ipv4(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.version != 4:
        return False
    return not any(ip in net for net in PRIVATE_NETS)


# ── IOC extraction ------------------------------------------------------
def extract_iocs(text: str):
    """Return (public_ips, urls, domains)."""
    # IPs
    raw_ips = {ip for ip in IP_RE.findall(text) if _is_public_ipv4(ip)}

    # URLs
    urls = set(URL_RE.findall(text))
    # normalise hxxp → http
    urls = {u.replace("hxxp://", "http://") for u in urls}

    # Domains
    domains = {urlparse(u).netloc for u in urls if urlparse(u).netloc}

    return sorted(raw_ips), sorted(urls), sorted(domains)


# ── EML parser ----------------------------------------------------------
def parse_eml(blob: bytes) -> dict:
    """Parse .eml bytes → metadata + IOCs + auth + IP-reputation."""
    msg = BytesParser(policy=policy.default).parsebytes(blob)

    frm      = str(msg.get("from"   , ""))
    to       = str(msg.get("to"     , ""))
    subject  = str(msg.get("subject", ""))
    date_hdr = str(msg.get("date"   , ""))

    # --- Auth results ---------------------------------------------------
    auth_hdr = str(msg.get("authentication-results") or "").lower()
    def _res(tag: str) -> str:
        if f"{tag}=pass" in auth_hdr:  return "pass"
        if f"{tag}=fail" in auth_hdr:  return "fail"
        return "none"
    spf, dkim, dmarc = _res("spf"), _res("dkim"), _res("dmarc")

    # --- Body extraction ------------------------------------------------
    bodies = []
    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            bodies.append(_decode_payload(part))
    joined_body = "\n".join(bodies)

    # --- IOC extraction -------------------------------------------------
    ips, urls, domains = extract_iocs("\n".join([joined_body, auth_hdr, str(msg)]))

    

# --- IP reputation (adds ~50-100 ms) --------------------------------
    
    ip_details = {}
    high_risk = False


    for ip in ips:
        if ip in SAFE_IPS:
            print(f"[SAFE] {ip} skipped")
            continue

        try:
            intel = lookup_ip_threat(ip)
            verdict, adjusted_score = smarten_ip_verdict(
                intel, email_sender=frm  # use the parsed sender
            )
            
            ip_details[ip] = {
                **intel,
                "verdict": verdict,
                "adjusted_score": adjusted_score
            }

            if adjusted_score >= THREAT_THRESHOLDS["RED"]:
                print(f"🚨 HIGH RISK IP DETECTED: {ip} with adjusted score {adjusted_score}")
                high_risk = True

        except Exception as e:
            ip_details[ip] = {"error": str(e)}
            print(f"[ERROR] IP lookup failed for {ip}: {e}")




    return {
        "from":    frm,
        "to":      to,
        "subject": subject,
        "date":    date_hdr,
        "spf":     spf,
        "dkim":    dkim,
        "dmarc":   dmarc,

        "ips":        ips,
        "ip_details": ip_details,   # ← new
        "high_risk_ip_hit": high_risk,

        "urls":    urls,
        "domains": domains,
        "raw_body": joined_body,
    }
