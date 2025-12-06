# nichosec_scan_engine.py 
# ✅ Cleaned and fixed as of 2025-07-18
# This script includes all prior fixes: scoped variables, verdict label mapping, and fallback safeguards.

# ── Imports ────────────────────────────────────────────────────────────
import ipaddress, re, time, urllib.parse as up
from urllib.parse           import urlparse
from typing                 import Dict, List
from openai                 import APIError, RateLimitError

from bs4                    import BeautifulSoup
from email                  import policy
from email.parser           import BytesParser
from email.message          import Message
from hashlib                import md5
from io                     import BytesIO
from docx                   import Document
import fitz  # PyMuPDF
import hashlib

# ── Internal Modules ───────────────────────────────────────────────────
from src.core.openai_client  import client
from src.core.constants      import SAFE_IPS, PHISH_PATTERNS
from src.core.thresholds     import THREAT_THRESHOLDS
from src.core.reports        import save_result
from src.core.mitre_mapping  import MITRE_MAP
from src.core.threat_intel   import lookup_ip_threat, virustotal_lookup, upload_to_hybrid

from .email_ioc import parse_eml, extract_iocs
from .utils import extract_urls

from .utils                  import (
    parse_json,
    keyword_analysis,
    extract_urls,
    extract_ips,
    smarten_ip_verdict,
)


# ── Helper functions (image-only or link spam) ─────────────────────────
def has_plain_text(msg: Message) -> bool:
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            return True
    return False

def image_only_with_links(html_body: str) -> bool:
    doc = BeautifulSoup(html_body, "html.parser")
    text = doc.get_text(strip=True)
    imgs = doc.find_all("img")
    links = doc.find_all("a", href=True)

    if len(text) < 50 and imgs and links:
        return True
    if len(text) < 100 and len(links) > 3 and not imgs:
        return True
    if len(text) < 1000 and len(imgs) >= 1 and len(links) >= 3:
        return True
    return False

def is_suspicious_blast_pattern(eml_obj: Message) -> bool:
    if has_plain_text(eml_obj):
        return False
    sender = eml_obj.get("from", "").lower()
    TRUSTED = {"yourcompany.com", "mailchimp.com", "trusted-newsletter.com"}
    sender_domain = sender.split("@")[-1]
    if sender_domain in TRUSTED:
        return False
    for part in eml_obj.walk():
        if part.get_content_type() == "text/html":
            body = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
            if image_only_with_links(body):
                return True
    return False

# ── Constants ──────────────────────────────────────────────────────────
ALLOW_RANGES = {"zip.co": ipaddress.ip_network("167.89.0.0/17")}
TRUSTED_PHP_HOSTS = {"pb.propertysuite.co.nz", "catherinerichardson.propertybrokers.co.nz"}
AUTH_WEIGHT = -30
IP_MAX_POINTS = 40
CONTENT_MAX = 70

# ── Utility ─────────────────────────────────────────────────────────────
def is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def classify(points: int) -> str:
    if points >= THREAT_THRESHOLDS["RED"]:
        return "RED"
    elif points >= THREAT_THRESHOLDS["YELLOW"]:
        return "YELLOW"
    return "GREEN"

def is_whitelisted(frm_domain: str, ip: str) -> bool:
    net = ALLOW_RANGES.get(frm_domain.lower())
    try:
        return bool(net and ipaddress.ip_address(ip) in net)
    except ValueError:
        return False

def extract_from_domain(raw: str) -> str:
    m = re.search(r"^From:\s*.*?@([^>\s]+)", raw, flags=re.I | re.M)
    return m.group(1).lower() if m else ""

def auth_results(raw: str) -> dict:
    def got(pat: str) -> bool:
        return bool(re.search(pat, raw, flags=re.I))
    return {
        "spf": got(r"spf=pass"),
        "dkim": got(r"dkim=pass"),
        "dmarc": got(r"dmarc=pass"),
    }
def extract_domains(urls: list[str]) -> list[str]:
    domains = []
    for u in urls:
        try:
            parsed = urlparse(u)
            domain = parsed.netloc.lower()
            if domain:
                domains.append(domain)
        except:
            continue
    return domains


def compute_hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }


def scan_docx(file_bytes: bytes, filename: str) -> dict:
    doc = Document(BytesIO(file_bytes))
    text = "\n".join(p.text for p in doc.paragraphs if p.text.strip())

    words = text.split()
    word_count = len(words)

    report = {
        "source": "docx",
        "filename": filename,
        "word_count": word_count,
        "scan_time": 0.0,
        "summary": "Scanned .docx document.",
        "level": "GREEN",
        "reasons": [],
        "urls": extract_urls(text),
        "ips": extract_ips(text),
        "domains": extract_domains(text),
    }

    return report


def scan_pdf(file_bytes: bytes, filename: str) -> dict:
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    text = ""
    for page in doc:
        text += page.get_text()

    word_count = len(text.split())
    page_count = len(doc)

    report = {
        "source": "pdf",
        "filename": filename,
        "page_count": page_count,
        "word_count": word_count,
        "scan_time": 0.0,
        "summary": "Scanned PDF document.",
        "level": "GREEN",
        "reasons": [],
        "urls": extract_urls(text),
        "ips": extract_ips(text),
        "domains": extract_domains(text),
    }

    return report


def scan(raw: str | bytes, purge: bool = False) -> dict:
    t0 = time.perf_counter()
    ips, eml, reasons, llm_reasons = [], {}, [], []

    vt_data, sandbox_data, file_hashes = {}, {}, {}

    # ── Parse email if bytes ───────────────────────────────
    if isinstance(raw, (bytes, bytearray)) and b"\nFrom:" in raw:
        msg_obj = BytesParser(policy=policy.default).parsebytes(raw)
        eml = parse_eml(raw)
        eml["domains"] = extract_domains(eml.get("urls", []))
        ips = eml.get("ips", [])
        file_hashes = compute_hashes(raw)

        sha256 = file_hashes["sha256"]
        vt_data = virustotal_lookup(sha256)
        sandbox_data = upload_to_hybrid(raw, filename="scan_file.eml")

        if eml.get("spf") == "fail" or eml.get("dkim") == "fail":
            reasons.append("Sender failed SPF or DKIM checks")

        php_links = [
            u for u in eml["urls"]
            if u.lower().endswith(".php") and urlparse(u).netloc.lower() not in TRUSTED_PHP_HOSTS
        ]
        if php_links:
            reasons.append(f"{len(php_links)} .php link(s) on non-whitelisted hosts")

        if eml.get("high_risk_ip_hit"):
            risky = [ip for ip in eml["ips"] if ip not in SAFE_IPS]
            if risky:
                reasons.append("Mail relayed via high-risk IP (fraud ≥ 70)")

        if is_suspicious_blast_pattern(msg_obj):
            reasons.append("Image-only blast with embedded links")

    # Decode bytes if necessary
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode(errors="ignore")
    body = raw.partition("\n\n")[2] or raw

    # Fallback IP extraction
    if not ips:
        ips = sorted({w.strip('.,;:') for w in raw.split() if is_valid_ip(w)})

    frm_domain = extract_from_domain(raw)
    auth = auth_results(raw)

    # ── Keyword & Content Analysis ─────────────────────────
    kw_score, kw_reasons = keyword_analysis(body)
    content_points = min(kw_score * 10, CONTENT_MAX)
    if "<script" in body.lower():
        content_points += 15
        kw_reasons.append("Inline <script> tag detected")

    # ── Domain Analysis ───────────────────────────────────
    domain_points = 0
    domain_reasons = []
    domain_keywords = {"login", "secure", "verify", "update", "account", "click", "free", "urgent"}
    bad_domains = {"badsite.com", "phishy.biz", "known-scam.co"}

    extracted_domains = set([frm_domain] if frm_domain else [])
    for u in eml.get("urls", []):
        try:
            d = urlparse(u).netloc.lower()
            if d:
                extracted_domains.add(d)
        except:
            continue

    for d in extracted_domains:
        if d in bad_domains:
            domain_points += 25
            domain_reasons.append(f"Domain {d} is blacklisted")
        if any(k in d for k in domain_keywords):
            domain_points += 10
            domain_reasons.append(f"Suspicious keyword in domain: {d}")
        if len(d.split(".")) < 2 or not d.split(".")[-1].isalpha():
            domain_points += 5
            domain_reasons.append(f"Malformed or suspicious domain format: {d}")

    domain_points = min(domain_points, 60)  # increase cap for multiple bad domains

    # ── IP Threat Intelligence ─────────────────────────────
    ip_risks, ip_scores, ip_threats = {"avg":0,"high":0,"medium":0,"count":0}, [], {}
    for ip in ips:
        if ip in SAFE_IPS:
            continue
        intel = lookup_ip_threat(ip)
        ip_threats[ip] = intel
        score = intel.get("adjusted_score", intel.get("fraud_score", 0))

        if frm_domain and is_whitelisted(frm_domain, ip):
            score = 0
        elif auth["spf"] and auth["dkim"] and auth["dmarc"]:
            score *= 0.4
        elif auth["dmarc"]:
            score *= 0.6

        ip_scores.append(score)
        ip_risks["count"] += 1
        ip_risks["avg"] += score
        if score >= THREAT_THRESHOLDS["RED"]:
            ip_risks["high"] += 1
        elif score >= THREAT_THRESHOLDS["YELLOW"]:
            ip_risks["medium"] += 1

    if ip_risks["count"]:
        ip_risks["avg"] /= ip_risks["count"]

    # Forced escalation for high-risk IP
    high_risk_ips = [s for s in ip_scores if s >= 70]
    if high_risk_ips:
        ip_points = max(ip_scores)
        reasons.append(f"{len(high_risk_ips)} high-risk IP(s) detected; forced escalation")
    else:
        ip_points = min(sum(ip_scores) * 0.4, IP_MAX_POINTS)

    # Add IP threat summary to reasons
    if ip_risks["count"]:
        reasons.append(f"Scanned {ip_risks['count']} IP(s); avg threat score: {ip_risks['avg']:.1f}")
        if ip_risks["high"]:
            reasons.append(f"{ip_risks['high']} IP(s) HIGH risk")
        if ip_risks["medium"]:
            reasons.append(f"{ip_risks['medium']} IP(s) MODERATE risk")

    # ── LLM Analysis ──────────────────────────────────────
    llm_level, llm_summary, llm_reasons, t_llm = "YELLOW", "LLM unavailable", [], 0.0
    try:
        t0_llm = time.perf_counter()
        links = "\n".join(f"- {up.unquote(l)[:120]}" for l in re.findall(r"href=['\"]?([^'\" >]+)", body, flags=re.I)[:20]) or "None"
        prompt = f"""
        Analyze this email for phishing indicators.
        Decide RED / YELLOW / GREEN.
        Return strict JSON: {{"level":"","summary":"","reasons":[]}}

        Visible links:\n{links}
        """
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt + "\n\n" + body[:15000]}],
            temperature=0.1
        )
        ans = parse_json(resp.choices[0].message.content)
        llm_level   = ans.get("level", "YELLOW").upper()
        llm_summary = ans.get("summary", "No summary")
        llm_reasons = ans.get("reasons", [])
        t_llm = round(time.perf_counter() - t0_llm, 2)
    except Exception:
        pass

    # ── Compute final score ───────────────────────────────
    llm_points = {"GREEN":0, "YELLOW":20, "RED":50}[llm_level]
    auth_points = AUTH_WEIGHT if all(auth.values()) else 0
    risk_points = max(0, content_points + domain_points + ip_points + llm_points + auth_points)

    final_label = classify(risk_points)
    final_verdict = {
        "GREEN":  "No signs of phishing or malicious activity",
        "YELLOW": "Some suspicious patterns detected",
        "RED":    "Significant phishing or malicious indicators detected"
    }[final_label]

    # Forced escalation for VirusTotal or Sandbox
    if any([
        vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious",0) >= 3,
        sandbox_data.get("threat_score",0) >= 60,
        high_risk_ips
    ]) and final_label == "GREEN":
        final_label = "YELLOW"
        final_verdict = "Suspicious indicators detected; escalation applied"
        reasons.append("Forced escalation due to critical IP, VirusTotal, or Hybrid Analysis score")

    summary = f"{final_verdict} ({final_label}, score={risk_points:.1f})"

    # ── Assemble result ───────────────────────────────────
    all_reasons = kw_reasons + llm_reasons + domain_reasons + reasons
    mitre_hits = [MITRE_MAP[p] for p in MITRE_MAP if any(p in r.lower() for r in all_reasons)]

    result = {
        "level": final_label,
        "summary": summary,
        "reasons": all_reasons,
        "ips": eml.get("ips", ips),
        "components": {
            "auth": auth_points,
            "ip": ip_points,
            "content": content_points,
            "domain": domain_points,
            "llm": llm_points,
            "hashes": file_hashes,
            "vt": vt_data,
            "sandbox": sandbox_data
        },
        "scan_time": t_llm,
        "threat_summary": "Threat summary unavailable",
        "ip_scores": {ip: round(s,1) for ip,s in zip(ips, ip_scores)},
        "ip_threats": ip_threats,
        "mitre_techniques": mitre_hits,
        "from": eml.get("from","—"),
        "to": eml.get("to","—"),
        "subject": eml.get("subject","—"),
        "date": eml.get("date","—")
    }

    # Optional purge
    if purge and final_label != "GREEN":
        cleaned = "\n".join(
            l for l in raw.splitlines()
            if not any(t in l.lower() for t in ("seed phrase","wire transfer","password"))
        )
        result["cleaned"] = cleaned[:10000]

    return result
