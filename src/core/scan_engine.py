# nichosec_scan_engine.py 
# ✅ Cleaned and fixed as of 2025-07-18
# This script includes all prior fixes: scoped variables, verdict label mapping, and fallback safeguards.

# ── Imports ────────────────────────────────────────────────────────────
import ipaddress, re, time, urllib.parse as up
from urllib.parse           import urlparse
from typing                 import Dict, List
from openai                 import APIError, RateLimitError
from src.core.openai_client import client
from src.core.threat_intel  import lookup_ip_threat
from .email_ioc             import parse_eml, extract_iocs, extract_urls, extract_ips

from .utils                 import parse_json, keyword_analysis
from .constants             import PHISH_PATTERNS
from src.core.constants     import SAFE_IPS
from src.core.thresholds    import THREAT_THRESHOLDS
from src.core.utils         import smarten_ip_verdict
from bs4                    import BeautifulSoup
from email                  import policy
from email.parser           import BytesParser
from email.message          import Message
from src.core.reports       import save_result
from src.core.mitre_mapping import MITRE_MAP
import urllib.parse as up
import hashlib
import fitz  # PyMuPDF
from docx                   import Document
from io                     import BytesIO

from src.core.threat_intel import lookup_ip_threat, virustotal_lookup, upload_to_hybrid

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


# ── Main Scan Function ─────────────────────────────────────────────────
def scan(raw: str | bytes, purge: bool = False) -> dict:
    t0 = time.perf_counter()
    final_score = 0
    final_label = "GREEN"
    final_verdict = "No signs of phishing or malicious activity"
    ips, eml, reasons = [], {}, []
    llm_reasons = []

    vt_data = {}
    sandbox_data = {}
    file_hashes = {}


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
        php_links = [u for u in eml["urls"] if u.lower().endswith(".php") and urlparse(u).netloc.lower() not in TRUSTED_PHP_HOSTS]
        if php_links:
            reasons.append(f"{len(php_links)} .php link(s) on non-whitelisted hosts")
        if eml.get("high_risk_ip_hit"):
            risky = [ip for ip in eml["ips"] if ip not in SAFE_IPS]
            if risky:
                reasons.append("Mail relayed via high-risk IP (fraud ≥ 70)")
        if is_suspicious_blast_pattern(msg_obj):
            reasons.append("Image-only blast with embedded links")

    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode(errors="ignore")

    body = raw.partition("\n\n")[2] or raw
    if not ips:
        ips = sorted({w.strip('.,;:') for w in raw.split() if is_valid_ip(w)})

    frm_domain = extract_from_domain(raw)
    auth = auth_results(raw)
    
    # ── 2️⃣ IP THREAT INTELLIGENCE ──────────────────────────────────────
    
    ip_risks  = {"avg": 0, "high": 0, "medium": 0, "count": 0}
    ip_scores = []
    ip_threats = {}
    for ip in ips:
        if ip in SAFE_IPS:
            continue
        intel = lookup_ip_threat(ip)
        ip_threats[ip] = intel 
        score = intel.get("adjusted_score", intel.get("fraud_score", 0))
        
        # ── AUTH + WHITELIST ADJUSTMENT ────────────────────────
        if frm_domain and is_whitelisted(frm_domain, ip):
            score = 0
        elif auth["spf"] and auth["dkim"] and auth["dmarc"]:
            score *= 0.4
        elif auth["dmarc"]:
            score *= 0.6

        # ② now record it
        ip_scores.append(score)
        ip_risks["count"] += 1
        ip_risks["avg"]   += score
        if score >= THREAT_THRESHOLDS["RED"]:
            ip_risks["high"] += 1
        elif score >= THREAT_THRESHOLDS["YELLOW"]:
            ip_risks["medium"] += 1
        
        
    if ip_risks["count"] > 0:
        ip_risks["avg"] /= ip_risks["count"]

    # translate raw counts → a friendly verdict + 0–100 score
    ip_verdict, ip_score = smarten_ip_verdict(ip_risks)
    ip_points = min(ip_score * 0.4, IP_MAX_POINTS)

    # Add readable IP threat report to reasons
    if ip_risks["count"]:
        reasons.append(f"Scanned {ip_risks['count']} IP(s); avg threat score: {ip_risks['avg']:.1f}")
        if ip_risks["high"] > 0:
            reasons.append(f"{ip_risks['high']} IP(s) marked as HIGH risk")
        if ip_risks["medium"] > 0:
            reasons.append(f"{ip_risks['medium']} IP(s) marked as MODERATE risk")

    kw_score, kw_reasons = keyword_analysis(body)
    content_points = min(kw_score * 10, CONTENT_MAX)
    if "<script" in body.lower():
        content_points += 15
        kw_reasons.append("Inline <script> tag")

    
    
    # ── DOMAIN ANALYSIS ───────────────────────────────────────────────
    domain_points = 0
    domain_reasons = []
    domain_keywords = {"login", "secure", "verify", "update", "account", "click", "free", "urgent"}
    bad_domains = {"badsite.com", "phishy.biz", "known-scam.co"}  # TODO: Replace with live intel later

    extracted_domains = set()

    # ① From address domain
    from_domain = frm_domain
    if from_domain:
        extracted_domains.add(from_domain)

    # ② Domains from links
    for u in eml.get("urls", []):
        try:
            d = urlparse(u).netloc.lower()
            if d:
                extracted_domains.add(d)
        except:
            continue

    # ③ Evaluate domains
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

    # Cap domain points to avoid wild spikes
    domain_points = min(domain_points, 40)


    links = re.findall(r"href=['\"]?([^'\" >]+)", body, flags=re.I)
    link_list = "\n".join(f"- {up.unquote(l)[:120]}" for l in links[:20]) or "None"
    prompt = f"""
    Analyze this email for phishing indicators.
    Decide **RED** / **YELLOW** / **GREEN**.
    Return strict JSON: {{"level":"","summary":"","reasons":[]}}

    Visible links:\n{link_list}
    """

    llm_level, llm_summary, llm_reasons, t_llm = "YELLOW", "LLM unavailable", [], 0.0
       # … your first LLM call …
    try:
        t0 = time.perf_counter()
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt + "\n\n" + body[:15000]}],
            temperature=0.1,
        )
        ans = parse_json(resp.choices[0].message.content)
        llm_level   = ans.get("level",   "YELLOW").upper()
        llm_summary = ans.get("summary", "No summary")
        llm_reasons = ans.get("reasons",  [])
        t_llm       = round(time.perf_counter() - t0, 2)
    
    except (RateLimitError, APIError):
        # we swallow LLM errors and keep the defaults below
        pass
    
     # ── MITRE TTP Mapping ───────────────────────────────────────────────
    try:
        # OpenAI LLM call here
        ...
        llm_reasons = ans.get("reasons", [])
    except Exception as e:
        print("LLM error:", e)  # Optional for debugging
        

    # ✅ Safe now
    all_reasons = kw_reasons + llm_reasons + reasons
    mitre_hits = []
    for reason in all_reasons:
        for pattern, mitre in MITRE_MAP.items():
            if pattern in reason.lower():
                mitre_hits.append(mitre)

      # Calculate contributions
    llm_points   = {"GREEN": 0, "YELLOW": 20, "RED": 50}[llm_level]
    auth_points  = AUTH_WEIGHT if all(auth.values()) else 0
    risk_points  = max(0, content_points + ip_points + llm_points + auth_points)

    # (full reasons & metadata remain in result, and can be downloaded)
    final_label  = classify(risk_points)
    final_verdict = {
        "GREEN":  "No signs of phishing or malicious activity",
        "YELLOW": "Some suspicious patterns detected",
        "RED":    "Significant phishing or malicious indicators detected"
    }[final_label]

    # Only show verdict + score
    summary = f"{final_verdict} ({final_label}, score={risk_points:.1f})"
    threat_summary = "Threat summary unavailable"
  
    # ── AI One-liner Threat Summary ────────────────────────────────
    
    try:
        # Build top reasons with IP risk included
        top_reasons = (kw_reasons + llm_reasons + reasons)
        ip_risk_line = (
            f"Average IP threat score: {ip_risks['avg']:.1f} with {ip_risks['high']} high-risk IP(s)"
            if ip_risks["count"] else ""
        )
        top_reasons = ([ip_risk_line] if ip_risk_line else []) + top_reasons
        top_reasons = top_reasons[:4]  # Limit total lines for context

        # Call GPT to generate concise threat summary
        resp_summary = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity analyst. "
                        "In one concise sentence, summarize the overall threat level "
                        "and main risk indicator(s) of this email."
                    )
                },
                {
                    "role": "user",
                    "content": (
                        f"Threat level: {final_label}\n"
                        "Top reasons:\n" + "\n".join(top_reasons)
                    )
                },
            ],
            temperature=0.2,
        )
        threat_summary = resp_summary.choices[0].message.content.strip()
    except Exception:
        if final_label == "GREEN":
            threat_summary = "The email poses no signs of phishing or malicious activity."
        else:
            threat_summary = f"Threat level: {final_label} — summary unavailable due to system error."       
            pass
    # ─ Condensed verdicts ────────────────────────────────────────────────
    vt_summary = {
        "malicious": vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
        "suspicious": vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("suspicious", 0),
        "undetected": vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("undetected", 0),
        "reputation": vt_data.get("data", {}).get("attributes", {}).get("reputation", 0),
        "permalink": vt_data.get("data", {}).get("links", {}).get("self", "")
    }

    sandbox_summary = {
        "score": sandbox_data.get("threat_score", 0),
        "verdict": sandbox_data.get("verdict", "Unknown"),
        "submitted_url": sandbox_data.get("submit_name", "N/A"),
        "environment": sandbox_data.get("environment_description", "N/A"),
    }

    # Optional scoring logic
    if vt_summary["malicious"] >= 3:
        reasons.append(f"{vt_summary['malicious']} engines flagged this file in VirusTotal.")

    if sandbox_summary["score"] >= 60:
        reasons.append(f"Hybrid Analysis score: {sandbox_summary['score']} – Verdict: {sandbox_summary['verdict']}")

    
    # ── Assemble the final result ───────────────────────────────────── 
    result = {
        "level":         final_label,
        "summary":       summary,
        "reasons":       kw_reasons + llm_reasons + reasons,
        "ips":           eml.get("ips", ips),
        "components": {
            "auth":    auth_points,
            "ip":      ip_points,
            "content": content_points,
            "llm":     llm_points,
            "hashes": file_hashes,
            "vt": vt_summary,
            "sandbox": sandbox_summary,
        },
        "scan_time":      t_llm,
        "threat_summary": threat_summary,
        "ip_scores":  {ip: round(s, 1) for ip, s in zip(ips, ip_scores)},
        "ip_threats": ip_threats,
        "mitre_techniques": mitre_hits,


        # ⬇️ New: For PDF reporting
        "from":    eml.get("from", "—"),
        "to":      eml.get("to", "—"),
        "subject": eml.get("subject", "—"),
        "date":    eml.get("date", "—")
    }

    if purge and final_label != "GREEN":
        cleaned = "\n".join(
            l for l in raw.splitlines()
            if not any(t in l.lower() for t in ("seed phrase", "wire transfer", "password"))
        )
        result["cleaned"] = cleaned[:10000]

    return result