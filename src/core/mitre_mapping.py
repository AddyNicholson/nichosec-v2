# ── src/core/mitre_mapping.py ─────────────────────────────────────────

MITRE_MAP = {
    "spearphishing link": {
        "id": "T1566.001",
        "tactic": "Initial Access",
        "technique": "Phishing: Spearphishing Link"
    },
    "malicious redirect": {
        "id": "T1204.001",
        "tactic": "Execution",
        "technique": "User Execution: Malicious Link"
    },
    "obfuscated": {
        "id": "T1027",
        "tactic": "Defense Evasion",
        "technique": "Obfuscated Files or Information"
    },
    "javascript in body": {
        "id": "T1059.007",
        "tactic": "Execution",
        "technique": "JavaScript"
    },
    "fake unsubscribe link": {
        "id": "T1071.001",
        "tactic": "Command and Control",
        "technique": "Web Protocols"
    },
    "image-only blast": {
        "id": "T1566",
        "tactic": "Initial Access",
        "technique": "Phishing"
    },
    "storage.googleapis.com": {
        "id": "T1105",
        "tactic": "Command and Control",
        "technique": "Ingress Tool Transfer"
    },
    "tracking pixel": {
        "id": "T1070.006",
        "tactic": "Defense Evasion",
        "technique": "Indicator Removal on Host: Timestomp"
    },
    "shortened url": {
        "id": "T1204.002",
        "tactic": "Execution",
        "technique": "Malicious File"
    },    
    "spoofed sender": {
    "id": "T1585.001",
    "tactic": "Resource Development",
    "technique": "Impersonation: Email Accounts"
    },
    "executable attachment": {
        "id": "T1204.002",
        "tactic": "Execution",
        "technique": "Malicious File"
    },
    "macro attachment": {
        "id": "T1203.005",
        "tactic": "Execution",
        "technique": "Exploitation for Client Execution"
    },
    "dll download": {
        "id": "T1105",
        "tactic": "Command and Control",
        "technique": "Ingress Tool Transfer"
    },
    "base64 encoded payload": {
        "id": "T1027.002",
        "tactic": "Defense Evasion",
        "technique": "Obfuscated Files or Information: Software Packing"
    },
    "html smuggling": {
        "id": "T1027.006",
        "tactic": "Defense Evasion",
        "technique": "HTML Smuggling"
    },
    "external image load": {
        "id": "T1123",
        "tactic": "Collection",
        "technique": "Audio Capture"
    },
    "reply-to mismatch": {
        "id": "T1586.002",
        "tactic": "Resource Development",
        "technique": "Compromise Accounts: Email Accounts"
    },
    "link to executable": {
        "id": "T1204.001",
        "tactic": "Execution",
        "technique": "User Execution: Malicious Link"
    },
    "credential phishing page": {
        "id": "T1566.002",
        "tactic": "Initial Access",
        "technique": "Phishing: Spearphishing via Service"
    },
    "unknown tld domain": {
        "id": "T1566",
        "tactic": "Initial Access",
        "technique": "Phishing"
    },
    "encoded javascript": {
        "id": "T1059.007",
        "tactic": "Execution",
        "technique": "JavaScript"
    },
    "email forwarding rule": {
        "id": "T1114.003",
        "tactic": "Collection",
        "technique": "Email Collection: Email Forwarding Rule"
    },

}

