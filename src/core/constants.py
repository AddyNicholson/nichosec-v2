PHISH_PATTERNS = {
    # core high-confidence patterns
    r"\bconfirm (?:your )?account\b":          4,
    r"\breset (?:your )?password\b":           4,
    r"\baccount (?:locked|suspended)\b":       4,
    r"\bpayment (?:failed|due)\b":             2,
    r"\bupdate billing\b":                     2,
    r"\bsecurity (?:alert|notification)\b":    2,
    r"\bverify identity\b":                    3,
    r"\bunauthori(?:z|s)ed login\b":           3,
    r"\bone[-\s]?time code\b":                 2,
    r"\bverification code\b":                  2,

    # softer “urgency” patterns
    r"\burgent\b":                             1,
    r"\baction required\b":                    2,
    r"\bclick here\b":                         1,

    # newsletter safe-signal
    r"\bunsubscribe\b":                       -1,
}



SAFE_IPS = {
    "203.36.205.14",   # Known FH sender
    "52.101.150.138",  # Microsoft relay
    "8.18.1.2",        # …etc…
    # new internal/mail-service IPs:
    "54.206.8.236",    # AWS SES for pb.propertysuite
}
