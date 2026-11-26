"""
Payload Risk Analyzer — risk assessment for NON-URL QR payloads.

A QR code can encode much more than a URL, and several of these types are
actively abused. Previously the pipeline returned a flat "score 0" for anything
that was not a URL; this module gives each type its own analysis:

  * payment  (upi:// , bitcoin: , ...) : payment-redirection fraud
  * wifi     (WIFI:...)                : open / weakly-encrypted / hidden APs
  * sms/tel  (smsto: , tel:)           : premium-rate / scam numbers
  * contact  (vCard / MeCard)          : embedded malicious URL or number
  * email    (mailto:)                 : embedded malicious URL / phishing

For every type, any embedded http(s) URL is extracted so the caller can run it
through the full URL inspection pipeline and merge the result.
"""

import re
from urllib.parse import urlsplit, parse_qs, unquote


URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.IGNORECASE)


def extract_urls(text):
    """Return a de-duplicated list of http(s) URLs found anywhere in `text`."""
    if not text:
        return []
    seen, out = set(), []
    for m in URL_RE.findall(text):
        u = m.rstrip(".,;")
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _verdict(score):
    if score <= 20:
        return "safe"
    if score <= 50:
        return "caution"
    return "dangerous"


def _assessment(score, summary, breakdown):
    score = min(score, 100)
    return {
        "score": score,
        "verdict": _verdict(score),
        "summary": summary,
        "indicator_count": len(breakdown),
        "breakdown": breakdown,
    }


# ---------------------------------------------------------------------------
#  Payment (UPI / cryptocurrency)
# ---------------------------------------------------------------------------
def analyze_payment(payload):
    breakdown = []
    info = {"scheme": None, "payee": None, "payee_name": None, "amount": None}
    low = payload.lower()

    # Baseline: a QR that initiates a PAYMENT (money leaving the user) always
    # warrants caution, because the scanner cannot verify the payee is genuine.
    score = 25
    breakdown.append({
        "indicator": "QR initiates a payment — verify the payee before paying",
        "points": 25,
        "severity": "medium",
    })

    if low.startswith("upi://"):
        info["scheme"] = "UPI"
        # upi://pay?pa=payee@bank&pn=Name&am=100&cu=INR
        q = parse_qs(urlsplit(payload).query)
        info["payee"] = (q.get("pa") or [None])[0]
        info["payee_name"] = (q.get("pn") or [None])[0]
        info["amount"] = (q.get("am") or [None])[0]

        if info["amount"]:
            score += 10
            breakdown.append({
                "indicator": f"Pre-filled payment amount ({info['amount']})",
                "points": 10,
                "severity": "medium",
            })
        if not info["payee"]:
            score += 10
            breakdown.append({
                "indicator": "UPI request has no verifiable payee address (pa)",
                "points": 10,
                "severity": "medium",
            })
    else:
        # Cryptocurrency: bitcoin:<address>?amount=...
        info["scheme"] = payload.split(":", 1)[0].lower()
        rest = payload.split(":", 1)[1] if ":" in payload else ""
        info["payee"] = rest.split("?")[0] or None
        q = parse_qs(urlsplit(payload).query)
        info["amount"] = (q.get("amount") or [None])[0]
        # Crypto payments are irreversible -> slightly higher baseline concern.
        score += 10
        breakdown.append({
            "indicator": "Cryptocurrency payment address (transfers are irreversible)",
            "points": 10,
            "severity": "medium",
        })

    summary = (
        f"{info['scheme']} payment request"
        + (f" to {info['payee']}" if info['payee'] else "")
        + ". Confirm the recipient is who you expect before paying."
    )
    return {"type": "payment", "info": info,
            "risk_assessment": _assessment(score, summary, breakdown)}


# ---------------------------------------------------------------------------
#  Wi-Fi
# ---------------------------------------------------------------------------
def _parse_wifi(payload):
    # WIFI:T:WPA;S:MySSID;P:pass;H:true;;  (fields order-independent)
    body = payload[5:] if payload.upper().startswith("WIFI:") else payload
    fields = {}
    for part in re.split(r"(?<!\\);", body):
        if ":" in part:
            k, _, v = part.partition(":")
            fields[k.strip().upper()] = v.strip()
    return fields


def analyze_wifi(payload):
    f = _parse_wifi(payload)
    enc = (f.get("T") or "").upper()
    ssid = f.get("S")
    hidden = (f.get("H") or "").lower() == "true"
    breakdown = []
    score = 0

    if enc in ("", "NOPASS"):
        score += 25
        breakdown.append({
            "indicator": "Open / unencrypted Wi-Fi (prone to eavesdropping)",
            "points": 25, "severity": "medium"})
    elif enc == "WEP":
        score += 20
        breakdown.append({
            "indicator": "Wi-Fi uses WEP, a broken/insecure encryption scheme",
            "points": 20, "severity": "medium"})

    if hidden:
        score += 10
        breakdown.append({
            "indicator": "Hidden SSID (can facilitate evil-twin impersonation)",
            "points": 10, "severity": "low"})

    summary = (f"Wi-Fi network '{ssid}'" if ssid else "Wi-Fi configuration")
    summary += (" - open/insecure" if score >= 20 else " - password protected")
    return {"type": "wifi", "info": {"ssid": ssid, "encryption": enc or "OPEN",
            "hidden": hidden},
            "risk_assessment": _assessment(score, summary, breakdown)}


# ---------------------------------------------------------------------------
#  SMS / Telephone — premium-rate / scam number detection
# ---------------------------------------------------------------------------
PREMIUM_PREFIXES = ("190", "1900", "900", "809", "284", "876")  # indicative


def _number_from(payload):
    s = payload.split(":", 1)[1] if ":" in payload else payload
    s = s.split(":", 1)[0].split("?")[0]
    return re.sub(r"[^\d+]", "", s)


def analyze_sms_tel(payload, kind):
    num = _number_from(payload)
    breakdown = []
    score = 0
    digits = num.lstrip("+")
    # Also test the number without a leading NANP country code '1', so that
    # Caribbean premium/scam area codes (e.g. +1 876 ...) are caught.
    candidates = {digits}
    if digits.startswith("1"):
        candidates.add(digits[1:])

    if any(d.startswith(p) for p in PREMIUM_PREFIXES for d in candidates):
        score += 30
        breakdown.append({
            "indicator": f"Possible premium-rate / high-cost number ({num})",
            "points": 30, "severity": "high"})
    if kind == "sms":
        score += 10
        breakdown.append({
            "indicator": "QR pre-composes an SMS — may send a paid/scam message",
            "points": 10, "severity": "low"})

    label = "SMS" if kind == "sms" else "phone call"
    summary = f"QR triggers a {label} to {num or 'an unspecified number'}."
    return {"type": kind, "info": {"number": num},
            "risk_assessment": _assessment(score, summary, breakdown)}


# ---------------------------------------------------------------------------
#  Contact (vCard/MeCard) & Email — mostly about embedded content
# ---------------------------------------------------------------------------
def analyze_generic(payload, kind):
    """Contact/email/text: risk driven mainly by any embedded URL (handled by
    the caller) plus a small base note."""
    breakdown = []
    score = 0
    summary = {
        "contact": "Contact card — inspect any embedded link or number.",
        "email": "Pre-composed email — inspect any embedded link.",
        "text": "Plain-text payload.",
    }.get(kind, f"{kind} payload.")
    return {"type": kind, "info": {},
            "risk_assessment": _assessment(score, summary, breakdown)}


# ---------------------------------------------------------------------------
#  Dispatcher
# ---------------------------------------------------------------------------
def analyze_non_url_payload(payload_type, raw_payload):
    """
    Return a details dict (with 'risk_assessment') for a non-URL payload, plus
    a list of embedded URLs the caller should inspect separately.
    """
    if payload_type == "payment":
        details = analyze_payment(raw_payload)
    elif payload_type == "wifi":
        details = analyze_wifi(raw_payload)
    elif payload_type == "sms":
        details = analyze_sms_tel(raw_payload, "sms")
    elif payload_type == "telephone":
        details = analyze_sms_tel(raw_payload, "telephone")
    elif payload_type in ("contact", "email", "text"):
        details = analyze_generic(raw_payload, payload_type)
    else:
        details = {
            "type": payload_type,
            "info": {},
            "risk_assessment": _assessment(
                0, f"Non-executable {payload_type} payload", []),
        }

    embedded = extract_urls(raw_payload)
    # Don't treat the payment/wifi scheme itself as an embedded http URL.
    details["embedded_urls"] = embedded
    return details, embedded
