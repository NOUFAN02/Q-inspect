import re
from urllib.parse import urlparse


def classify_payload(payload):

    payload = payload.strip()

    if not payload:
        return {
            "type": "empty",
            "payload": payload
        }

    # 0. Payment requests (highest-risk QR category: money redirection)
    #    UPI (India), and common cryptocurrency payment URIs.
    low = payload.lower()
    if low.startswith((
        "upi://", "bitcoin:", "ethereum:", "litecoin:", "bitcoincash:",
        "dogecoin:", "monero:", "ripple:", "tron:", "tether:"
    )):
        return {
            "type": "payment",
            "payload": payload
        }

    # 1. Wi-Fi configuration
    if payload.upper().startswith("WIFI:"):
        return {
            "type": "wifi",
            "payload": payload
        }

    # 2. Contact information
    if payload.upper().startswith("BEGIN:VCARD") or \
       payload.upper().startswith("MECARD:"):

        return {
            "type": "contact",
            "payload": payload
        }

    # 3. Email
    if payload.lower().startswith("mailto:"):
        return {
            "type": "email",
            "payload": payload
        }

    # 4. Telephone
    if payload.lower().startswith("tel:"):
        return {
            "type": "telephone",
            "payload": payload
        }

    # 5. SMS
    if payload.lower().startswith(("sms:", "smsto:")):
        return {
            "type": "sms",
            "payload": payload
        }

    # 6. Geographic location
    if payload.lower().startswith("geo:"):
        return {
            "type": "location",
            "payload": payload
        }

    # 7. URL
    candidate = payload

    if candidate.lower().startswith("www."):
        candidate = "https://" + candidate

    parsed = urlparse(candidate)

    if parsed.scheme.lower() in ("http", "https") and parsed.hostname:
        return {
            "type": "url",
            "payload": payload
        }

    # 8. Plain text
    return {
        "type": "text",
        "payload": payload
    }