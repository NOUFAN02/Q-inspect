import httpx
from urllib.parse import urlsplit

from backend.modules.qr_decoder import decode_qr
from backend.modules.payload_classifier import classify_payload
from backend.modules.url_safety import validate_url
from backend.modules.url_analyzer import analyze_url
from backend.modules.redirect_analyzer import analyze_redirects
from backend.modules.shortener_detector import detect_shortener
from backend.modules.domain_info import get_domain_age, check_ssl_certificate
from backend.modules.content_analyzer import analyze_content
from backend.modules.reputation import check_reputation
from backend.modules.payload_risk import analyze_non_url_payload
from backend.modules.net_config import get_proxy_url
from backend.modules.risk_scorer import calculate_risk


def inspect_url(target_url, client=None, perform_network_checks=True,
                perform_content_analysis=True, perform_reputation=True):
    """
    Runs full multi-stage security analysis on a URL.
    Can be used both for URLs decoded from QR codes and direct URL inputs.
    """
    report = {
        "target_url": target_url,
        "safety_check": None,
        "url_analysis": None,
        "shortener_info": None,
        "redirect_analysis": None,
        "domain_info": {
            "domain_age": None,
            "ssl": None
        },
        "content_analysis": None,
        "reputation": None,
        "risk_assessment": None
    }

    # 1. Static URL analysis (does not need network)
    url_analysis = analyze_url(target_url)
    report["url_analysis"] = url_analysis

    # 2. Shortener detection
    shortener_info = detect_shortener(target_url)
    report["shortener_info"] = shortener_info

    # 3. SSRF / Safety validation before making any network requests
    safety_info = validate_url(target_url)
    report["safety_check"] = safety_info

    # If unsafe destination (e.g. private IP, localhost, cloud metadata), abort network requests
    if not safety_info.get("safe"):
        report["risk_assessment"] = calculate_risk(
            url_analysis=url_analysis,
            redirect_analysis=None,
            domain_info=None,
            shortener_info=shortener_info,
            safety_info=safety_info
        )
        return report

    # 4. Network-based checks (if enabled)
    redirect_analysis = None
    domain_info = {"domain_age": None, "ssl": None}

    if perform_network_checks:
        # A. Redirect analysis
        close_client = False
        if client is None:
            # Route redirect-following through the same proxy (e.g. Tor) so the
            # target server never sees the analyst's real IP. None = direct.
            proxy_url = get_proxy_url()
            client_kwargs = {
                "timeout": 6.0,
                "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) QInspect/1.0"},
                "trust_env": False,
            }
            if proxy_url:
                client_kwargs["proxy"] = proxy_url
            client = httpx.Client(**client_kwargs)
            close_client = True

        try:
            redirect_analysis = analyze_redirects(target_url, client=client)
            report["redirect_analysis"] = redirect_analysis
        finally:
            if close_client:
                client.close()

        # Destination hostname to check (use final redirect URL hostname if available)
        final_url = redirect_analysis.get("final_url", target_url) if redirect_analysis else target_url
        try:
            target_host = urlsplit(final_url).hostname or urlsplit(target_url).hostname
        except Exception:
            target_host = urlsplit(target_url).hostname

        # B. Domain age & SSL inspection
        if target_host:
            domain_info["domain_age"] = get_domain_age(target_host)
            domain_info["ssl"] = check_ssl_certificate(target_host)
            report["domain_info"] = domain_info

    # 5. Dynamic content analysis (Layer 2) — only runs AFTER the SSRF guard
    #    has cleared the destination as a public, safe host. This renders the
    #    page in a sandboxed headless browser to detect phishing content that
    #    the URL/infra heuristics cannot see.
    content_analysis = None
    if perform_network_checks and perform_content_analysis:
        final_target = (
            redirect_analysis.get("final_url", target_url)
            if redirect_analysis else target_url
        )
        content_analysis = analyze_content(final_target)
        report["content_analysis"] = content_analysis

    # 6. Threat-intelligence reputation (VirusTotal). Queries VT, not the
    #    target, so it needs no proxy. Runs only when an API key is configured.
    reputation = None
    if perform_network_checks and perform_reputation:
        final_target = (
            redirect_analysis.get("final_url", target_url)
            if redirect_analysis else target_url
        )
        reputation = check_reputation(final_target)
        report["reputation"] = reputation

    # 7. Calculate overall risk score
    risk_assessment = calculate_risk(
        url_analysis=url_analysis,
        redirect_analysis=redirect_analysis,
        domain_info=domain_info,
        shortener_info=shortener_info,
        safety_info=safety_info,
        content_analysis=content_analysis,
        reputation=reputation
    )
    report["risk_assessment"] = risk_assessment

    return report


def process_qr(image_path, client=None, perform_network_checks=True):
    """
    Main orchestration entry point:
    Step 1: Decode QR image
    Step 2: Classify payload type
    Step 3: Route based on payload (URL -> inspect_url, others -> informational report)
    """
    # 1. Decode QR code
    decode_result = decode_qr(image_path)
    if not decode_result["success"]:
        return {
            "success": False,
            "message": decode_result["message"],
            "payload": None,
            "classification": None,
            "details": None
        }

    raw_payload = decode_result["payload"]

    # 2 + 3. Classify and analyse the decoded payload.
    return analyze_payload_text(
        raw_payload, client=client,
        perform_network_checks=perform_network_checks
    )


def analyze_payload_text(raw_payload, client=None, perform_network_checks=True):
    """
    Classify and analyse an already-decoded QR payload (text). This is shared
    by process_qr (QR image) and the /api/scan-payload endpoint used by the
    mobile app, which decodes the QR on-device and sends the raw text.
    """
    if raw_payload is None or str(raw_payload).strip() == "":
        return {
            "success": False,
            "message": "Empty payload — nothing to analyse.",
            "payload": raw_payload,
            "classification": None,
            "details": None,
        }

    classification = classify_payload(raw_payload)
    payload_type = classification.get("type")

    result = {
        "success": True,
        "message": "Payload processed successfully",
        "payload": raw_payload,
        "classification": payload_type,
        "details": None,
    }

    # Route handling
    if payload_type == "url":
        url_to_inspect = raw_payload.strip()
        if url_to_inspect.lower().startswith("www."):
            url_to_inspect = "https://" + url_to_inspect
        elif not (url_to_inspect.startswith("http://") or url_to_inspect.startswith("https://")):
            url_to_inspect = "https://" + url_to_inspect

        result["details"] = inspect_url(
            target_url=url_to_inspect,
            client=client,
            perform_network_checks=perform_network_checks
        )

    else:
        # Non-URL payload types (payment, wifi, sms, telephone, contact,
        # email, text, ...) get type-specific analysis, plus inspection of any
        # URL embedded inside them (e.g. a phishing link inside a vCard).
        details, embedded = analyze_non_url_payload(payload_type, raw_payload)

        embedded_reports = []
        worst_embedded = None
        if perform_network_checks:
            for emb in embedded[:3]:  # cap to avoid abuse via many URLs
                try:
                    rep = inspect_url(
                        target_url=emb,
                        client=client,
                        perform_network_checks=perform_network_checks,
                    )
                    embedded_reports.append(rep)
                    ra = rep.get("risk_assessment") or {}
                    if worst_embedded is None or ra.get("score", 0) > worst_embedded:
                        worst_embedded = ra.get("score", 0)
                except Exception:
                    continue

        details["embedded_reports"] = embedded_reports

        # Merge: the payload's own risk, raised by the worst embedded URL.
        own = details.get("risk_assessment", {})
        if worst_embedded is not None and worst_embedded > own.get("score", 0):
            own["breakdown"] = list(own.get("breakdown", [])) + [{
                "indicator": f"Embedded link assessed as high-risk (score {worst_embedded})",
                "points": worst_embedded - own.get("score", 0),
                "severity": "high",
            }]
            own["score"] = worst_embedded
            own["verdict"] = ("dangerous" if worst_embedded > 50
                              else "caution" if worst_embedded > 20 else "safe")
            own["summary"] = "Embedded link raised the risk - " + own.get("summary", "")
            details["risk_assessment"] = own

        result["details"] = details

    return result
