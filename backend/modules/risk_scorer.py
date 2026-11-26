def calculate_risk(
    url_analysis=None,
    redirect_analysis=None,
    domain_info=None,
    shortener_info=None,
    safety_info=None,
    content_analysis=None,
    reputation=None
):

    score = 0
    breakdown = []

    # ── URL Analysis Indicators ──

    if url_analysis and url_analysis.get("valid_url"):

        if not url_analysis.get("uses_https"):
            score += 10
            breakdown.append({
                "indicator": "Uses HTTP instead of HTTPS",
                "points": 10,
                "severity": "medium"
            })

        if url_analysis.get("contains_ip_address"):
            score += 20
            breakdown.append({
                "indicator": "Uses IP address instead of domain name",
                "points": 20,
                "severity": "high"
            })

        if url_analysis.get("contains_credentials"):
            score += 25
            breakdown.append({
                "indicator": "Contains embedded credentials in URL",
                "points": 25,
                "severity": "high"
            })

        if url_analysis.get("uses_nonstandard_port"):
            score += 10
            breakdown.append({
                "indicator": "Uses a non-standard port",
                "points": 10,
                "severity": "medium"
            })

        if url_analysis.get("contains_punycode"):
            score += 20
            breakdown.append({
                "indicator": "Contains punycode (possible homograph attack)",
                "points": 20,
                "severity": "high"
            })

        subdomain_count = url_analysis.get("subdomain_count", 0)

        if subdomain_count >= 3:
            score += 15
            breakdown.append({
                "indicator": f"Excessive subdomains ({subdomain_count} levels)",
                "points": 15,
                "severity": "medium"
            })

        keywords = url_analysis.get("suspicious_keywords", [])
        keyword_points = min(len(keywords) * 5, 15)

        if keyword_points > 0:
            score += keyword_points
            breakdown.append({
                "indicator": (
                    f"Suspicious keywords in URL: "
                    f"{', '.join(keywords)}"
                ),
                "points": keyword_points,
                "severity": "low"
            })

        if url_analysis.get("url_length", 0) > 200:
            score += 5
            breakdown.append({
                "indicator": "Unusually long URL",
                "points": 5,
                "severity": "low"
            })

    # ── Safety Check Indicators ──

    if safety_info and not safety_info.get("safe"):
        reason = safety_info.get("reason", "")

        if reason == "private_or_non_global_ip":
            score += 30
            breakdown.append({
                "indicator": "URL resolves to a private/internal IP address",
                "points": 30,
                "severity": "critical"
            })

        elif reason == "dns_resolution_failed":
            score += 15
            breakdown.append({
                "indicator": "Domain could not be resolved (DNS failure)",
                "points": 15,
                "severity": "medium"
            })

        elif reason in ("embedded_credentials", "unsupported_scheme"):
            score += 20
            breakdown.append({
                "indicator": f"Safety check failed: {reason}",
                "points": 20,
                "severity": "high"
            })

    # ── URL Shortener ──

    if shortener_info and shortener_info.get("is_shortener"):
        score += 10
        service = shortener_info.get("service", "Unknown")
        breakdown.append({
            "indicator": f"URL uses a shortener service ({service})",
            "points": 10,
            "severity": "medium"
        })

    # ── Redirect Analysis Indicators ──

    if redirect_analysis and redirect_analysis.get("success"):

        count = redirect_analysis.get("redirect_count", 0)

        if count > 3:
            score += 10
            breakdown.append({
                "indicator": f"Long redirect chain ({count} hops)",
                "points": 10,
                "severity": "medium"
            })

        if redirect_analysis.get("domain_changed"):
            score += 15
            breakdown.append({
                "indicator": "Domain changed during redirects",
                "points": 15,
                "severity": "high"
            })

        status = redirect_analysis.get("status")

        if status == "redirect_loop":
            score += 20
            breakdown.append({
                "indicator": "Redirect loop detected",
                "points": 20,
                "severity": "high"
            })

        elif status == "max_redirects_reached":
            score += 15
            breakdown.append({
                "indicator": "Maximum redirect limit reached",
                "points": 15,
                "severity": "medium"
            })

    # ── Domain Age ──

    if domain_info:

        age_data = domain_info.get("domain_age") or {}

        if age_data.get("available"):
            age_days = age_data.get("age_days")

            if age_days is not None:

                if age_days < 30:
                    score += 25
                    breakdown.append({
                        "indicator": (
                            f"Domain is very new "
                            f"({age_days} days old)"
                        ),
                        "points": 25,
                        "severity": "critical"
                    })

                elif age_days < 90:
                    score += 15
                    breakdown.append({
                        "indicator": (
                            f"Domain is relatively new "
                            f"({age_days} days old)"
                        ),
                        "points": 15,
                        "severity": "medium"
                    })

        # ── SSL Certificate ──

        ssl_data = domain_info.get("ssl") or {}

        if ssl_data.get("available"):

            if not ssl_data.get("valid"):
                score += 15
                breakdown.append({
                    "indicator": "SSL certificate is invalid or untrusted",
                    "points": 15,
                    "severity": "high"
                })

            if ssl_data.get("self_signed"):
                score += 15
                breakdown.append({
                    "indicator": "SSL certificate is self-signed",
                    "points": 15,
                    "severity": "high"
                })

            days_left = ssl_data.get("days_until_expiry")

            if days_left is not None and days_left < 0:
                score += 10
                breakdown.append({
                    "indicator": "SSL certificate has expired",
                    "points": 10,
                    "severity": "high"
                })

    # ── Dynamic Content Analysis (Layer 2) ──
    # These signals come from actually rendering the page in a sandboxed
    # headless browser, so they catch phishing regardless of hosting/domain.

    if content_analysis and content_analysis.get("available"):

        has_password = content_analysis.get("has_password_field")
        brand_mismatch = content_analysis.get("brand_domain_mismatch")
        cross_domain = content_analysis.get("cross_domain_form")
        claimed_brands = content_analysis.get("claimed_brands", [])
        mismatch_details = content_analysis.get("mismatch_details", [])

        # Strongest fingerprint: a login (password field) on a page that
        # impersonates a known brand on an unrelated domain.
        if has_password and brand_mismatch:
            score += 55
            names = ", ".join(sorted({m.get("brand") for m in mismatch_details}))
            breakdown.append({
                "indicator": (
                    f"Credential-harvesting page impersonating "
                    f"[{names}] on an unrelated domain"
                ),
                "points": 55,
                "severity": "critical"
            })

        else:
            # Brand impersonation without a captured password field is still
            # a serious signal on its own.
            if brand_mismatch:
                names = ", ".join(sorted({m.get("brand") for m in mismatch_details}))
                score += 30
                breakdown.append({
                    "indicator": (
                        f"Page impersonates brand(s) [{names}] "
                        f"on an unrelated domain"
                    ),
                    "points": 30,
                    "severity": "high"
                })

            # A password field on a page with no legitimate brand context.
            if has_password and not brand_mismatch:
                score += 10
                breakdown.append({
                    "indicator": "Page requests a password / credentials",
                    "points": 10,
                    "severity": "medium"
                })

        # Login form that ships entered data to a different domain.
        if cross_domain:
            targets = content_analysis.get("cross_domain_targets", [])
            tgt_str = ", ".join(targets[:3]) if targets else "external domain"
            score += 20
            breakdown.append({
                "indicator": f"Form submits credentials to a different domain ({tgt_str})",
                "points": 20,
                "severity": "high"
            })

    # ── Threat-Intelligence Reputation (VirusTotal) ──
    # Known-bad is a strong confirmation. "Clean" is intentionally NOT rewarded
    # with a score reduction: brand-new phishing is absent from all feeds, so a
    # clean reputation is not evidence of safety (the sandbox layer covers it).

    if reputation and reputation.get("available"):
        mal = reputation.get("malicious", 0)
        sus = reputation.get("suspicious", 0)

        if mal >= 3:
            score += 40
            breakdown.append({
                "indicator": f"Flagged malicious by {mal} VirusTotal engines",
                "points": 40,
                "severity": "critical"
            })
        elif mal >= 1:
            score += 25
            breakdown.append({
                "indicator": f"Flagged malicious by {mal} VirusTotal engine(s)",
                "points": 25,
                "severity": "high"
            })
        elif sus >= 1:
            score += 10
            breakdown.append({
                "indicator": f"Flagged suspicious by {sus} VirusTotal engine(s)",
                "points": 10,
                "severity": "medium"
            })

    # ── Determine Verdict ──

    score = min(score, 100)

    if score <= 20:
        verdict = "safe"
        summary = "No significant threats detected"

    elif score <= 50:
        verdict = "caution"
        summary = "Some suspicious indicators found — proceed with care"

    else:
        verdict = "dangerous"
        summary = "Multiple threat indicators detected — do not visit"

    return {
        "score": score,
        "verdict": verdict,
        "summary": summary,
        "indicator_count": len(breakdown),
        "breakdown": breakdown
    }
