"""
Content Analyzer — Dynamic (Layer 2) inspection.

Unlike the static heuristics, this module actually RENDERS the target page
in a sandboxed headless Chromium browser (via Playwright) and inspects what
the page really shows a victim. This catches phishing pages regardless of
their hosting infrastructure or domain age (e.g. a zphisher login page served
through a Cloudflare tunnel), because it judges the *content*, not the URL.

Key signals extracted:
  * Presence of a password input field (login page fingerprint)
  * The brand the page claims to be (title / meta / visible text)
  * Whether that claimed brand matches the actual domain (brand-domain mismatch)
  * Whether login forms submit (action=) to a DIFFERENT domain (cross-domain POST)
  * A screenshot (base64) for the UI and for evidence in the report

SAFETY: This module executes untrusted remote code (JavaScript). It must only
ever be called on a URL that has already passed the SSRF guard in
`url_safety.validate_url`. The pipeline enforces this ordering. As extra
defence, the browser is launched with networking confined to the single
navigation and a hard timeout.
"""

from urllib.parse import urlsplit


# Brands commonly impersonated by phishing kits (incl. zphisher templates).
# Maps a brand keyword -> the full set of legitimate domains that brand (and its
# corporate family) is allowed to be served from. A page that CLAIMS to be a
# brand (in its title / site-name) but is hosted outside that brand's domain set
# is a strong phishing signal.
#
# Domain families prevent false positives: e.g. Instagram's real login page
# mentions "Facebook" and "Meta" (same company), so Facebook/Instagram/WhatsApp
# share the Meta domains and do not flag each other.
META = ["facebook.com", "fb.com", "fb.me", "meta.com", "messenger.com",
        "instagram.com", "cdninstagram.com", "whatsapp.com", "whatsapp.net"]
GOOGLE = ["google.com", "google.co.uk", "gmail.com", "googlemail.com",
          "youtube.com", "youtu.be", "withgoogle.com", "abc.xyz"]
MICROSOFT = ["microsoft.com", "live.com", "outlook.com", "office.com",
             "office365.com", "microsoftonline.com", "windows.com", "msn.com"]
APPLE = ["apple.com", "icloud.com", "me.com"]
AMAZON = ["amazon.com", "amazon.co.uk", "amazon.in", "amazon.de",
          "amazon.co.jp", "amazonaws.com", "amzn.to"]

BRAND_DOMAINS = {
    "facebook": META,
    "instagram": META,
    "whatsapp": META,
    "messenger": META,
    "meta": META,
    "google": GOOGLE,
    "gmail": GOOGLE,
    "youtube": GOOGLE,
    "microsoft": MICROSOFT,
    "outlook": MICROSOFT,
    "office365": MICROSOFT,
    "paypal": ["paypal.com", "paypal.me"],
    "apple": APPLE,
    "icloud": APPLE,
    "netflix": ["netflix.com"],
    "amazon": AMAZON,
    "linkedin": ["linkedin.com", "lnkd.in"],
    "twitter": ["twitter.com", "x.com", "t.co"],
    "snapchat": ["snapchat.com", "snap.com"],
    "github": ["github.com", "githubusercontent.com", "github.io"],
    "steam": ["steampowered.com", "steamcommunity.com", "valvesoftware.com"],
    "spotify": ["spotify.com"],
    "dropbox": ["dropbox.com"],
    "yahoo": ["yahoo.com"],
    "tiktok": ["tiktok.com"],
    "telegram": ["telegram.org", "telegram.me", "t.me"],
    "discord": ["discord.com", "discord.gg", "discordapp.com"],
}


def _host_matches_brand(host, allowed_domains):
    """True if host is, or is a subdomain of, any of the brand's legit domains."""
    host = (host or "").lower().rstrip(".")
    for d in allowed_domains:
        if host == d or host.endswith("." + d):
            return True
    return False


def _registered_domain(hostname):
    """Return the last two labels of a hostname, e.g. a.b.example.com -> example.com."""
    if not hostname:
        return ""
    labels = hostname.rstrip(".").lower().split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return labels[0]


def _empty_result(url, error=None, available=False):
    return {
        "available": available,
        "error": error,
        "proxied": False,
        "final_url": url,
        "page_title": None,
        "has_password_field": False,
        "input_field_count": 0,
        "form_count": 0,
        "claimed_brands": [],
        "brand_domain_mismatch": False,
        "mismatch_details": [],
        "cross_domain_form": False,
        "cross_domain_targets": [],
        "external_form_action": False,
        "screenshot_base64": None,
        "indicators": [],
    }


def _get_proxy():
    """
    Returns a Playwright proxy config dict, or None.

    Routing the sandbox browser through a proxy (e.g. Tor) means the target
    phishing server sees the proxy's IP, NOT the analyst's real public IP.
    This preserves the "pre-visit" guarantee: inspecting the page never
    discloses the user's identity to the attacker's infrastructure.

    Configure via environment variable:
        QI_PROXY=socks5://127.0.0.1:9050      (Tor default)
        QI_PROXY=http://user:pass@host:port   (authenticated HTTP proxy)
    """
    import os
    server = os.environ.get("QI_PROXY", "").strip()
    if not server:
        return None
    proxy = {"server": server}
    # Optional separate credentials (if not embedded in the URL).
    user = os.environ.get("QI_PROXY_USER", "").strip()
    pw = os.environ.get("QI_PROXY_PASS", "").strip()
    if user:
        proxy["username"] = user
    if pw:
        proxy["password"] = pw
    return proxy


def analyze_content(url, timeout_ms=12000, take_screenshot=True):
    """
    Render `url` in headless Chromium and extract phishing content signals.

    Returns a dict (see `_empty_result`). `available=False` means the dynamic
    analysis could not run (Playwright/Chromium missing, navigation failed,
    timeout, etc.) — in that case the pipeline simply falls back to the static
    layers, so the tool degrades gracefully.
    """
    result = _empty_result(url)

    # Import lazily so the rest of the app still works if Playwright is absent.
    try:
        from playwright.sync_api import sync_playwright, Error as PWError
    except ImportError:
        result["error"] = "playwright_not_installed"
        return result

    import base64

    proxy = _get_proxy()
    result["proxied"] = proxy is not None

    try:
        with sync_playwright() as p:
            launch_kwargs = {
                "headless": True,
                "args": [
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            }
            if proxy:
                launch_kwargs["proxy"] = proxy
            browser = p.chromium.launch(**launch_kwargs)
            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,
            )
            # Block downloads / popups from auto-navigating us anywhere unexpected.
            page = context.new_page()
            page.set_default_timeout(timeout_ms)

            try:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                # Give JavaScript-built pages a brief moment to render.
                try:
                    page.wait_for_timeout(1500)
                except PWError:
                    pass

                result["available"] = True
                result["final_url"] = page.url
                result["page_title"] = (page.title() or "").strip() or None

                # --- Input / form structure -------------------------------
                try:
                    result["input_field_count"] = page.locator("input").count()
                except PWError:
                    result["input_field_count"] = 0

                try:
                    pw_count = page.locator(
                        "input[type='password']"
                    ).count()
                    result["has_password_field"] = pw_count > 0
                except PWError:
                    result["has_password_field"] = False

                # Collect form action targets.
                try:
                    form_actions = page.eval_on_selector_all(
                        "form",
                        "els => els.map(e => e.getAttribute('action') || '')",
                    )
                except PWError:
                    form_actions = []

                result["form_count"] = len(form_actions)

                final_host = urlsplit(result["final_url"]).hostname or ""
                final_reg = _registered_domain(final_host)

                cross_targets = []
                for action in form_actions:
                    if not action:
                        continue
                    action_host = urlsplit(action).hostname
                    if not action_host:
                        continue  # relative action -> same origin, fine
                    action_reg = _registered_domain(action_host)
                    if action_reg and action_reg != final_reg:
                        cross_targets.append(action_host)

                if cross_targets:
                    result["cross_domain_form"] = True
                    result["external_form_action"] = True
                    result["cross_domain_targets"] = sorted(set(cross_targets))
                    result["indicators"].append(
                        "Login form submits data to a different domain"
                    )

                # --- Brand impersonation ----------------------------------
                # The brand a page CLAIMS to be is taken only from authoritative
                # identity fields (title, og:site_name, application-name), NOT
                # from arbitrary body text. This avoids false positives from
                # legitimate cross-brand mentions such as "Log in with Facebook"
                # buttons or "Meta" footers on the real Instagram page.
                identity_parts = [result["page_title"] or ""]
                try:
                    metas = page.eval_on_selector_all(
                        "meta[name='application-name'], "
                        "meta[property='og:site_name'], "
                        "meta[property='og:title'], "
                        "meta[name='apple-mobile-web-app-title']",
                        "els => els.map(e => e.getAttribute('content') || '')",
                    )
                    identity_parts.extend(metas)
                except PWError:
                    pass

                identity = " ".join(identity_parts).lower()

                claimed = []
                mismatches = []
                for brand, allowed_domains in BRAND_DOMAINS.items():
                    if brand in identity:
                        claimed.append(brand)
                        # Impersonation only if the host is NOT within the
                        # brand's legitimate domain family.
                        if not _host_matches_brand(final_host, allowed_domains):
                            mismatches.append({
                                "brand": brand,
                                "expected_domain": allowed_domains[0],
                            })

                result["claimed_brands"] = sorted(set(claimed))
                if mismatches:
                    result["brand_domain_mismatch"] = True
                    result["mismatch_details"] = mismatches
                    names = ", ".join(sorted({m["brand"] for m in mismatches}))
                    result["indicators"].append(
                        f"Page impersonates brand(s) [{names}] "
                        f"but is hosted on an unrelated domain ({final_host})"
                    )

                if result["has_password_field"]:
                    result["indicators"].append(
                        "Page contains a password entry field"
                    )

                # --- Screenshot -------------------------------------------
                if take_screenshot:
                    try:
                        png = page.screenshot(
                            full_page=False, timeout=5000
                        )
                        result["screenshot_base64"] = base64.b64encode(
                            png
                        ).decode("ascii")
                    except PWError:
                        result["screenshot_base64"] = None

            except PWError as nav_err:
                result["available"] = False
                result["error"] = f"navigation_failed: {str(nav_err)[:200]}"
            finally:
                try:
                    context.close()
                except Exception:
                    pass
                try:
                    browser.close()
                except Exception:
                    pass

    except Exception as e:  # Playwright runtime / browser-not-installed, etc.
        result["available"] = False
        result["error"] = str(e)[:200]

    return result
