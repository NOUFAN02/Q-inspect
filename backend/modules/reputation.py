"""
Reputation Layer — Threat-Intelligence corroboration (VirusTotal).

Looks the target up in VirusTotal's aggregated database (~70 engines) to find
out whether it is ALREADY a known threat. This complements, but does not
replace, the dynamic sandbox layer:

  * VirusTotal MALICIOUS  -> strong confirmation (large score contribution).
  * VirusTotal CLEAN      -> weak signal only. Freshly created phishing pages
                             (e.g. a zphisher + Cloudflare tunnel) are NOT yet
                             in any feed, so "clean" must never be treated as
                             proof of safety. The sandbox layer covers those.

Design choices:
  * LOOKUP-ONLY. We issue GET requests for an EXISTING report (by URL id /
    domain / IP). We never POST a URL for scanning, so we do not cause a visit
    to the target and do not broadcast/queue the URL publicly.
  * URL and DOMAIN reputation are weighted above IP reputation, because
    phishing frequently hides behind shared reputable hosting (e.g. Cloudflare)
    whose IPs look clean.
  * Graceful degradation: with no API key, or on rate-limit / network error,
    the layer reports available=False and the pipeline relies on other layers.

Configuration:
    QI_VT_API_KEY = <your VirusTotal API v3 key>   (free tier is sufficient)
"""

import os
import base64
from urllib.parse import urlsplit

from backend.modules import net_config  # noqa: F401  (ensures .env is loaded)

VT_BASE = "https://www.virustotal.com/api/v3"


def get_vt_api_key():
    return os.environ.get("QI_VT_API_KEY", "").strip() or None


def _url_to_vt_id(url):
    """VirusTotal URL id = base64url(url) with '=' padding stripped."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")


def _empty(available=False, error=None):
    return {
        "available": available,
        "source": "VirusTotal",
        "error": error,
        "queried": [],
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "total_engines": 0,
        "verdict": "unknown",   # malicious | suspicious | clean | unknown
        "details": {},
    }


def _fetch_stats(client, path, headers):
    """
    GET a VT report. Returns (stats_dict, status) where stats_dict is the
    last_analysis_stats or None. status is one of: 'ok', 'not_found',
    'rate_limited', 'error'.
    """
    try:
        resp = client.get(f"{VT_BASE}/{path}", headers=headers, timeout=8.0)
    except Exception:
        return None, "error"

    if resp.status_code == 404:
        return None, "not_found"      # target not in VT database (unknown)
    if resp.status_code == 429:
        return None, "rate_limited"
    if resp.status_code != 200:
        return None, "error"

    try:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return stats, "ok"
    except Exception:
        return None, "error"


def check_reputation(url, client=None, check_ip=False):
    """
    Look up `url` (and its domain, optionally its IP) in VirusTotal.

    `client` is an optional httpx.Client. NOTE: reputation queries go to
    VirusTotal (a trusted third party), not to the target, so they do not need
    to be proxied for IP-anonymity. They DO disclose the target URL to VT —
    an accepted, documented trade-off of using threat intelligence.
    """
    result = _empty()

    api_key = get_vt_api_key()
    if not api_key:
        result["error"] = "no_api_key"
        return result

    headers = {"x-apikey": api_key}

    host = urlsplit(url).hostname or ""

    close_client = False
    if client is None:
        try:
            import httpx
            client = httpx.Client(trust_env=False)
            close_client = True
        except Exception as e:
            result["error"] = f"httpx_unavailable: {e}"
            return result

    worst = {"malicious": 0, "suspicious": 0, "harmless": 0, "total": 0}
    any_ok = False
    rate_limited = False

    try:
        # 1. URL reputation (strongest signal)
        stats, status = _fetch_stats(client, f"urls/{_url_to_vt_id(url)}", headers)
        _record(result, worst, "url", stats, status)
        any_ok = any_ok or status == "ok"
        rate_limited = rate_limited or status == "rate_limited"

        # 2. Domain reputation
        if host:
            stats, status = _fetch_stats(client, f"domains/{host}", headers)
            _record(result, worst, "domain", stats, status)
            any_ok = any_ok or status == "ok"
            rate_limited = rate_limited or status == "rate_limited"

        # 3. IP reputation (weakest; opt-in) — only if host is not already an IP
        if check_ip and host:
            stats, status = _fetch_stats(client, f"ip_addresses/{host}", headers)
            # IP is weighted lightly; record but do not let it dominate.
            _record(result, worst, "ip", stats, status, weight=0.5)
            any_ok = any_ok or status == "ok"
            rate_limited = rate_limited or status == "rate_limited"

    finally:
        if close_client:
            try:
                client.close()
            except Exception:
                pass

    result["malicious"] = worst["malicious"]
    result["suspicious"] = worst["suspicious"]
    result["harmless"] = worst["harmless"]
    result["total_engines"] = worst["total"]

    if any_ok:
        result["available"] = True
        if worst["malicious"] >= 1:
            result["verdict"] = "malicious"
        elif worst["suspicious"] >= 1:
            result["verdict"] = "suspicious"
        else:
            result["verdict"] = "clean"   # known to VT, nothing flagged it
    else:
        result["available"] = False
        result["verdict"] = "unknown"
        statuses = [q.get("status") for q in result["queried"]]
        if rate_limited:
            result["error"] = "rate_limited"
        elif statuses and all(s == "not_found" for s in statuses):
            # Key worked, queries succeeded, but the target is simply not in the
            # VirusTotal database yet (common for brand-new phishing).
            result["error"] = "not_found"
        else:
            result["error"] = "unavailable"

    return result


def _record(result, worst, kind, stats, status, weight=1.0):
    """Merge one VT report's stats, keeping the worst (highest malicious) seen."""
    result["queried"].append({"kind": kind, "status": status})
    if status != "ok" or not stats:
        return
    mal = int(stats.get("malicious", 0) * weight)
    sus = int(stats.get("suspicious", 0) * weight)
    harm = int(stats.get("harmless", 0))
    total = sum(int(v) for v in stats.values())
    result["details"][kind] = {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
    }
    # Keep the strongest malicious signal across the queried objects.
    if mal > worst["malicious"] or (
        mal == worst["malicious"] and sus > worst["suspicious"]
    ):
        worst["malicious"] = mal
        worst["suspicious"] = sus
        worst["harmless"] = harm
        worst["total"] = total
