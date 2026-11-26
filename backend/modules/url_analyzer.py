import re
import ipaddress
from urllib.parse import urlsplit


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "update",
    "password",
    "banking",
    "wallet",
    "confirm"
]


def analyze_url(url):

    result = {
        "valid_url": False,
        "scheme": None,
        "hostname": None,
        "uses_https": False,
        "contains_ip_address": False,
        "contains_credentials": False,
        "uses_nonstandard_port": False,
        "contains_punycode": False,
        "subdomain_count": 0,
        "suspicious_keywords": [],
        "url_length": len(url),
        "indicators": []
    }

    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() not in ("http", "https"):
            result["indicators"].append("Unsupported URL scheme")
            return result

        hostname = parsed.hostname

        if not hostname:
            result["indicators"].append("Missing hostname")
            return result

        # Validate port syntax
        port = parsed.port

        result["valid_url"] = True
        result["scheme"] = parsed.scheme.lower()
        result["hostname"] = hostname
        result["uses_https"] = parsed.scheme.lower() == "https"

        # Check for HTTP instead of HTTPS
        if not result["uses_https"]:
            result["indicators"].append("Uses HTTP instead of HTTPS")

        # Check for embedded credentials
        if parsed.username is not None or parsed.password is not None:
            result["contains_credentials"] = True
            result["indicators"].append("Contains embedded URL credentials")

        # Check whether hostname is an IP address
        try:
            ipaddress.ip_address(hostname)
            result["contains_ip_address"] = True
            result["indicators"].append("Uses an IP address instead of a domain")
        except ValueError:
            pass

        # Check for nonstandard port
        if port is not None:
            default_port = 443 if result["uses_https"] else 80

            if port != default_port:
                result["uses_nonstandard_port"] = True
                result["indicators"].append("Uses a nonstandard port")

        # Check for punycode
        if "xn--" in hostname.lower():
            result["contains_punycode"] = True
            result["indicators"].append("Contains a punycode domain label")

        # Count subdomains (basic hostname-label heuristic)
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        if not is_ip:
            labels = hostname.rstrip(".").split(".")

            if len(labels) > 2:
                result["subdomain_count"] = len(labels) - 2

                if result["subdomain_count"] >= 3:
                    result["indicators"].append(
                        "Contains multiple subdomain labels"
                    )

        # Search for suspicious keywords
        url_lower = url.lower()

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                result["suspicious_keywords"].append(keyword)

        if result["suspicious_keywords"]:
            result["indicators"].append(
                "Contains potentially sensitive URL keywords"
            )

        # Check URL length
        if len(url) > 200:
            result["indicators"].append("Unusually long URL")

        return result

    except ValueError:
        result["indicators"].append("Malformed URL or invalid port")
        return result