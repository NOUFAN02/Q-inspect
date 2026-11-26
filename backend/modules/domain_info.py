import ssl
import socket
from datetime import datetime, timezone

from backend.modules.net_config import get_proxy_url, get_socks_proxy


def _verifying_context():
    """
    SSL context that verifies against the certifi CA bundle.

    On some systems (notably Windows + a venv Python), the default SSL context
    cannot locate the OS trust store, which makes EVERY certificate appear
    'untrusted' and produces false positives. Pinning certifi's bundle makes
    certificate validity deterministic across machines.
    """
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _open_socket(hostname, port, timeout=5):
    """
    Open a TCP socket to (hostname, port), routed through the configured proxy
    when one is set, so the SSL inspection never leaks the analyst's real IP.

    Returns (sock, None) on success, or (None, reason) when it must not connect
    directly (e.g. an HTTP-only proxy is set that cannot tunnel raw TLS).
    """
    proxy_url = get_proxy_url()

    if not proxy_url:
        # No anonymization requested: direct connection.
        return socket.create_connection((hostname, port), timeout=timeout), None

    socks_cfg = get_socks_proxy()
    if not socks_cfg:
        # A proxy is configured but it is not SOCKS; we cannot tunnel a raw TLS
        # socket through it without leaking, so skip the SSL check entirely.
        return None, "ssl_check_skipped_non_socks_proxy"

    try:
        import socks  # PySocks
    except ImportError:
        return None, "pysocks_not_installed"

    proxy_type = socks.SOCKS5 if socks_cfg["scheme"].startswith("socks5") else socks.SOCKS4
    s = socks.socksocket()
    s.set_proxy(
        proxy_type,
        socks_cfg["host"],
        socks_cfg["port"],
        rdns=True,  # resolve the target's DNS at the proxy (no local DNS leak)
    )
    s.settimeout(timeout)
    s.connect((hostname, port))
    return s, None


def get_domain_age(hostname):

    result = {
        "available": False,
        "domain": hostname,
        "creation_date": None,
        "age_days": None,
        "registrar": None,
        "error": None
    }

    if not hostname:
        result["error"] = "No hostname provided"
        return result

    try:
        import whois

        w = whois.whois(hostname)

        creation = w.creation_date

        # whois can return a list of dates
        if isinstance(creation, list):
            creation = creation[0]

        if creation is None:
            result["error"] = "Creation date not found in WHOIS"
            return result

        # Make sure creation is offset-aware for subtraction
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age = (now - creation).days

        result["available"] = True
        result["creation_date"] = creation.strftime("%Y-%m-%d")
        result["age_days"] = age
        result["registrar"] = str(w.registrar) if w.registrar else None

        return result

    except ImportError:
        result["error"] = "python-whois package not installed"
        return result

    except Exception as e:
        result["error"] = str(e)
        return result


def check_ssl_certificate(hostname, port=443):

    result = {
        "available": False,
        "valid": False,
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "self_signed": False,
        "error": None
    }

    if not hostname:
        result["error"] = "No hostname provided"
        return result

    try:
        # First try with verification enabled (against the certifi CA bundle)
        context = _verifying_context()

        sock, skip_reason = _open_socket(hostname, port, timeout=5)
        if sock is None:
            result["error"] = skip_reason
            return result

        with sock:

            with context.wrap_socket(
                sock, server_hostname=hostname
            ) as tls:

                cert = tls.getpeercert()

                result["available"] = True
                result["valid"] = True

                # Extract issuer
                issuer_parts = []

                for field in cert.get("issuer", ()):
                    for key, value in field:
                        if key == "organizationName":
                            issuer_parts.append(value)

                result["issuer"] = ", ".join(issuer_parts) or None

                # Extract subject
                subject_parts = []

                for field in cert.get("subject", ()):
                    for key, value in field:
                        if key == "commonName":
                            subject_parts.append(value)

                result["subject"] = ", ".join(subject_parts) or None

                # Parse dates
                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")

                if not_before:
                    nb = ssl.cert_time_to_seconds(not_before)
                    nb_dt = datetime.fromtimestamp(nb, tz=timezone.utc)
                    result["not_before"] = nb_dt.strftime("%Y-%m-%d")

                if not_after:
                    na = ssl.cert_time_to_seconds(not_after)
                    na_dt = datetime.fromtimestamp(na, tz=timezone.utc)
                    result["not_after"] = na_dt.strftime("%Y-%m-%d")

                    now = datetime.now(timezone.utc)
                    result["days_until_expiry"] = (na_dt - now).days

                # Check self-signed
                result["self_signed"] = (
                    result["issuer"] == result["subject"]
                )

                return result

    except ssl.SSLCertVerificationError:
        # Certificate exists but is invalid
        result["available"] = True
        result["valid"] = False
        result["error"] = "Certificate verification failed"

        # Try again without verification to get cert details
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            sock2, _ = _open_socket(hostname, port, timeout=5)
            if sock2 is None:
                return result

            with sock2 as sock:

                with ctx.wrap_socket(
                    sock, server_hostname=hostname
                ) as tls:

                    cert = tls.getpeercert(binary_form=True)

                    # We can at least note it's invalid
                    result["error"] = "Invalid or untrusted certificate"

        except Exception:
            pass

        return result

    except Exception as e:
        result["error"] = str(e)
        return result
