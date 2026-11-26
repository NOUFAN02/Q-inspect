"""
Central network-egress configuration.

Every outbound connection the scanner makes to an untrusted target
(redirect following, SSL inspection, sandbox page render) must respect the
SAME proxy so the analyst's real public IP is never disclosed to the phishing
infrastructure.

Configure once via environment variable:
    QI_PROXY=socks5://127.0.0.1:9050      (Tor default)
    QI_PROXY=http://user:pass@host:port   (authenticated HTTP proxy)

When QI_PROXY is unset, scans run directly (fast, but the target server sees
your IP). The UI reports which mode was used.
"""

import os
from urllib.parse import urlsplit

# Load configuration from a .env file in the project root, if present, so the
# VirusTotal key and the Tor proxy can be set once instead of exported every
# session. Real environment variables still take precedence (override=False).
try:
    from dotenv import load_dotenv
    _ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    load_dotenv(os.path.join(_ROOT, ".env"), override=False)
except Exception:
    pass


def get_proxy_url():
    """Return the configured proxy URL string, or None for a direct connection."""
    return os.environ.get("QI_PROXY", "").strip() or None


def get_socks_proxy():
    """
    Parse QI_PROXY into (host, port) if it is a SOCKS proxy, else None.

    Used for routing raw TLS sockets (SSL certificate inspection) through the
    proxy via PySocks. Only SOCKS proxies are supported for raw sockets;
    HTTP-CONNECT tunnelling of raw TLS is not implemented.
    """
    url = get_proxy_url()
    if not url:
        return None
    parsed = urlsplit(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("socks5", "socks5h", "socks4", "socks4a"):
        return None
    host = parsed.hostname
    port = parsed.port or 9050
    if not host:
        return None
    return {"host": host, "port": port, "scheme": scheme}
