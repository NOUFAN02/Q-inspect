import socket
import ipaddress

from urllib.parse import urlsplit


ALLOWED_SCHEMES = ("http", "https")

ALLOWED_PORTS = (80, 443)


def is_safe_ip(address):

    try:
        ip = ipaddress.ip_address(address)

        # Handle IPv4-mapped IPv6 addresses
        if isinstance(ip, ipaddress.IPv6Address):
            if ip.ipv4_mapped is not None:
                ip = ip.ipv4_mapped

        # Only globally routable IP addresses are permitted
        if not ip.is_global:
            return False

        return True

    except ValueError:
        return False


def validate_url(url):

    result = {
        "safe": False,
        "url": url,
        "hostname": None,
        "resolved_ips": [],
        "reason": None
    }

    # 1. Check URL format
    try:
        parsed = urlsplit(url)

        hostname = parsed.hostname

    except (ValueError, TypeError):
        result["reason"] = "invalid_url"
        return result

    if not hostname:
        result["reason"] = "missing_hostname"
        return result

    # 2. Check permitted schemes
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        result["reason"] = "unsupported_scheme"
        return result

    # 3. Reject embedded credentials
    if parsed.username is not None or parsed.password is not None:
        result["reason"] = "embedded_credentials"
        return result

    # 4. Check the port
    try:
        port = parsed.port

    except ValueError:
        result["reason"] = "invalid_port"
        return result

    if port is not None and port not in ALLOWED_PORTS:
        result["reason"] = "nonstandard_port"
        return result

    # 5. Normalize hostname
    try:
        hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()

    except UnicodeError:
        result["reason"] = "invalid_hostname"
        return result

    result["hostname"] = hostname

    # 6. Check whether hostname is already an IP address
    try:
        ip = ipaddress.ip_address(hostname)

        addresses = [str(ip)]

    except ValueError:

        # 7. Resolve domain names using DNS
        try:

            dns_results = socket.getaddrinfo(
                hostname,
                port or (443 if parsed.scheme.lower() == "https" else 80),
                type=socket.SOCK_STREAM
            )

            addresses = list({
                item[4][0]
                for item in dns_results
            })

        except socket.gaierror:
            result["reason"] = "dns_resolution_failed"
            return result

    result["resolved_ips"] = addresses

    # 8. Reject the destination if ANY resolved address is unsafe
    for address in addresses:

        if not is_safe_ip(address):

            result["reason"] = "private_or_non_global_ip"
            return result

    # 9. All checks passed
    result["safe"] = True
    result["reason"] = "public_destination"

    return result