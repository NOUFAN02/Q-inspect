import httpx
from urllib.parse import urlsplit


REDIRECT_CODES = (301, 302, 303, 307, 308)


def analyze_redirects(url, client=None, max_redirects=10):

    if client is None:
        raise ValueError(
            "A controlled HTTPX client must be provided"
        )

    if max_redirects < 0:
        raise ValueError(
            "max_redirects cannot be negative"
        )

    redirect_chain = []
    visited_urls = set()

    current_url = url
    original_hostname = urlsplit(url).hostname

    redirect_count = 0

    for request_number in range(max_redirects + 1):

        # 1. Detect redirect loops
        if current_url in visited_urls:

            return {
                "success": True,
                "status": "redirect_loop",
                "original_url": url,
                "final_url": current_url,
                "redirect_chain": redirect_chain,
                "redirect_count": redirect_count,
                "domain_changed": (
                    original_hostname != urlsplit(current_url).hostname
                )
            }

        visited_urls.add(current_url)

        try:

            # 2. Send HTTP request
            response = client.get(
                current_url,
                follow_redirects=False
            )

            status_code = response.status_code

            redirect_chain.append({
                "url": current_url,
                "status_code": status_code
            })

            # 3. Check whether response is a redirect
            if status_code not in REDIRECT_CODES:
                break

            redirect_count += 1

            # 4. Extract redirect destination
            location = response.headers.get("location")

            if not location:
                break

            # 5. Check redirect limit
            if request_number == max_redirects:

                return {
                    "success": True,
                    "status": "max_redirects_reached",
                    "original_url": url,
                    "final_url": current_url,
                    "redirect_chain": redirect_chain,
                    "redirect_count": redirect_count,
                    "domain_changed": (
                        original_hostname != urlsplit(current_url).hostname
                    )
                }

            # 6. Resolve relative redirect URLs
            next_url = str(
                response.url.join(location)
            )

            parsed = urlsplit(next_url)

            # 7. Permit only HTTP and HTTPS
            if parsed.scheme.lower() not in ("http", "https"):

                return {
                    "success": False,
                    "status": "invalid_redirect",
                    "original_url": url,
                    "final_url": current_url,
                    "redirect_chain": redirect_chain,
                    "redirect_count": redirect_count,
                    "domain_changed": False
                }

            # 8. Reject embedded credentials
            if parsed.username is not None or parsed.password is not None:

                return {
                    "success": False,
                    "status": "invalid_redirect",
                    "original_url": url,
                    "final_url": current_url,
                    "redirect_chain": redirect_chain,
                    "redirect_count": redirect_count,
                    "domain_changed": False
                }

            # 9. Continue with the next destination
            current_url = next_url

        except httpx.RequestError as error:

            return {
                "success": False,
                "status": "request_failed",
                "original_url": url,
                "final_url": current_url,
                "redirect_chain": redirect_chain,
                "redirect_count": redirect_count,
                "domain_changed": (
                    original_hostname != urlsplit(current_url).hostname
                ),
                "error": str(error)
            }

    # 10. Return completed analysis
    final_hostname = urlsplit(current_url).hostname

    return {
        "success": True,
        "status": "completed",
        "original_url": url,
        "final_url": current_url,
        "redirect_chain": redirect_chain,
        "redirect_count": redirect_count,
        "domain_changed": original_hostname != final_hostname
    }