from urllib.parse import urlsplit


SHORTENER_DOMAINS = {
    "bit.ly": "Bitly",
    "bitly.com": "Bitly",
    "tinyurl.com": "TinyURL",
    "t.co": "Twitter/X",
    "goo.gl": "Google",
    "ow.ly": "Hootsuite",
    "is.gd": "is.gd",
    "v.gd": "v.gd",
    "buff.ly": "Buffer",
    "rb.gy": "Rebrandly",
    "cutt.ly": "Cuttly",
    "shorturl.at": "ShortURL",
    "tiny.cc": "TinyCC",
    "lnkd.in": "LinkedIn",
    "youtu.be": "YouTube",
    "amzn.to": "Amazon",
    "fb.me": "Facebook",
    "aka.ms": "Microsoft",
    "short.io": "Short.io",
    "surl.li": "SURL",
    "urlzs.com": "URLzs",
    "clck.ru": "Yandex",
    "qr.ae": "Quora",
    "s.id": "s.id",
    "rotf.lol": "ROTF",
    "cli.re": "Cliclk",
    "bc.vc": "bc.vc",
    "smarturl.it": "SmartURL",
    "dl.acm.org": "ACM",
}


def detect_shortener(url):

    result = {
        "is_shortener": False,
        "service": None,
        "domain": None
    }

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname

        if not hostname:
            return result

        hostname = hostname.lower().rstrip(".")

        # Direct match
        if hostname in SHORTENER_DOMAINS:
            result["is_shortener"] = True
            result["service"] = SHORTENER_DOMAINS[hostname]
            result["domain"] = hostname
            return result

        # Match without leading "www."
        if hostname.startswith("www."):
            bare = hostname[4:]

            if bare in SHORTENER_DOMAINS:
                result["is_shortener"] = True
                result["service"] = SHORTENER_DOMAINS[bare]
                result["domain"] = bare
                return result

        # Heuristic: very short path on a short domain
        # (most shorteners use short random paths)
        labels = hostname.split(".")
        domain_length = len(labels[-2]) if len(labels) >= 2 else 0
        path = parsed.path.strip("/")

        if domain_length <= 4 and 1 <= len(path) <= 10 and "/" not in path:
            result["service"] = "Unknown (short domain pattern)"

        return result

    except Exception:
        return result
