from backend.modules.url_analyzer import analyze_url


test_urls = [
    "https://example.com",
    "http://example.com/login",
    "https://192.168.1.10/login",
    "https://trusted.example@attacker.example/login",
    "https://login.verify.account.example.com",
    "https://example.com:8080/login",
    "https://xn--pple-43d.com"
]


for url in test_urls:

    result = analyze_url(url)

    print("\nURL:", url)
    print("Valid:", result["valid_url"])
    print("Hostname:", result["hostname"])
    print("IP address:", result["contains_ip_address"])
    print("Credentials:", result["contains_credentials"])
    print("Nonstandard port:", result["uses_nonstandard_port"])
    print("Punycode:", result["contains_punycode"])
    print("Keywords:", result["suspicious_keywords"])
    print("Indicators:", result["indicators"])

    print("-" * 60)