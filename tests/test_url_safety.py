from backend.modules.url_safety import validate_url


test_urls = [

    "https://example.com",

    "http://127.0.0.1",

    "http://192.168.1.1",

    "http://10.0.0.5",

    "http://169.254.169.254",

    "ftp://example.com",

    "https://user:password@example.com",

    "https://example.com:8080",

    "http://0.0.0.0",

    "http://[::1]"
]


for url in test_urls:

    result = validate_url(url)

    print("\nURL:", url)
    print("Safe:", result["safe"])
    print("Hostname:", result["hostname"])
    print("Resolved IPs:", result["resolved_ips"])
    print("Reason:", result["reason"])
    print("-" * 60)