import httpx

from backend.modules.redirect_analyzer import analyze_redirects


test_urls = [
    "http://127.0.0.1:8000/offer",
    "http://127.0.0.1:8000/start",
    "http://127.0.0.1:8000/loop-a"
]


with httpx.Client(
    timeout=5.0,
    trust_env=False
) as client:

    for url in test_urls:

        result = analyze_redirects(
            url,
            client=client
        )

        print("\nREDIRECT TEST")
        print("-" * 50)

        print("Original URL:", result["original_url"])
        print("Final URL:", result["final_url"])
        print("Redirect count:", result["redirect_count"])
        print("Status:", result["status"])

        print("\nRedirect chain:")

        for item in result["redirect_chain"]:
            print(item)