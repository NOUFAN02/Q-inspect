import httpx

from backend.modules.redirect_analyzer import analyze_redirects


def mock_response(request):

    if request.url.path == "/offer":

        return httpx.Response(
            302,
            headers={
                "Location": "https://destination.example/login"
            },
            request=request
        )

    if request.url.path == "/login":

        return httpx.Response(
            200,
            request=request
        )

    return httpx.Response(
        404,
        request=request
    )


transport = httpx.MockTransport(mock_response)

with httpx.Client(transport=transport) as client:

    result = analyze_redirects(
        "https://example.com/offer",
        client=client
    )


print("\nREDIRECT ANALYSIS RESULT")
print("------------------------")

print("Success:", result["success"])
print("Original URL:", result["original_url"])
print("Final URL:", result["final_url"])
print("Redirect count:", result["redirect_count"])
print("Domain changed:", result["domain_changed"])

print("\nRedirect chain:")

for item in result["redirect_chain"]:
    print(item)