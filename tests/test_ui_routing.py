from backend.api import app
from starlette.testclient import TestClient

client = TestClient(app)

print("=" * 70)
print("PHASE 3 VERIFICATION: ROUTING & ASSET INTEGRITY")
print("=" * 70)

# 1. Test GET /
resp = client.get("/")
print("GET / Status:", resp.status_code)
assert resp.status_code == 200
assert "Q Inspect" in resp.text
print("✅ Index HTML delivered properly with Q Inspect UI elements")

# 2. Test GET /static/style.css
resp_css = client.get("/static/style.css")
print("GET /static/style.css Status:", resp_css.status_code)
assert resp_css.status_code == 200
assert "--color-safe" in resp_css.text
print("✅ CSS delivered with design tokens and styling")

# 3. Test GET /static/app.js
resp_js = client.get("/static/app.js")
print("GET /static/app.js Status:", resp_js.status_code)
assert resp_js.status_code == 200
assert "performScanFile" in resp_js.text
print("✅ Frontend JS script delivered with scanning logic")

print("\n" + "=" * 70)
print("ALL PHASE 3 UI ROUTES & STATIC ASSETS VALIDATED SUCCESSFULLY!")
print("=" * 70)
