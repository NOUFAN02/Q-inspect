from backend.api import serve_home, FRONTEND_DIR
import os

print("=" * 70)
print("PHASE 3 VERIFICATION: FRONTEND ASSET SERVING")
print("=" * 70)

print(f"Frontend Directory: {FRONTEND_DIR}")
assert os.path.exists(FRONTEND_DIR), "Frontend directory does not exist!"

index_file = os.path.join(FRONTEND_DIR, "index.html")
style_file = os.path.join(FRONTEND_DIR, "style.css")
app_file = os.path.join(FRONTEND_DIR, "app.js")

assert os.path.exists(index_file), "index.html is missing"
assert os.path.exists(style_file), "style.css is missing"
assert os.path.exists(app_file), "app.js is missing"

print("✅ Found index.html")
print("✅ Found style.css")
print("✅ Found app.js")

resp = serve_home()
print(f"Home route response type: {type(resp).__name__}")
print(f"Serving path: {getattr(resp, 'path', None)}")
assert os.path.normpath(resp.path) == os.path.normpath(index_file)

print("\n" + "=" * 70)
print("PHASE 3 VERIFICATION COMPLETE: ALL ASSETS READY & MOUNTED!")
print("=" * 70)
