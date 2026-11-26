import io
import qrcode
from fastapi import UploadFile
from backend.api import health_check, scan_direct_url, scan_qr_file, UrlScanRequest

print("=" * 70)
print("PHASE 2 VERIFICATION: FASTAPI REST API ENDPOINTS")
print("=" * 70)

# 1. Health check
res = health_check()
print(f"1. Health Check: {res}")
assert res["status"] == "healthy"

# 2. Direct URL scan
req = UrlScanRequest(
    url="http://user:pass@192.168.1.100:8080/account/login",
    perform_network_checks=False
)
res = scan_direct_url(req)
print(f"\n2. Direct URL Scan:")
print(f"   Target: {res['target_url']}")
risk = res["report"]["risk_assessment"]
print(f"   Risk Score: {risk['score']} / 100")
print(f"   Verdict: {risk['verdict'].upper()}")
assert res["success"] is True
assert risk["score"] > 50

# 3. QR File upload scan
qr = qrcode.QRCode(version=1, box_size=8, border=2)
qr.add_data("http://192.168.1.1/admin")
qr.make(fit=True)
img = qr.make_image(fill_color="black", back_color="white")

buf = io.BytesIO()
img.save(buf, format="PNG")
buf.seek(0)

upload = UploadFile(
    file=buf,
    filename="qr.png",
    headers={"content-type": "image/png"}
)

res = scan_qr_file(file=upload, perform_network_checks=False)
print(f"\n3. QR File Upload Scan:")
print(f"   Success: {res['success']}")
print(f"   Payload: {res['payload']}")
print(f"   Classification: {res['classification']}")
risk = res["details"]["risk_assessment"]
print(f"   Risk Score: {risk['score']} / 100")
print(f"   Verdict: {risk['verdict'].upper()}")
assert res["success"] is True
assert res["classification"] == "url"

print("\n" + "=" * 70)
print("ALL PHASE 2 API ENDPOINT TESTS PASSED SUCCESSFULLY!")
print("=" * 70)
