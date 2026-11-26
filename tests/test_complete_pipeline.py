import qrcode
import os
import tempfile
from backend.modules.pipeline import process_qr


def create_sample_qr(data):
    fd, path = tempfile.mkstemp(suffix=".png")
    os.close(fd)
    qr = qrcode.QRCode(version=1, box_size=8, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(path)
    return path


test_cases = [
    ("Safe Site", "https://example.com"),
    ("SSRF Cloud Metadata Attack", "http://169.254.169.254/latest/meta-data"),
    ("Shortener Link", "https://bit.ly/test-link"),
    ("Phishing URL (Creds + Private IP + Port + Keywords)", "http://user:pass@192.168.1.50:8080/secure/bank/login"),
    ("Punycode Homograph", "https://xn--pple-43d.com/verify-account"),
    ("Open WiFi", "WIFI:S:PublicCafe;T:nopass;;")
]

print("=" * 70)
print("PHASE 1 VERIFICATION: END-TO-END PIPELINE & RISK ENGINE")
print("=" * 70)

for label, payload in test_cases:
    tmp_path = create_sample_qr(payload)
    try:
        result = process_qr(tmp_path, perform_network_checks=False)
        print(f"\n[Test Case] {label}")
        print(f"Payload: {payload}")
        print(f"Classification: {result.get('classification')}")
        
        details = result.get("details", {})
        risk = details.get("risk_assessment") if details else None
        
        if risk:
            print(f"Risk Score: {risk.get('score')} / 100")
            print(f"Verdict: {risk.get('verdict').upper()}")
            print(f"Summary: {risk.get('summary')}")
            breakdown = risk.get("breakdown", [])
            if breakdown:
                print("Indicators flagged:")
                for item in breakdown:
                    print(f"  - [{item.get('severity').upper()}] {item.get('indicator')} (+{item.get('points')} pts)")
            else:
                print("No security indicators flagged.")
        else:
            print("No risk assessment returned.")
            
        print("-" * 50)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
