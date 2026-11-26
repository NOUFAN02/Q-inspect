from backend.modules.payload_classifier import classify_payload


test_payloads = [
    "https://example.com",
    "WIFI:T:WPA;S=Office;P=password;;",
    "BEGIN:VCARD\nFN:John\nEND:VCARD",
    "mailto:user@example.com",
    "tel:+911234567890",
    "Hello World",
    "www.example.com"
]


for payload in test_payloads:

    result = classify_payload(payload)

    print("Payload:", payload)
    print("Classification:", result["type"])
    print("-" * 50)