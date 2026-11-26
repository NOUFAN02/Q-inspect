import os
from backend.modules.pipeline import process_qr


result = process_qr(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_qr.png"))

print("\nQR PROCESSING RESULT")
print("--------------------")

print("Success:", result["success"])
print("Payload:", result["payload"])
print("Classification:", result["classification"])
print("Message:", result["message"])