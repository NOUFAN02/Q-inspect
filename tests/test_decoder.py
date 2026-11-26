import os
from backend.modules.qr_decoder import decode_qr

result = decode_qr(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_qr.png"))

print(result)