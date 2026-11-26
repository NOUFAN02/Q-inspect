import os
import qrcode

# Create a QR code containing a harmless test URL
data = "https://example.com"

qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_H,
    box_size=10,
    border=4
)

qr.add_data(data)
qr.make(fit=True)

# Generate and save the image
image = qr.make_image(fill_color="black", back_color="white")

image.save(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_qr.png"))

print("Test QR code generated successfully")