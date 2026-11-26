"""
QR Decoder — robust multi-strategy decoding.

OpenCV's QRCodeDetector is fast but fragile: it often fails on styled codes,
low contrast, small images, screenshots, or PNGs with transparency. This module
tries a series of image preprocessing variants and both OpenCV decode paths,
and falls back to ZBar (pyzbar) when that native library is available. It
returns success=False with a clear message when nothing decodes, so callers
never mistake an undecodable image for a safe one.
"""

import cv2
import numpy as np


def _load_image(image_path):
    """Load an image as BGR, flattening any alpha channel onto a white
    background (a transparent QR would otherwise become black-on-black)."""
    img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        # Fallback via Pillow for formats/edge cases OpenCV can't read.
        try:
            from PIL import Image
            pil = Image.open(image_path).convert("RGBA")
            img = cv2.cvtColor(np.array(pil), cv2.COLOR_RGBA2BGRA)
        except Exception:
            return None

    if img.ndim == 2:  # grayscale
        return cv2.cvtColor(img, cv2.COLOR_GRAY2BGR)
    if img.shape[2] == 4:  # has alpha -> composite over white
        bgr = img[:, :, :3].astype(float)
        alpha = img[:, :, 3].astype(float) / 255.0
        white = np.ones_like(bgr) * 255
        out = bgr * alpha[..., None] + white * (1 - alpha[..., None])
        return out.astype(np.uint8)
    return img


def _candidates(image):
    """Yield progressively processed variants to maximise decode chances."""
    yield image

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    yield cv2.cvtColor(gray, cv2.COLOR_GRAY2BGR)

    # Upscale small / dense codes.
    for scale in (2, 3):
        yield cv2.resize(image, None, fx=scale, fy=scale,
                         interpolation=cv2.INTER_CUBIC)

    # Otsu binarisation (handles poor contrast / coloured codes).
    _, otsu = cv2.threshold(gray, 0, 255,
                            cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    yield cv2.cvtColor(otsu, cv2.COLOR_GRAY2BGR)
    yield cv2.cvtColor(
        cv2.resize(otsu, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC),
        cv2.COLOR_GRAY2BGR)

    # Adaptive threshold (handles uneven lighting / screenshots).
    adap = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                 cv2.THRESH_BINARY, 31, 2)
    yield cv2.cvtColor(adap, cv2.COLOR_GRAY2BGR)


def _opencv_decode(detector, img):
    try:
        payload, _, _ = detector.detectAndDecode(img)
        if payload:
            return payload
    except cv2.error:
        pass
    try:
        ok, decoded, _, _ = detector.detectAndDecodeMulti(img)
        if ok and decoded:
            for d in decoded:
                if d:
                    return d
    except cv2.error:
        pass
    return None


def _zbar_decode(image):
    """Optional ZBar fallback; silently skipped if the library is unavailable."""
    try:
        from pyzbar.pyzbar import decode as zbar
    except Exception:
        return None
    try:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        for img in (image, gray):
            results = zbar(img)
            for r in results:
                if r.data:
                    return r.data.decode("utf-8", errors="replace")
    except Exception:
        return None
    return None


def decode_qr(image_path):
    image = _load_image(image_path)
    if image is None:
        return {
            "success": False,
            "payload": None,
            "message": "Unable to read the image file (unsupported or corrupt)."
        }

    detector = cv2.QRCodeDetector()

    for candidate in _candidates(image):
        payload = _opencv_decode(detector, candidate)
        if payload:
            return {
                "success": True,
                "payload": payload,
                "message": "QR code successfully decoded"
            }

    # Last resort: ZBar (more tolerant of styled codes), if installed.
    payload = _zbar_decode(image)
    if payload:
        return {
            "success": True,
            "payload": payload,
            "message": "QR code successfully decoded (ZBar)"
        }

    return {
        "success": False,
        "payload": None,
        "message": ("No QR code could be decoded. Try a clearer, higher-contrast "
                    "image with the full code and some white margin around it.")
    }
