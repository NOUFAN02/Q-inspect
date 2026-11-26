import os
import tempfile
from typing import Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from backend.modules.pipeline import process_qr, inspect_url, analyze_payload_text


app = FastAPI(
    title="Q Inspect API",
    description="Multi-layered pre-visit inspection engine for detecting malicious QR codes (quishing)",
    version="1.0.0"
)

# Enable CORS for Web frontend and Android/mobile applications
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Base directory for static assets
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


class UrlScanRequest(BaseModel):
    url: str
    perform_network_checks: Optional[bool] = True


class PayloadScanRequest(BaseModel):
    payload: str
    perform_network_checks: Optional[bool] = True


@app.get("/")
def serve_home():
    """Serves the VirusTotal-style Web UI"""
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {
        "service": "Q Inspect Security API",
        "status": "online",
        "docs_url": "/docs"
    }


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "version": "1.0.0"
    }


@app.post("/api/scan-file")
def scan_qr_file(
    file: UploadFile = File(...),
    perform_network_checks: bool = Query(True)
):
    """
    Accepts an uploaded QR code image (PNG, JPG, JPEG, WEBP),
    runs the full inspection pipeline, and returns the threat report.
    """
    try:
        content = file.file.read()
    except Exception:
        content = None

    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # Save to a secure temporary file
    temp_dir = tempfile.gettempdir()
    file_ext = os.path.splitext(file.filename or "")[1] or ".png"
    temp_path = os.path.join(temp_dir, f"quishing_scan_{os.urandom(8).hex()}{file_ext}")

    try:
        with open(temp_path, "wb") as f:
            f.write(content)

        # Run complete pipeline
        result = process_qr(
            image_path=temp_path,
            perform_network_checks=perform_network_checks
        )

        return {
            "success": result["success"],
            "message": result["message"],
            "payload": result["payload"],
            "classification": result["classification"],
            "details": result["details"]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    finally:
        # Guarantee cleanup of temporary image file
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


@app.post("/api/scan-url")
def scan_direct_url(payload: UrlScanRequest):
    """
    Inspects a raw URL directly through the security pipeline
    without needing a QR code image.
    """
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    # Normalize missing scheme
    if url.lower().startswith("www."):
        url = "https://" + url
    elif not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    try:
        report = inspect_url(
            target_url=url,
            perform_network_checks=payload.perform_network_checks
        )
        return {
            "success": True,
            "target_url": url,
            "report": report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/api/scan-payload")
def scan_payload(request: PayloadScanRequest):
    """
    Analyses an already-decoded QR payload (any type: URL, UPI/crypto payment,
    Wi-Fi, SMS, tel, vCard, ...). Used by the mobile app, which decodes the QR
    on-device and sends the raw text, so no image upload is needed.
    """
    raw = (request.payload or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Payload cannot be empty")

    try:
        result = analyze_payload_text(
            raw,
            perform_network_checks=request.perform_network_checks,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
