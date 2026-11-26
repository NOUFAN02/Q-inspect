# Q Inspect — Mobile App (Phase 4)

A thin-client Android/iOS app (Expo / React Native). It scans a QR code with
the live camera, decodes it **on-device**, sends the decoded content to the
Q Inspect backend for analysis, and shows a **pre-visit warning**
before any link is ever opened. The phone never connects to the scanned target —
only the (Tor-anonymised) backend does.

## Architecture

```
Camera scan → decode on device → POST /api/scan-payload → backend analyses
→ verdict JSON → warning modal (SAFE / CAUTION / DANGEROUS). Link opens only
if the user explicitly overrides.
```

## Prerequisites

- Node.js (installed)
- The **Expo Go** app on your phone (Play Store / App Store)
- The backend reachable from your phone — easiest via a Cloudflare tunnel:
  ```powershell
  # Terminal 1: backend
  python run_server.py   # from the repository root
  # Terminal 2: public URL for the backend
  & "C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --url http://127.0.0.1:8000
  ```
  Copy the `https://xxxx.trycloudflare.com` URL it prints.

## Install & run

```powershell
cd mobile   # from the repository root
npm install
npx expo install expo-camera @react-native-async-storage/async-storage
npx expo start
```

A QR code appears in the terminal. Open **Expo Go** on your phone and scan it
(phone and PC on the same network). The app loads on your phone.

## First launch

1. The app asks for the **backend URL** — paste the Cloudflare tunnel URL.
   (It is saved on the device; change it any time via the ⚙️ icon.)
2. Grant **camera** permission.
3. Point the camera at a QR code → the verdict appears.

## Notes

- The Cloudflare quick-tunnel URL changes each time you restart it; just paste
  the new one via the ⚙️ settings icon (no rebuild needed).
- `/api/scan-payload` handles every payload type (URL, UPI/crypto payment,
  Wi-Fi, SMS, tel, vCard…), so the app shows a verdict for non-URL QR codes too.
- "Open anyway" exists for URLs but requires an explicit confirmation, so a
  flagged link is never opened by accident.
