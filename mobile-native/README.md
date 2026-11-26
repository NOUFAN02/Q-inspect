# Q Inspect — Native Android App (Kotlin)

A native Android client. Scans a QR code with ZXing, sends the decoded content
to the Q Inspect backend (`/api/scan-payload`), and shows the verdict.
The phone never connects to the scanned target — only the backend does.

## Step 1 — New project in Android Studio
`File > New > New Project` → **Empty Views Activity** → Next. Set:
- **Name:** `Q Inspect`
- **Package name:** `com.quishinginspector.app`  (must match — the code uses it)
- **Language:** Kotlin
- **Minimum SDK:** API 24
- **Build configuration language:** Kotlin DSL (default)
Click **Finish** and let it sync.

## Step 2 — Add the three dependencies
Open `Gradle Scripts > build.gradle.kts (Module :app)`. Inside `dependencies { }`
add the three lines from `build-gradle-dependencies.txt`. Confirm
`defaultConfig { minSdk = 24 }`. Click **Sync Now**.

## Step 3 — Permissions
Open `app/src/main/AndroidManifest.xml`. Add the two `<uses-permission>` lines
from `AndroidManifest-additions.xml` just inside `<manifest>`, above
`<application>`.

## Step 4 — The screen layout
Open `app/src/main/res/layout/activity_main.xml`, switch to the **Code** tab,
delete everything, and paste the full contents of `activity_main.xml` from here.

## Step 5 — The activity code
Open `app/src/main/java/com/quishinginspector/app/MainActivity.kt`, delete its
contents, and paste the full contents of `MainActivity.kt` from here.
(If you chose a different package name in Step 1, change the first `package`
line to match.)

## Step 6 — Run it
- Plug in your Android phone with **USB debugging** on (or start an emulator).
- Press the green **Run ▶**. The app installs and launches.

## Step 7 — Use it
1. Start the backend and a Cloudflare tunnel on your PC:
   ```powershell
   # Terminal 1
   python run_server.py   # from the repository root
   # Terminal 2
   & "C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --url http://127.0.0.1:8000
   ```
2. In the app, paste the `https://xxxx.trycloudflare.com` URL and tap **Save URL**.
3. Tap **SCAN QR CODE**, allow the camera, and scan.
   - Your zphisher QR → **DANGEROUS**; a normal link → **SAFE**.

## Building a shareable APK
`Build > Build App Bundle(s) / APK(s) > Build APK(s)`. When it finishes, click
**locate** — that `app-debug.apk` is the file you can send and sideload.
(The recipient still needs your backend URL reachable to use it.)
