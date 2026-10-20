# Android QR scanning

The join screen's camera scanner on Android. It is the app's own small Tauri
plugin, registered inline by the client (`src-tauri/src/qr_scan.rs`); Tauri
forwards `plugin:qr-scan|request_permissions`, `scan` and `cancel` to
`QrScanPlugin` after the capability check, which grants them to the Android
main window only.

- Back camera, QR only. CameraX shows the preview behind the transparent
  WebView and delivers frames to one background analysis thread that keeps
  only the latest frame.
- `QrFrameDecoder` reads each frame's luminance plane with ZXing's algorithmic
  QR reader. There is no model, no model download, no Play Services and no
  network use; `scripts/android_no_models.py` checks built APKs for that.
- The decoded text goes back to the page as untrusted text. Joining still goes
  only through `pairing_join` and its canonical parser.
- A scan reserves its native slot before queueing the camera start. Cancel,
  pause and destroy invalidate that request; resuming never starts it again.
  Completion stops analysis and releases its worker after unbinding, draining
  already submitted frames through their close paths. A scan settles once:
  a code, cancel, pause or a prompt refusal when the camera or permission is missing.

Dependencies: CameraX 1.5.1 and ZXing core 3.5.4 (Apache-2.0); their
attribution is in the source package's `LICENSES/qr-scanner.txt`.
The ZXing 3.5.4 repository NOTICE names Barcode4J and JCommander, neither of
which is part of the core artifact; core's source jar contains no NOTICE.
From
`basehero/`, the JVM decoder and lifecycle tests and the release library build:

```sh
nix develop .#android --command bash scripts/check.sh android-qr-scan
```
