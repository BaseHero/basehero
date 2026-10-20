# Imagefile camera fixture

`camera-fixture.py` renders the showing host's `qr_svg` into a deterministic
camera input. It does not decode the QR, call JavaScript with a scan result,
or replace native pairing. Only synthetic local sessions belong in this test.

Build the feature APK and start the local synthetic stack **before** obtaining
the showing code: a session lasts 300 seconds. Check that the APK's compiled
endpoint, policy and public roots match that stack, and run the no-model APK
gate. The showing device must remain live and report the candidate from that
same session; `SCAN_CANDIDATE` is the observation file written by that host's
test harness, not a file the scanner creates.

From the product workspace, with a fresh host SVG saved as `/tmp/host-qr.svg`:

```sh
python3 apps/client/tests/android/camera-fixture.py /tmp/host-qr.svg /tmp/camera.png
SCAN_IMAGE=/tmp/camera.png SCAN_CANDIDATE=/tmp/showing-host/candidate \
  SCAN_UNSIGNED_APK=/path/to/matching-model-free-feature.apk \
  nix develop .#androidEmulator --command \
  bash apps/client/tests/android/run-scan.sh scan
```

The existing runner creates its own disposable API 36 `pixel_fold` AVD,
sets a PIN, enrolls its test fingerprint, closes Settings, and runs the real
app permission/scan flow. Android key policy is unchanged. Do not aim it at
a physical phone or another test's emulator. This is emulator evidence, not
physical-device acceptance.

## Why the QR is left of source centre

Measured with emulator 37.1.11, a 1920×1080 `imagefile` source and the app's
unchanged CameraX 1.5.1 back-camera analysis configuration. The actual Y plane
was 1280×960, full crop, row stride 1280, pixel stride 1, rotation metadata 90°.
Three raw frames two seconds apart were byte-identical. Thirty-six labelled
crosses gave this source-to-raw-frame map (maximum fit residual 0.44 px):

- `frame_x = 1.185 × source_y + 0.267`
- `frame_y = −1.1853125 × source_x + 1243.475`

Source `(644,540)` therefore maps to frame centre `(640,480)`. The host's
61×61-module SVG, including its four-module quiet zone, is rendered at seven
source pixels per module: box `(431,327,427,427)`. It occupies approximately
frame `x=388..894, y=227..733`, at 8.3 pixels per module. The outer grey border
is another 40 source pixels away. Placing it at source image centre clips its
top in analysis pixels. The image is rotated and cropped, not globally fitted.

The corrected raw frame had a complete white quiet zone, decoded to the exact
host code with the production `QrFrameDecoder` offline, and the real app scan
reached the live showing host's candidate. Recheck actual analysis pixels if
the emulator or camera configuration changes; a preview screenshot alone does
not establish this mapping.

Fast generator checks (also included by `check.sh android`):

```sh
node --test apps/client/tests/android/camera-fixture.test.mjs
```
