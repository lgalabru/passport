#!/bin/bash
# Records the demo on the iPhone Duo simulator: adding a passport on the cover
# display, unfolding, folding, an age-restricted film rental on a streaming
# service arriving, unfolding to approve it, folding again.
#
# The app plays the taps itself (`-demo`, debug builds); folding and unfolding
# are yours, in DeviceHub. Start with the Duo folded.
#
#   clients/ios/scripts/record-demo.sh        # or: just demo-video
#
# Output: clients/ios/build/demo/passport-duo.mp4, a recording of the DeviceHub window,
# device frame and folds included. Keep that window on this desktop, in front,
# and don't move it while recording.
# Recording a window needs Screen Recording permission for this terminal.
#
#   RECORD=displays  the simulator's own screens instead (sharper, but no fold)
#   RECORD=0         drive the demo only
#   AUTO=1           no Enter presses: the script waits for your folds instead
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$ROOT/clients/ios/build/demo"
APP="$ROOT/clients/ios/build/DerivedData/Build/Products/Debug-iphonesimulator/Passport.app"

UDID=$(xcrun simctl list devices booted -j | python3 -c '
import json, sys
for devices in json.load(sys.stdin)["devices"].values():
    for d in devices:
        if d["name"] == "iPhone Duo":
            print(d["udid"]); raise SystemExit
raise SystemExit("Boot the iPhone Duo simulator first (open it in DeviceHub).")
')

rm -rf "$OUT" && mkdir -p "$OUT"
echo "Building…"
xcodebuild -quiet -project "$ROOT/clients/ios/Passport.xcodeproj" -scheme Passport -configuration Debug \
    -derivedDataPath "$ROOT/clients/ios/build/DerivedData" -destination "id=$UDID" build
cargo build -q --release --manifest-path "$ROOT/Cargo.toml" -p passport-attest --example relying_party

# A simulated enrolled finger, so Share asks for Touch ID (matched below).
xcrun simctl spawn "$UDID" notifyutil -s com.apple.BiometricKit.enrollmentChanged 1
xcrun simctl spawn "$UDID" notifyutil -p com.apple.BiometricKit.enrollmentChanged

# A fresh install: no passport, no history.
xcrun simctl terminate "$UDID" sh.scarce.passport 2>/dev/null || true
xcrun simctl uninstall "$UDID" sh.scarce.passport
xcrun simctl install "$UDID" "$APP"

# The shop: a streaming service renting a film rated 18. RP_NAME, RP_PURPOSE
# and CLAIMS change the scenario.
RP_TITLE="${RP_TITLE:-Lumen+ wants to verify your age}"
RP_BODY="${RP_BODY:-Confirm you’re 18 or older to rent “Night Signal”. Tap to review.}"
RP_NAME="${RP_NAME:-Lumen+}" \
RP_PURPOSE="${RP_PURPOSE:-Rent “Night Signal” (rated 18) · \$3.99 · 48 h in 4K.}" \
    "$ROOT/target/release/examples/relying_party" ${CLAIMS:-'age.gte(18)'} >"$OUT/rp.out" 2>"$OUT/rp.err" &
RP=$!
trap 'kill $RP 2>/dev/null || true; touch "$OUT/stop"' EXIT
for _ in $(seq 50); do [ -s "$OUT/rp.out" ] && break; sleep 0.1; done
LINK=$(head -1 "$OUT/rp.out")

# The take starts folded: wait for the cover display.
python3 "$ROOT/clients/ios/scripts/follow-displays.py" wait "$UDID" cover "$OUT" &&
    echo "folded, starting"

RECORD="${RECORD:-window}"
case "$RECORD" in
window)
    osascript -e 'tell application "DeviceHub" to activate' >/dev/null
    sleep 1
    # The window's rectangle, read now: `screencapture -l` records a stale one.
    # Don't move the window while recording.
    RECT=$(swift "$ROOT/clients/ios/scripts/devicehub-window.swift")
    screencapture -v -x -R"$RECT" "$OUT/window.mov" &
    FOLLOW=$!
    ;;
displays)
    python3 "$ROOT/clients/ios/scripts/follow-displays.py" "$UDID" "$OUT" &
    FOLLOW=$!
    ;;
esac
sleep 2
xcrun simctl launch "$UDID" sh.scarce.passport -demo >/dev/null

cat <<'EOF'

Recording. In DeviceHub (keep its window in front, don't move it):
  1. The passport is added on the cover display (about 15 s).
  2. Tap Allow when Passport asks to send notifications; it returns to the Home screen.
EOF
wait_display() { python3 "$ROOT/clients/ios/scripts/follow-displays.py" wait "$UDID" "$1" "$OUT"; }
DATA=$(xcrun simctl get_app_container "$UDID" sh.scarce.passport data)
until [ -e "$DATA/Documents/demo-home" ]; do sleep 0.5; done
sleep 3
# The request arrives as a notification, carrying the OpenID4VP link.
python3 - "$LINK" "$RP_TITLE" "$RP_BODY" >"$OUT/push.json" <<'PY'
import json, sys
link, title, body = sys.argv[1:4]
print(json.dumps({"aps": {"alert": {"title": title, "body": body}, "sound": "default"}, "request": link}))
PY
xcrun simctl push "$UDID" sh.scarce.passport "$OUT/push.json" >/dev/null
# Touch the sensor whenever Share asks, until the shop has its proof.
(
    while ! grep -q '^VERIFIED' "$OUT/rp.out" && [ ! -e "$OUT/stop" ]; do
        sleep 1.5
        xcrun simctl spawn "$UDID" notifyutil -p com.apple.BiometricKit_Sim.fingerTouch.match
    done
) &
cat <<'EOF'
  3. The Lumen+ notification is on the cover. Unfold, then tap it (or swipe down
     from the top for Notification Center). Don't tap Share: it is approved on
     the right page.
  4. Fold again when it says Shared.
Press Enter here to stop recording.
EOF
if [ "${AUTO:-0}" = 1 ]; then
    # Unfold (the app approves on the right page), then fold to finish.
    wait_display inner && echo "unfolded"
    until grep -q '^VERIFIED' "$OUT/rp.out"; do sleep 1; done
    echo "approved"
    wait_display cover && echo "folded"
    sleep 7
else
    read -r _
fi

touch "$OUT/stop"
case "$RECORD" in
window) kill -INT $FOLLOW; wait $FOLLOW || true ;;
displays) wait $FOLLOW ;;
esac
if grep -q '^VERIFIED' "$OUT/rp.out"; then
    echo "Shop verified: $(grep '^VERIFIED' "$OUT/rp.out" | cut -c10-)"
else
    echo "warning: the shop did not receive a proof" >&2
fi

if [ "$RECORD" = window ]; then
    ffmpeg -v error -y -i "$OUT/window.mov" -vf "fps=30,scale=trunc(iw/2)*2:trunc(ih/2)*2" \
        -c:v libx264 -pix_fmt yuv420p -crf 18 -movflags +faststart "$OUT/passport-duo.mp4"
    echo "Video: $OUT/passport-duo.mp4"
    exit 0
fi
[ "$RECORD" = displays ] || exit 0

# Each segment centred on a 1920×1080 black canvas, then joined.
inputs=() filters="" n=0
for segment in "$OUT"/segment-*.mov; do
    inputs+=(-i "$segment")
    filters+="[$n:v]fps=30,scale=1920:1040:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:black,setsar=1[v$n];"
    n=$((n + 1))
done
concat=""
for i in $(seq 0 $((n - 1))); do concat+="[v$i]"; done
ffmpeg -v error -y "${inputs[@]}" -filter_complex "${filters}${concat}concat=n=$n:v=1:a=0[out]" \
    -map "[out]" -c:v libx264 -pix_fmt yuv420p -crf 20 -movflags +faststart "$OUT/passport-duo.mp4"
echo "Video: $OUT/passport-duo.mp4"
