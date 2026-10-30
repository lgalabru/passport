#!/bin/sh
# Builds crates/ffi as a static library for the platform Xcode is building
# (device or simulator) into ios/RustCore/lib/<platform>/libpassport_ffi.a.
#
# Run by the "Build Rust core" phase of the Passport target; can also be run by
# hand: `scripts/build-rust.sh iphoneos release`.
set -eu

PLATFORM="${1:-${PLATFORM_NAME:-iphonesimulator}}"
CONFIG="${2:-${CONFIGURATION:-Debug}}"

# Xcode runs scripts with a minimal PATH.
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-26.0}"

HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

case "$PLATFORM" in
    iphoneos) TARGET=aarch64-apple-ios ;;
    iphonesimulator) TARGET=aarch64-apple-ios-sim ;;
    *) echo "error: unsupported platform $PLATFORM" >&2; exit 1 ;;
esac

# The reader is crypto-heavy and small: always build it optimised.
PROFILE=release

if ! rustup target list --installed | grep -qx "$TARGET"; then
    rustup target add "$TARGET"
fi

# Xcode exports SDKROOT and friends for the app's platform; cargo's build
# scripts compile for the host and must not inherit them.
env -u SDKROOT -u LIBRARY_PATH -u CPATH \
    cargo build --manifest-path "$ROOT/Cargo.toml" -p passport-ffi \
    --target "$TARGET" --profile "$PROFILE"

OUT="$HERE/RustCore/lib/$PLATFORM"
mkdir -p "$OUT"
cp "$ROOT/target/$TARGET/$PROFILE/libpassport_ffi.a" "$OUT/libpassport_ffi.a"

# Cargo's dependency file lists every Rust source the library was built from.
# Point it at the copy and hand it to Xcode (the phase's "dependencyFile"), so
# Xcode skips this phase when no Rust changed. The manifests are added because
# a dependency bump changes the library without touching a source file.
{
    printf '%s:' "$OUT/libpassport_ffi.a"
    sed 's/^[^:]*://' "$ROOT/target/$TARGET/$PROFILE/libpassport_ffi.d" | tr -d '\n'
    printf ' %s %s %s\n' "$ROOT/Cargo.toml" "$ROOT/Cargo.lock" "$HERE/scripts/build-rust.sh"
} > "$OUT/libpassport_ffi.d"
echo "Rust core ($CONFIG, $TARGET) -> $OUT/libpassport_ffi.a"
