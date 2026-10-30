#!/bin/sh
# Copies the passport_claim circuit artifacts (xark build + xark setup --cache)
# into the app bundle's Circuit/ folder, where the prover loads them.
# Produce them with `just claim-artifacts`.
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$HERE/../../crates/circuits/claim/target/xark/passport_claim"
DEST="${TARGET_BUILD_DIR:?}/${UNLOCALIZED_RESOURCES_FOLDER_PATH:?}/Circuit"
for f in circuit.xbc r1cs.min.wcz pk.bin vk.bin; do
    if [ ! -f "$SRC/$f" ]; then
        echo "error: $SRC/$f is missing. Run \`just claim-artifacts\` first." >&2
        exit 1
    fi
done
mkdir -p "$DEST"
for f in circuit.xbc r1cs.min.wcz pk.bin vk.bin; do
    cp "$SRC/$f" "$DEST/$f"
done
