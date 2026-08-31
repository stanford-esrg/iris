#!/usr/bin/env bash
#
# Checks that the Iris compiler produces byte-identical output for identical
# input across builds.
#
# The filter trees are printed by the proc macro at build time and the generated
# code follows from them, so `cargo expand` captures both. Any difference between
# runs means something on the path from parsed inputs to generated code is
# iterating a hash collection (see `core_ptree_deterministic` in
# core/src/filter/ptree.rs and `test_decoder_deterministic` in
# compiler/src/subscription.rs).
#
# Usage: tests/check_codegen_determinism.sh [package] [runs] [cargo expand args...]
#
#   tests/check_codegen_determinism.sh measuring_sec 3
#   tests/check_codegen_determinism.sh ml_qos 3 --bin serve_ml
#
# A package with more than one target needs an explicit `--bin <name>`.
#
# Requires the DPDK environment (DPDK_PATH, DPDK_VERSION, PKG_CONFIG_PATH,
# LD_LIBRARY_PATH), IRIS_HOME, and `cargo install cargo-expand`.

set -euo pipefail

PKG="${1:-measuring_sec}"
RUNS="${2:-3}"
EXPAND_ARGS=("${@:3}")

if ! cargo expand --version >/dev/null 2>&1; then
    echo "cargo-expand not found; install with 'cargo install cargo-expand'" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# The macro only re-runs (and only re-prints the trees) if the crate is dirty.
SRC="$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
    | python3 -c "
import json,sys
md = json.load(sys.stdin)
for p in md['packages']:
    if p['name'] == '$PKG':
        for t in p['targets']:
            print(t['src_path'])
        break
")"
if [ -z "$SRC" ]; then
    echo "Could not locate sources for package '$PKG'" >&2
    exit 2
fi

OUT_DIR="$(mktemp -d)"
trap 'rm -rf "$OUT_DIR"' EXIT

# Warm-up run, discarded: makes sure every dependency is already built, so that
# the compared runs only differ in what this package's macro emits.
cargo expand -p "$PKG" "${EXPAND_ARGS[@]}" >/dev/null 2>&1 || true

for i in $(seq 1 "$RUNS"); do
    # shellcheck disable=SC2086
    touch $SRC
    if ! cargo expand -p "$PKG" "${EXPAND_ARGS[@]}" \
            > "$OUT_DIR/raw_$i.txt" 2> "$OUT_DIR/err_$i.txt"; then
        echo "cargo expand failed for '$PKG':" >&2
        tail -20 "$OUT_DIR/err_$i.txt" >&2
        echo "If the package has several targets, pass e.g. --bin <name>." >&2
        exit 2
    fi
    # Everything from the first printed tree onward: the filter trees plus the
    # generated code. Earlier lines are the parse-time log of whichever crates
    # happened to be rebuilt, which depends on the build cache, not on codegen.
    sed -n '/^Tree Per-Packet:/,$p' "$OUT_DIR/raw_$i.txt" > "$OUT_DIR/run_$i.txt"
    if [ ! -s "$OUT_DIR/run_$i.txt" ]; then
        echo "No filter trees in the expansion of '$PKG'" >&2
        exit 2
    fi
done

status=0
for i in $(seq 2 "$RUNS"); do
    if ! diff -u "$OUT_DIR/run_1.txt" "$OUT_DIR/run_$i.txt" > "$OUT_DIR/diff_$i.txt"; then
        echo "FAIL: run 1 and run $i differ for '$PKG':"
        head -60 "$OUT_DIR/diff_$i.txt"
        status=1
    fi
done

if [ "$status" -eq 0 ]; then
    echo "OK: $RUNS runs of '$PKG' produced identical output"
fi
exit "$status"
