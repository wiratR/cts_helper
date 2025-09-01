#!/usr/bin/env bash
set -Eeuo pipefail

# strip_signature.sh - Remove <dsi:Signature> (XMLDSig) from a DeviceMessageBatch XML
# Usage:
#   ./strip_signature.sh [-i input.xml] [-o output.xml] [--c14n]
#   cat input.xml | ./strip_signature.sh > clean.xml

IN="" OUT="" DO_C14N=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -i|--in) IN="$2"; shift 2;;
    -o|--out) OUT="$2"; shift 2;;
    --c14n) DO_C14N=1; shift;;
    -h|--help)
      echo "Usage: $0 [-i input.xml] [-o output.xml] [--c14n]"; exit 0;;
    *) echo "[ERROR] unknown arg: $1" >&2; exit 2;;
  esac
done

# ---- temp vars (init to empty to avoid set -u issues) ----
TMP_IN=""; TMP_OUT=""; TMP_C14N=""
cleanup() {
  rm -f "${TMP_IN:-}" "${TMP_OUT:-}" "${TMP_C14N:-}"
}
trap cleanup EXIT

# ---- read input ----
TMP_IN="$(mktemp)"
if [[ -n "$IN" ]]; then
  cp -- "$IN" "$TMP_IN"
else
  cat > "$TMP_IN"
fi

# ---- process: remove <dsi:Signature> ----
TMP_OUT="$(mktemp)"
if command -v xmlstarlet >/dev/null 2>&1; then
  # precise, namespace-aware removal
  xmlstarlet ed \
    -N dsi='http://www.w3.org/2000/09/xmldsig#' \
    -d '//dsi:Signature' \
    "$TMP_IN" > "$TMP_OUT"
else
  # fallback: Python stdlib
  python - "$TMP_IN" "$TMP_OUT" <<'PY'
import sys, xml.etree.ElementTree as ET
IN, OUT = sys.argv[1:3]
NS = {'dsi': 'http://www.w3.org/2000/09/xmldsig#'}
tree = ET.parse(IN)
root = tree.getroot()
parent = {c: p for p in root.iter() for c in p}
for sig in list(root.findall('.//dsi:Signature', NS)):
    p = parent.get(sig)
    if p is not None:
        p.remove(sig)
tree.write(OUT, encoding='utf-8', xml_declaration=True)
PY
fi

# ---- optional C14N ----
if [[ "$DO_C14N" == "1" ]]; then
  if command -v xmllint >/dev/null 2>&1; then
    TMP_C14N="$(mktemp)"
    xmllint --noblanks --c14n "$TMP_OUT" > "$TMP_C14N"
    mv -- "$TMP_C14N" "$TMP_OUT"
  else
    echo "[WARN] --c14n specified but xmllint not found; skipping canonicalization" >&2
  fi
fi

# ---- write output ----
if [[ -n "$OUT" ]]; then
  mv -- "$TMP_OUT" "$OUT"
else
  cat "$TMP_OUT"
fi
