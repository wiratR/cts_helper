#!/usr/bin/env bash
set -Eeuo pipefail

# Inputs
IN_XML=""
CERT="${CERT_PATH:-./keys/authentication.crt}"                 # device cert (PEM)
CA_CERT="${CA_CERT:-${CA:-./certs/platform-certificate.crt}}"  # CA / trust anchor (optional)
OUT_DIR="${OUT_DIR:-./sigverify}"

usage() {
  echo "Usage: $0 -i <signed-batch.xml> [-c device.crt] [-a ca.pem] [-o outdir]" >&2
  exit 2
}

while getopts ":i:c:a:o:h" opt; do
  case "$opt" in
    i) IN_XML="$OPTARG" ;;
    c) CERT="$OPTARG" ;;
    a) CA_CERT="$OPTARG" ;;
    o) OUT_DIR="$OPTARG" ;;
    h|*) usage ;;
  esac
done
[[ -n "$IN_XML" ]] || usage

# Tools
require() { command -v "$1" >/dev/null 2>&1 || { echo "[ERROR] need tool: $1" >&2; exit 127; }; }
require openssl
have_xmllint=0; command -v xmllint >/dev/null 2>&1 && have_xmllint=1
have_xmlstar=0; command -v xmlstarlet >/dev/null 2>&1 && have_xmlstar=1
if (( !have_xmllint && !have_xmlstar )); then
  echo "[ERROR] need xmllint or xmlstarlet for C14N/XPath" >&2
  exit 127
fi

mkdir -p "$OUT_DIR"

# Helpers
c14n() { # c14n file -> stdout
  if (( have_xmllint )); then xmllint --c14n "$1"
  else xmlstarlet c14n "$1"
  fi
}
xpath_string() { # expr file -> stdout (single string)
  local expr="$1" file="$2"
  if (( have_xmllint )); then
    xmllint --xpath "string($expr)" "$file" 2>/dev/null || true
  else
    xmlstarlet sel -t -v "normalize-space($expr)" "$file" 2>/dev/null || true
  fi
}
xpath_copy() { # expr file out
  local expr="$1" file="$2" out="$3"
  if (( have_xmllint )); then
    xmllint --xpath "$expr" "$file" >"$out"
  else
    xmlstarlet sel -t -c "$expr" "$file" >"$out"
  fi
}

# Files
SIGNEDINFO_XML="$OUT_DIR/signedinfo.xml"
SIGNEDINFO_C14N="$OUT_DIR/signedinfo.c14n"
SIG_B64="$OUT_DIR/signature.b64"
SIG_BIN="$OUT_DIR/signature.bin"
PUB_PEM="$OUT_DIR/device.pub.pem"
DIG_ORIG="$OUT_DIR/digest.fromfile"
DIG_RECALC="$OUT_DIR/digest.recalc"
CLEAN_XML="$OUT_DIR/batch-without-signature.xml"
CLEAN_C14N="$OUT_DIR/batch.c14n"

echo "[INFO] Input: $IN_XML"
echo "[INFO] Cert : $CERT"
[[ -f "$CA_CERT" ]] && echo "[INFO] CA   : $CA_CERT" || echo "[INFO] CA   : (skip chain verify)"

# 1) Extract <SignedInfo> and C14N
xpath_copy "//*[local-name()='Signature']/*[local-name()='SignedInfo']" "$IN_XML" "$SIGNEDINFO_XML"
[[ -s "$SIGNEDINFO_XML" ]] || { echo "[ERROR] cannot extract SignedInfo" >&2; exit 3; }
c14n "$SIGNEDINFO_XML" > "$SIGNEDINFO_C14N"
echo "[OK] Extracted & canonicalized SignedInfo -> $SIGNEDINFO_C14N"

# 2) Extract SignatureValue (base64) and verify with RSA-SHA256
xpath_string "//*[local-name()='SignatureValue']" "$IN_XML" > "$SIG_B64"
tr -d '\r\n[:space:]' <"$SIG_B64" >"$SIG_B64.tmp" && mv "$SIG_B64.tmp" "$SIG_B64"
openssl base64 -d -A -in "$SIG_B64" -out "$SIG_BIN" >/dev/null 2>&1

openssl x509 -in "$CERT" -pubkey -noout > "$PUB_PEM"
if openssl dgst -sha256 -verify "$PUB_PEM" -signature "$SIG_BIN" "$SIGNEDINFO_C14N" >/dev/null; then
  echo "[OK] SignatureValue: VALID (openssl RSA-SHA256)"
else
  echo "[FAIL] SignatureValue: INVALID"
  exit 4
fi

# 3) Verify DigestValue: remove enveloped Signature, C14N, SHA256, Base64
if (( have_xmlstar )); then
  xmlstarlet ed -N dsi="http://www.w3.org/2000/09/xmldsig#" \
    -d "//dsi:Signature" "$IN_XML" > "$CLEAN_XML"
else
  # namespace-agnostic removal (python fallback)
  python3 - "$IN_XML" "$CLEAN_XML" <<'PY'
import sys, io
from xml.etree import ElementTree as ET
src, dst = sys.argv[1], sys.argv[2]
tree = ET.parse(src); root = tree.getroot()
for parent in list(root.iter()):
    for child in list(parent):
        if child.tag.split('}')[-1] == 'Signature':
            parent.remove(child)
tree.write(dst, encoding='utf-8', xml_declaration=True)
PY
fi

c14n "$CLEAN_XML" > "$CLEAN_C14N"
openssl dgst -sha256 -binary "$CLEAN_C14N" | openssl base64 -A > "$DIG_RECALC"
xpath_string "//*[local-name()='DigestValue']" "$IN_XML" > "$DIG_ORIG"
tr -d '\r\n[:space:]' <"$DIG_ORIG" >"$DIG_ORIG.tmp" && mv "$DIG_ORIG.tmp" "$DIG_ORIG"

if cmp -s "$DIG_ORIG" "$DIG_RECALC"; then
  echo "[OK] DigestValue: MATCH"
else
  echo "[FAIL] DigestValue: MISMATCH"
  echo "  file : $(cat "$DIG_ORIG")"
  echo "  calc : $(cat "$DIG_RECALC")"
  exit 5
fi

# 4) (Optional) verify cert chain
if [[ -f "$CA_CERT" ]]; then
  if openssl verify -CAfile "$CA_CERT" "$CERT" >/dev/null 2>&1; then
    echo "[OK] Certificate chain: VALID"
  else
    echo "[WARN] Certificate chain: FAILED (check CA/chain files)"
  fi
fi

echo "[DONE] XML Signature verification passed."
echo "[ARTIFACTS] $OUT_DIR"
