#!/usr/bin/env bash
set -Eeuo pipefail

# ================== Config (override ได้ด้วย ENV) ==================
BATCH_XML="${BATCH_XML:-}"                           # ไฟล์ XML ของ transaction batch (input)
KEY_PATH="${KEY_PATH:-./keys/authentication.key}"    # private key (RSA 2048)
CERT_PATH="${CERT_PATH:-./keys/authentication.crt}"  # device certificate (PEM) — DEFAULT CHANGED

OUT_DIR="${OUT_DIR:-./sigout}"
SIGNEDINFO_XML="${SIGNEDINFO_XML:-$OUT_DIR/signedinfo.xml}"
SIGNEDINFO_C14N="${SIGNEDINFO_C14N:-$OUT_DIR/signedinfo.c14n}"
DIGEST_TXT="${DIGEST_TXT:-$OUT_DIR/digest.txt}"
SIGNATURE_TXT="${SIGNATURE_TXT:-$OUT_DIR/signature.b64}"
SIGNATURE_XML="${SIGNATURE_XML:-$OUT_DIR/signature.xml}"
SIGNED_BATCH_XML="${SIGNED_BATCH_XML:-$OUT_DIR/signed-batch.xml}"  # ผลลัพธ์ Step 5

# URIs ตามสเปค
C14N_ALG_URI="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
SIG_METHOD_URI="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
DIGEST_METHOD_URI="http://www.w3.org/2001/04/xmlenc#sha256"
TRANSFORM_ENV_URI="http://www.w3.org/2000/09/xmldsig#enveloped-signature"

# ================== Checks ==================
require() { command -v "$1" >/dev/null 2>&1 || { echo "[ERROR] missing tool: $1" >&2; exit 127; }; }
require_openssl() { require openssl; }

# เลือกเครื่องมือ C14N: xmllint > xmlstarlet
C14N_TOOL=""
if command -v xmllint >/dev/null 2>&1; then
  C14N_TOOL="xmllint"
elif command -v xmlstarlet >/dev/null 2>&1; then
  C14N_TOOL="xmlstarlet"
else
  echo "[ERROR] need xmllint or xmlstarlet for XML C14N 1.0" >&2
  exit 127
fi

# ================== Helpers ==================
b64_one_line() {
  if command -v openssl >/dev/null 2>&1; then
    openssl base64 -A
  elif command -v base64 >/dev/null 2>&1; then
    base64 | tr -d '\n'
  else
    echo "[ERROR] need openssl or base64 for Base64" >&2
    exit 127
  fi
}

c14n_file() { # $1 -> stdout
  if [[ "$C14N_TOOL" == "xmllint" ]]; then xmllint --c14n "$1"; else xmlstarlet c14n "$1"; fi
}

strip_pem_headers() { sed -e '/-----BEGIN .*-----/d' -e '/-----END .*-----/d' -e 's/[[:space:]]//g'; }

mktempf() { mktemp "${TMPDIR:-/tmp}/sig.XXXXXXXX"; }

usage() {
  cat <<USAGE
Usage: $0 -i <batch.xml> [-k <private.key>] [-c <device.crt>] [-o <outdir>]

  -i  Path to transaction batch XML (required)
  -k  Private key (RSA 2048)           [default: $KEY_PATH]
  -c  Device certificate (PEM)         [default: $CERT_PATH]
  -o  Output directory                 [default: $OUT_DIR]

Outputs (in OUT_DIR):
  - digest.txt           : Base64(SHA256(C14N(batch)))
  - signedinfo.xml       : <dsi:SignedInfo> (embed DIGEST)
  - signedinfo.c14n      : bytes used to sign (C14N of SignedInfo)
  - signature.b64        : Base64 PKCS#1 v1.5 RSA-SHA256 over C14N(SignedInfo)
  - signature.xml        : <dsi:Signature> (with X509Certificate stripped headers)
  - signed-batch.xml     : BATCH_XML + enveloped <dsi:Signature> (Step 5)

USAGE
  exit 2
}

# ================== Parse args ==================
while getopts ":i:k:c:o:h" opt; do
  case "$opt" in
    i) BATCH_XML="$OPTARG" ;;
    k) KEY_PATH="$OPTARG" ;;
    c) CERT_PATH="$OPTARG" ;;
    o) OUT_DIR="$OPTARG" ;;
    h|*) usage ;;
  esac
done

[[ -n "${BATCH_XML:-}" ]] || usage

# ================== Prep ==================
require_openssl
[[ -f "$BATCH_XML" ]] || { echo "[ERROR] not found: $BATCH_XML" >&2; exit 1; }
[[ -f "$KEY_PATH"  ]] || { echo "[ERROR] not found: $KEY_PATH"  >&2; exit 1; }
[[ -f "$CERT_PATH" ]] || { echo "[ERROR] not found: $CERT_PATH" >&2; exit 1; }

mkdir -p "$OUT_DIR"

# ================== Step 1: Compute digest of batch ==================
C14N_BATCH_FILE="$(mktempf)"
c14n_file "$BATCH_XML" > "$C14N_BATCH_FILE"
DIGEST="$(openssl dgst -sha256 -binary "$C14N_BATCH_FILE" | b64_one_line)"
printf '%s\n' "$DIGEST" > "$DIGEST_TXT"
echo "[INFO] Step 1: Digest -> $DIGEST_TXT"

# ================== Step 2: Build SignedInfo ==================
cat > "$SIGNEDINFO_XML" <<XML
<dsi:SignedInfo xmlns:dmb="http://www.thales.dc/DeviceMessageBatch"
                xmlns:dsi="http://www.w3.org/2000/09/xmldsig#"
                xmlns:dtf="http://www.thales.dc/DeviceTransactionFiles"
                xmlns:dtt="http://www.thales.dc/TicketingTypes"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dsi:CanonicalizationMethod Algorithm="$C14N_ALG_URI"></dsi:CanonicalizationMethod>
  <dsi:SignatureMethod Algorithm="$SIG_METHOD_URI"></dsi:SignatureMethod>
  <dsi:Reference URI="">
    <dsi:Transforms>
      <dsi:Transform Algorithm="$TRANSFORM_ENV_URI"></dsi:Transform>
    </dsi:Transforms>
    <dsi:DigestMethod Algorithm="$DIGEST_METHOD_URI"></dsi:DigestMethod>
    <dsi:DigestValue>$DIGEST</dsi:DigestValue>
  </dsi:Reference>
</dsi:SignedInfo>
XML
echo "[INFO] Step 2: SignedInfo -> $SIGNEDINFO_XML"

# ================== Step 3: Sign C14N(SignedInfo) with RSA-SHA256 ==================
c14n_file "$SIGNEDINFO_XML" > "$SIGNEDINFO_C14N"
SIGNATURE="$(openssl dgst -sha256 -sign "$KEY_PATH" "$SIGNEDINFO_C14N" | b64_one_line)"
printf '%s\n' "$SIGNATURE" > "$SIGNATURE_TXT"
echo "[INFO] Step 3: Signature (Base64) -> $SIGNATURE_TXT"

# ================== Step 4: Build <dsi:Signature> ==================
DEVICE_CERT="$(strip_pem_headers < "$CERT_PATH")"
cat > "$SIGNATURE_XML" <<XML
<dsi:Signature xmlns:dsi="http://www.w3.org/2000/09/xmldsig#">
  <dsi:SignedInfo xmlns:dmb="http://www.thales.dc/DeviceMessageBatch"
                  xmlns:dsi="http://www.w3.org/2000/09/xmldsig#"
                  xmlns:dtf="http://www.thales.dc/DeviceTransactionFiles"
                  xmlns:dtt="http://www.thales.dc/TicketingTypes"
                  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <dsi:CanonicalizationMethod Algorithm="$C14N_ALG_URI"/>
    <dsi:SignatureMethod Algorithm="$SIG_METHOD_URI"/>
    <dsi:Reference URI="">
      <dsi:Transforms>
        <dsi:Transform Algorithm="$TRANSFORM_ENV_URI"/>
      </dsi:Transforms>
      <dsi:DigestMethod Algorithm="$DIGEST_METHOD_URI"/>
      <dsi:DigestValue>$DIGEST</dsi:DigestValue>
    </dsi:Reference>
  </dsi:SignedInfo>
  <dsi:SignatureValue>$SIGNATURE</dsi:SignatureValue>
  <dsi:KeyInfo>
    <dsi:X509Data>
      <dsi:X509Certificate>$DEVICE_CERT</dsi:X509Certificate>
    </dsi:X509Data>
  </dsi:KeyInfo>
</dsi:Signature>
XML
echo "[INFO] Step 4: Signature XML -> $SIGNATURE_XML"

# ================== Step 5: Insert enveloped <dsi:Signature> into batch ==================
insert_signature_enveloped() {
  # แทรก <dsi:Signature> ก่อนปิดแท็กของ root: </*:DeviceMessageBatch> หรือ </DeviceMessageBatch>
  local in_xml="$1" sig_xml="$2" out_xml="$3"

  local pybin=""
  if command -v python3 >/dev/null 2>&1; then pybin="python3"
  elif command -v python  >/dev/null 2>&1; then pybin="python"
  else echo "[ERROR] need python or python3 to inject enveloped signature" >&2; return 127
  fi

  "$pybin" - "$in_xml" "$sig_xml" "$out_xml" <<'PY'
import io, re, sys
in_path, sig_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

data = io.open(in_path, 'r', encoding='utf-8').read()
sig  = io.open(sig_path, 'r', encoding='utf-8').read().strip()

# จับชื่อ root ที่แท้จริง (มีหรือไม่มี prefix)
m_open = re.search(r'<\s*(?P<prefix>[A-Za-z0-9_.-]+:)?DeviceMessageBatch\b', data)
if m_open and m_open.group('prefix'):
    prefix = re.escape(m_open.group('prefix'))
    close_re = re.compile(r'</\s*' + prefix + r'DeviceMessageBatch\s*>')
else:
    # เผื่อกรณีไม่มี prefix หรือ prefix ใด ๆ
    close_re = re.compile(r'</\s*(?:[A-Za-z0-9_.-]+:)?DeviceMessageBatch\s*>')

last = None
for m in close_re.finditer(data):
    last = m

if not last:
    sys.stderr.write("[ERROR] cannot find closing tag for DeviceMessageBatch (any namespace prefix)\n")
    sys.exit(3)

i = last.start()
before, after = data[:i], data[i:]

out = before
if not before.endswith('\n'):
    out += '\n'
out += sig
if not sig.endswith('\n'):
    out += '\n'
out += after

io.open(out_path, 'w', encoding='utf-8', newline='').write(out)
PY
}

insert_signature_enveloped "$BATCH_XML" "$SIGNATURE_XML" "$SIGNED_BATCH_XML"
echo "[INFO] Step 5: Enveloped signature inserted -> $SIGNED_BATCH_XML"

echo "[DONE] All artifacts are in $OUT_DIR"
