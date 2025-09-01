#!/usr/bin/env bash
set -euo pipefail

# get_denylist.sh
# Download a Deny List FlatBuffers file via HTTP and optionally run denylist_reader.py.
#
# Usage examples:
#   ./get_denylist.sh --base-url https://api.example.com \
#                     --id 12345 \
#                     --token "$TOKEN" \
#                     --out primaryDenyList.bin \
#                     --stats --list --suppress-id-warn
#
#   ./get_denylist.sh --base-url https://api.example.com \
#                     --id 12345 \
#                     --api-key "$API_KEY" \
#                     --expect-zip \
#                     --export-csv denylist.csv
#
#   ./get_denylist.sh --base-url https://api.example.com \
#                     --id 12345 \
#                     --basic "user:pass" \
#                     --pan ABCDEF123... \
#                     --reader-cmd "python3 /path/to/denylist_reader.py"
#
# Flags:
#   --base-url           Base URL (e.g., https://host)
#   --id, --denylist-id  Deny list id
#   --token              Bearer token (Authorization: Bearer ...)
#   --api-key            API key (x-api-key: ...)
#   --basic              Basic auth "user:pass"
#   --out                Output .bin path (default: primaryDenyList.bin)
#   --expect-zip         Treat response as ZIP (extract first .bin inside)
#   --auto               Auto-detect ZIP by Content-Type or file magic
#   --http1.1            Force HTTP/1.1
#   --cacert PATH        Provide custom CA cert
#   --insecure           Skip TLS verification (NOT recommended)
#   --suppress-id-warn   Pass through to reader to hide file_identifier warning
#   --stats              Run reader: print stats
#   --list               Run reader: list all entries
#   --pan VALUE          Run reader: check a single PAN
#   --export-csv PATH    Run reader: export entries as CSV
#   --export-json PATH   Run reader: export entries+reasons as JSON
#   --reader-cmd CMD     Reader command (default: python3 ./denylist_reader.py)
#   --curl PATH          Path to curl binary (default: ./bin/curl if executable, else system curl)
#
# Requirements:
#   - curl
#   - unzip (if using --expect-zip / --auto for ZIP responses) or Python fallback available
#   - denylist_reader.py + generated FlatBuffers Python files (see README.md)
#
usage() {
  sed -n '1,100p' "$0" | sed 's/^# \{0,1\}//'
}

BASE_URL=""
DENY_ID=""
TOKEN=""
API_KEY=""
BASIC=""
OUT="primaryDenyList.bin"
EXPECT_ZIP=0
AUTO_DETECT=0
INSECURE=0
CACERT=""
CURL_EXTRA=()
READER_CMD=""
READER_FLAGS=()
CURL_CMD="${CURL_CMD:-}"   # env override allowed

needs_arg() {
  case "$1" in
    --pan|--export-csv|--export-json|--base-url|--id|--denylist-id|--token|--api-key|--basic|--out|--cacert|--reader-cmd|--curl) return 0 ;;
    *) return 1 ;;
  esac
}

if [[ $# -eq 0 ]]; then usage; exit 1; fi

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url) BASE_URL="${2:-}"; shift 2;;
    --id|--denylist-id) DENY_ID="${2:-}"; shift 2;;
    --token) TOKEN="${2:-}"; shift 2;;
    --api-key) API_KEY="${2:-}"; shift 2;;
    --basic) BASIC="${2:-}"; shift 2;;
    --out) OUT="${2:-}"; shift 2;;
    --expect-zip) EXPECT_ZIP=1; shift;;
    --auto) AUTO_DETECT=1; shift;;
    --http1.1) CURL_EXTRA+=(--http1.1); shift;;
    --cacert) CACERT="${2:-}"; shift 2;;
    --insecure) INSECURE=1; shift;;
    --suppress-id-warn) READER_FLAGS+=(--suppress-id-warn); shift;;
    --stats|--list)
      READER_FLAGS+=("$1"); shift;;
    --pan|--export-csv|--export-json)
      flag="$1"; val="${2:-}"
      if [[ -z "$val" || "$val" == --* ]]; then echo "Missing argument for $flag"; exit 2; fi
      READER_FLAGS+=("$flag" "$val"); shift 2;;
    --reader-cmd) READER_CMD="${2:-}"; shift 2;;
    --curl) CURL_CMD="${2:-}"; shift 2;;
    -h|--help) usage; exit 0;;
    *)
      echo "Unknown option: $1"; usage; exit 2;;
  esac
done

# Decide curl path:
if [[ -z "$CURL_CMD" ]]; then
  if [[ -x "./bin/curl" ]]; then
    CURL_CMD="./bin/curl"
  else
    CURL_CMD="$(command -v curl || true)"
  fi
fi
if [[ -z "$CURL_CMD" ]]; then
  echo "[ERR] curl not found. Install curl or provide --curl /path/to/curl" >&2
  exit 2
fi

echo "[INFO] Using curl at: $CURL_CMD"

# Basic validation
if [[ -z "$BASE_URL" || -z "$DENY_ID" ]]; then
  echo "[ERR] --base-url and --id are required"
  exit 2
fi

if [[ -z "$TOKEN" && -z "$API_KEY" && -z "$BASIC" ]]; then
  echo "[WARN] No auth specified ( --token / --api-key / --basic ). Continuing unauthenticated..."
fi

URL="${BASE_URL%/}/cysl/denyLists/flatBuffers/${DENY_ID}"

# Prepare curl headers
CURL_HEADERS=(-H "Accept-Encoding: identity")
if (( EXPECT_ZIP || AUTO_DETECT )); then
  CURL_HEADERS+=(-H "Accept: application/zip, application/octet-stream;q=0.9, */*;q=0.5")
else
  CURL_HEADERS+=(-H "Accept: application/octet-stream, */*;q=0.5")
fi

if [[ -n "$TOKEN" ]]; then
  CURL_HEADERS+=(-H "Authorization: Bearer $TOKEN")
fi
if [[ -n "$API_KEY" ]]; then
  CURL_HEADERS+=(-H "x-api-key: $API_KEY")
fi

# TLS options
if (( INSECURE )); then
  CURL_EXTRA+=(-k)
fi
if [[ -n "$CACERT" ]]; then
  CURL_EXTRA+=(--cacert "$CACERT")
fi

# Basic auth (optional)
CURL_AUTH=()
if [[ -n "$BASIC" ]]; then
  CURL_AUTH=(-u "$BASIC")
fi

tmp_body="$(mktemp -t denylist_body.XXXXXX)"
tmp_head="$(mktemp -t denylist_head.XXXXXX)"
cleanup() { rm -f "$tmp_body" "$tmp_head"; }
trap cleanup EXIT

echo "[INFO] Downloading: $URL"
set -x
"$CURL_CMD" -fSL --retry 3 --retry-all-errors \
  -D "$tmp_head" \
  -o "$tmp_body" \
  "${CURL_HEADERS[@]}" \
  "${CURL_AUTH[@]}" \
  "${CURL_EXTRA[@]}" \
  "$URL"
set +x

is_zip=0
if (( EXPECT_ZIP )); then
  is_zip=1
elif (( AUTO_DETECT )); then
  # Check Content-Type header first
  ct="$(grep -i '^content-type:' "$tmp_head" | tail -n1 | awk '{print tolower($2)}' | tr -d '\r')"
  if [[ "$ct" == application/zip* ]]; then
    is_zip=1
  else
    # Fallback to file magic
    if command -v file >/dev/null 2>&1; then
      mt="$(file -b --mime-type "$tmp_body" || true)"
      [[ "$mt" == "application/zip" ]] && is_zip=1 || true
    fi
  fi
fi

if (( is_zip )); then
  echo "[INFO] Response appears to be a ZIP; extracting first .bin ..."
  # Prefer unzip if available; otherwise use Python fallback
  if command -v unzip >/dev/null 2>&1; then
    # Try to extract first *.bin; if none, extract first entry
    if unzip -Z1 "$tmp_body" | grep -i '\.bin$' >/dev/null 2>&1; then
      unzip -p "$tmp_body" '*.bin' > "$OUT"
    else
      first="$(unzip -Z1 "$tmp_body" | head -n1)"
      unzip -p "$tmp_body" "$first" > "$OUT"
    fi
  else
    python3 - << 'PY' "$tmp_body" "$OUT"
import sys, zipfile
zip_path, out_path = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(zip_path, 'r') as zf:
    names = zf.namelist()
    if not names:
        raise SystemExit("Empty ZIP")
    target = next((n for n in names if n.lower().endswith('.bin')), names[0])
    with open(out_path, 'wb') as fo:
        fo.write(zf.read(target))
print(f"[OK] extracted -> {out_path}")
PY
  fi
else
  mv -f "$tmp_body" "$OUT"
  # avoid cleanup removing moved tmp
  tmp_body="/dev/null"
fi

echo "[OK] saved -> $OUT"

# Run reader if flags provided
if [[ ${#READER_FLAGS[@]} -gt 0 ]]; then
  if [[ -z "$READER_CMD" ]]; then
    if [[ -f "./denylist_reader.py" ]]; then
      READER_CMD="python3 ./denylist_reader.py"
    else
      READER_CMD="python3 denylist_reader.py"
    fi
  fi
  echo "[INFO] Running: $READER_CMD $OUT ${READER_FLAGS[*]}"
  set -x
  $READER_CMD "$OUT" "${READER_FLAGS[@]}"
  set +x
fi
