#!/usr/bin/env bash
set -euo pipefail

# cts_login.sh
# Login เพื่อขอ access token (Bearer) จาก CTS
#
# เอกสารอ้างอิง:
# - POST /v1.0.0/acm/login   (รับ token สำหรับเรียก API อื่น ๆ)  [consumes: application/x-www-form-urlencoded]
#   ต้องส่ง Basic auth (username:password) + form fields: realm=device, grant_type=password
#   และผลลัพธ์จะมี access_token, token_type="Bearer", expires_in, refresh_token, ... 
#   (อิงตามสเปกในเอกสาร) 
#
# ใช้งานตัวอย่าง:
#   ./cts_login.sh --base-url https://<host> --user <username> --pass <password>
#   TOKEN="$(./cts_login.sh --base-url https://<host> --user user --pass 'p@ss')" \
#     ./get_denylist.sh --base-url https://<host> --id <denylistId> --token "$TOKEN" --stats
#
# ตัวเลือก:
#   --base-url URL        Base URL เช่น https://api.example.com
#   --user USERNAME       ชื่อผู้ใช้ (ใช้กับ Basic auth)
#   --pass PASSWORD       รหัสผ่าน (ใช้กับ Basic auth)
#   --realm VALUE         ค่า realm (ดีฟอลต์: device)
#   --grant-type VALUE    ค่า grant_type (ดีฟอลต์: password)
#   --curl PATH           path ของ curl (ดีฟอลต์: ./bin/curl ถ้ามี, ไม่งั้น system curl)
#   --http1.1             บังคับใช้ HTTP/1.1
#   --cacert PATH         ใส่ CA เฉพาะองค์กร
#   --insecure            ข้าม TLS verify (ไม่แนะนำ)
#   --json                พิมพ์ JSON ทั้งก้อนแทน token อย่างเดียว
#   --export-env          พิมพ์รูปแบบ export TOKEN=... (เอาไป source ต่อได้)
#
usage() {
  sed -n '1,80p' "$0" | sed 's/^# \{0,1\}//'
}

BASE_URL=""
USERNAME=""
PASSWORD=""
REALM="device"
GRANT="password"
PRINT_JSON=0
EXPORT_ENV=0
CURL_CMD="${CURL_CMD:-}"
CURL_EXTRA=()

needs_arg() {
  case "$1" in
    --base-url|--user|--pass|--realm|--grant-type|--curl|--cacert) return 0 ;;
    *) return 1 ;;
  esac
}

if [[ $# -eq 0 ]]; then usage; exit 1; fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url) BASE_URL="${2:-}"; shift 2;;
    --user) USERNAME="${2:-}"; shift 2;;
    --pass) PASSWORD="${2:-}"; shift 2;;
    --realm) REALM="${2:-}"; shift 2;;
    --grant-type) GRANT="${2:-}"; shift 2;;
    --curl) CURL_CMD="${2:-}"; shift 2;;
    --http1.1) CURL_EXTRA+=(--http1.1); shift;;
    --cacert) CURL_EXTRA+=(--cacert "${2:-}"); shift 2;;
    --insecure) CURL_EXTRA+=(-k); shift;;
    --json) PRINT_JSON=1; shift;;
    --export-env) EXPORT_ENV=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option: $1"; usage; exit 2;;
  esac
done

if [[ -z "$BASE_URL" || -z "$USERNAME" || -z "$PASSWORD" ]]; then
  echo "[ERR] --base-url, --user และ --pass จำเป็นต้องระบุ" >&2
  exit 2
fi

# เลือก curl
if [[ -z "$CURL_CMD" ]]; then
  if [[ -x "./bin/curl" ]]; then
    CURL_CMD="./bin/curl"
  else
    CURL_CMD="$(command -v curl || true)"
  fi
fi
if [[ -z "$CURL_CMD" ]]; then
  echo "[ERR] ไม่พบ curl โปรดติดตั้งหรือกำหนด --curl /path/to/curl" >&2
  exit 2
fi

LOGIN_URL="${BASE_URL%/}/v1.0.0/acm/login"

# สเปกกำหนดว่า endpoint นี้:
# - Consumes: application/x-www-form-urlencoded
# - ต้องส่ง form: realm=device, grant_type=password
# - ใช้ Basic auth (username:password) ใน HTTP Authorization header
# - ผลลัพธ์มี access_token/token_type=Bearer/expires_in/... เป็น JSON
# (ตามเอกสารอ้างอิง)
#
# หมายเหตุ: Accept header จากเอกสารเป็น 
#   "application/resource.oauthaccesstokenexchange+hal+json; charset=UTF-8"
# เราตั้ง Accept เป็นค่านี้ และ Content-Type เป็น x-www-form-urlencoded
#
TMP="$(mktemp -t cts_login.XXXXXX.json)"
cleanup() { rm -f "$TMP"; }
trap cleanup EXIT

set -x
"$CURL_CMD" -fSL --retry 3 --retry-all-errors \
  -u "${USERNAME}:${PASSWORD}" \
  -H "Accept: application/resource.oauthaccesstokenexchange+hal+json; charset=UTF-8" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "realm=${REALM}" \
  -d "grant_type=${GRANT}" \
  -o "$TMP" \
  "${CURL_EXTRA[@]}" \
  "$LOGIN_URL"
set +x

# ดึง access_token ออกมา (พยายามใช้ jq ถ้ามี; ไม่มีก็ใช้ python)
if (( PRINT_JSON )); then
  cat "$TMP"
  exit 0
fi

if command -v jq >/dev/null 2>&1; then
  TOKEN="$(jq -r '.access_token // empty' "$TMP")"
else
  TOKEN="$(python3 - << 'PY' "$TMP"
import sys, json
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    j=json.load(f)
print(j.get('access_token',''))
PY
)"
fi

if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
  echo "[ERR] ไม่พบ access_token ในผลลัพธ์" >&2
  echo "----- response -----" >&2
  cat "$TMP" >&2
  exit 1
fi

if (( EXPORT_ENV )); then
  printf 'export TOKEN=%q\n' "$TOKEN"
else
  printf '%s\n' "$TOKEN"
fi
