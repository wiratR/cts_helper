#!/usr/bin/env bash
set -Eeuo pipefail

# ===== Config (override ได้ด้วย ENV) =====
ROLE_ID="${ROLE_ID:-device}"
CURL_BIN="${CURL_BIN:-curl}"

# โดเมนหลักของโปรเจกต์ (เช่น preprod-mangmoom.com)
DEFAULT_HOST="${HOST:-vault.preprod-mangmoom.com}"
PROJECT_ROOT_URL_DEFAULT="${PROJECT_ROOT_URL:-${DEFAULT_HOST#vault.}}"
PROJECT_ROOT_URL="${PROJECT_ROOT_URL:-$PROJECT_ROOT_URL_DEFAULT}"
HOST="vault.${PROJECT_ROOT_URL}"

CERT_PATH="${CERT_PATH:-./certs/platform-certificate.crt}"

# Step 6 URL (AppRole login)
ENDPOINT="${ENDPOINT:-https://${HOST}/v1/auth/approle/login}"
# Step 8 URL (มี v1/v1 ตามสเปค)
STEP8_URL_DEFAULT="https://${HOST}/v1/v1/device-ca/sign/device"
STEP8_URL="${STEP8_URL:-$STEP8_URL_DEFAULT}"

# Secret ID formula: base64( sha256( base64_decode(project_salt) + ":" + utf8(hw_serial) ) )
PROJECT_SALT_B64="${PROJECT_SALT_B64:-6PsNcDh6NH5WnaItxsD7C2SkZpiSZkuljbcJUiNRIo0=}"
HW_SERIAL="${HW_SERIAL:-410113}"

# ===== Keypair / CSR / Cert =====
KEY_TYPE="${KEY_TYPE:-RSA}"
KEY_BITS="${KEY_BITS:-2048}"
KEY_DIR="${KEY_DIR:-./keys}"
KEY_PATH="${KEY_PATH:-${KEY_DIR}/authentication.key}"           # private key
PUB_PATH="${PUB_PATH:-${KEY_DIR}/authentication.pub.pem}"       # public key
CSR_PATH="${CSR_PATH:-${KEY_DIR}/authentication.csr}"           # CSR (PEM)
CERT_OUT_PATH="${CERT_OUT_PATH:-${KEY_DIR}/authentication.crt}" # device certificate (PEM)
REGEN_KEY="${REGEN_KEY:-0}"                                     # 1=สร้าง key ใหม่ทับ
REGEN_CSR="${REGEN_CSR:-1}"                                     # 1=สร้าง/เขียน CSR ทับ

# ===== Misc =====
INSECURE="${INSECURE:-0}"                 # 1=ใช้ --insecure (dev เท่านั้น)
SHOW_VERBOSE="${SHOW_VERBOSE:-0}"         # 1=แสดง verbose log
SHOW_SECRET="${SHOW_SECRET:-0}"           # 1=แสดง secret_id จริง
SHOW_TOKEN="${SHOW_TOKEN:-0}"             # 1=แสดง VAULT_TOKEN จริง
FORCE_HTTP1="${FORCE_HTTP1:-0}"           # 1=บังคับ --http1.1
FORCE_IPV4="${FORCE_IPV4:-0}"             # 1=บังคับ -4
PROCEED_ON_STEP6_ERROR="${PROCEED_ON_STEP6_ERROR:-1}"  # 1=Step6 ล้มเหลวไป Step7/8 ต่อ
EXPECTED_SECRET_ID="${EXPECTED_SECRET_ID:-}"
CONSOLE_JSON="${CONSOLE_JSON:-0}"         # 1=รวมผล curl เป็น JSON เดียว

# ===== JSON formatter (jq > python > cat) =====
if command -v jq >/dev/null 2>&1; then
  FORMATTER="jq ."
elif command -v python3 >/dev/null 2>&1; then
  FORMATTER="python3 -m json.tool"
elif command -v python >/dev/null 2>&1; then
  FORMATTER="python -m json.tool"
else
  FORMATTER="cat"
fi

require_openssl() { command -v openssl >/dev/null 2>&1 || { echo "[ERROR] ต้องติดตั้ง openssl ก่อน" >&2; exit 127; }; }
require_curl() {
  if [[ "$CURL_BIN" == */* ]]; then
    [[ -x "$CURL_BIN" ]] || { echo "[ERROR] curl binary ไม่ executable: $CURL_BIN" >&2; exit 127; }
  else
    command -v "$CURL_BIN" >/dev/null 2>&1 || { echo "[ERROR] ไม่พบ curl ใน PATH: $CURL_BIN" >&2; exit 127; }
  fi
}

# ===== Helpers =====
iso_now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { if [[ "$CONSOLE_JSON" == "1" ]]; then >&2 echo -e "$*"; else echo -e "$*"; fi; }

# NOTE: meta format ที่ใช้กับ --write-out
CURL_META_FMT=$'http_code=%{http_code}\ncontent_type=%{content_type}\nremote_ip=%{remote_ip}\nremote_port=%{remote_port}\nlocal_ip=%{local_ip}\nlocal_port=%{local_port}\nscheme=%{scheme}\nhttp_version=%{http_version}\nssl_verify_result=%{ssl_verify_result}\nssl_cipher=%{ssl_cipher}\nsize_upload=%{size_upload}\nsize_download=%{size_download}\nredirect_url=%{redirect_url}\nnum_connects=%{num_connects}\ntime_namelookup=%{time_namelookup}\ntime_connect=%{time_connect}\ntime_appconnect=%{time_appconnect}\ntime_pretransfer=%{time_pretransfer}\ntime_starttransfer=%{time_starttransfer}\ntime_total=%{time_total}\nurl_effective=%{url_effective}\n'
meta_get() { sed -n "s/^$2=//p" "$1"; }

# สำหรับโหมด JSON: buffer JSON ของแต่ละ step แล้วค่อยรวมพิมพ์ทีเดียว
STEP6_JSON="$(mktemp)"; echo "null" >"$STEP6_JSON"
STEP8_JSON="$(mktemp)"; echo "null" >"$STEP8_JSON"
trap 'rm -f "$STEP6_JSON" "$STEP8_JSON"' EXIT

# ===== พิมพ์คำสั่ง curl แบบสวย ๆ (Step 6/8) =====
print_pretty_curl_step6() {
  echo "---- CURL REQUEST (Step 6, copy/paste) ----"
  local lines=()
  lines+=("$CURL_BIN \\")
  lines+=("  -q -sS -v \\")
  lines+=("  -H 'Content-Type: application/json' \\")
  lines+=("  -X POST \\")
  if [[ -f "$CERT_PATH" && "$INSECURE" != "1" ]]; then lines+=("  --cacert '$CERT_PATH' \\"); else lines+=("  -k \\"); fi
  [[ "$FORCE_HTTP1" == "1" ]] && lines+=("  --http1.1 \\")
  [[ "$FORCE_IPV4" == "1" ]] && lines+=("  -4 \\")
  [[ -n "${HOST_IP:-}" ]] && lines+=("  --resolve '${HOST}:443:${HOST_IP}' \\")
  lines+=("  --data '${payload_print}' \\")
  lines+=("  '${ENDPOINT}'")
  printf "%s\n" "${lines[@]}"
}

print_pretty_curl_step8() {
  local header_token="$1"  # "X-Vault-Token: ***REDACTED***" หรือค่าจริงถ้า SHOW_TOKEN=1
  echo "---- CURL REQUEST (Step 8, copy/paste) ----"
  local lines=()
  lines+=("$CURL_BIN \\")
  lines+=("  -q -sS -v \\")
  lines+=("  -H 'Content-Type: application/json' \\")
  lines+=("  -H '${header_token}' \\")
  lines+=("  -X POST \\")
  if [[ -f "$CERT_PATH" && "$INSECURE" != "1" ]]; then lines+=("  --cacert '$CERT_PATH' \\"); else lines+=("  -k \\"); fi
  [[ "$FORCE_HTTP1" == "1" ]] && lines+=("  --http1.1 \\")
  [[ "$FORCE_IPV4" == "1" ]] && lines+=("  -4 \\")
  [[ -n "${HOST_IP:-}" ]] && lines+=("  --resolve '${HOST}:443:${HOST_IP}' \\")
  lines+=("  --data '${payload8}' \\")
  lines+=("  '${STEP8_URL}'")
  printf "%s\n" "${lines[@]}"
}

# ===== Step 5: Generate RSA key pair (authentication.key) =====
generate_rsa_keypair() {
  require_openssl
  if [[ "$CONSOLE_JSON" != "1" ]]; then
    log "===================================================================================="
    log "========== step 5 - generate authentication.key in directory keys =================="
    log "===================================================================================="
  fi
  mkdir -p "$KEY_DIR"
  if [[ -f "$KEY_PATH" && "$REGEN_KEY" != "1" ]]; then
    [[ "$CONSOLE_JSON" != "1" ]] && log "[INFO] พบ private key อยู่แล้ว: $KEY_PATH (ข้ามการสร้างใหม่; ตั้ง REGEN_KEY=1 เพื่อบังคับสร้างใหม่)"
  else
    [[ "$CONSOLE_JSON" != "1" ]] && log "[INFO] กำลังสร้างกุญแจ ${KEY_TYPE} ขนาด ${KEY_BITS}-bit -> $KEY_PATH"
    if openssl genpkey -algorithm "$KEY_TYPE" -pkeyopt rsa_keygen_bits:"$KEY_BITS" -out "$KEY_PATH" >/dev/null 2>&1; then :; else
      [[ "$CONSOLE_JSON" != "1" ]] && log "[WARN] genpkey ใช้งานไม่ได้ จะใช้ genrsa แทน"
      openssl genrsa -out "$KEY_PATH" "$KEY_BITS" >/dev/null
    fi
    chmod 600 "$KEY_PATH" 2>/dev/null || true
    [[ "$CONSOLE_JSON" != "1" ]] && log "[INFO] บันทึก private key แล้ว (chmod 600)"
    if openssl pkey -in "$KEY_PATH" -pubout -out "$PUB_PATH" >/dev/null 2>&1 || \
       openssl rsa  -in "$KEY_PATH" -pubout -out "$PUB_PATH"  >/dev/null 2>&1; then
      [[ "$CONSOLE_JSON" != "1" ]] && log "[INFO] บันทึก public key -> $PUB_PATH"
    else
      [[ "$CONSOLE_JSON" != "1" ]] && log "[WARN] export public key ไม่สำเร็จ"
    fi
    if openssl pkey -in "$KEY_PATH" -pubout -outform DER >/dev/null 2>&1; then
      fp="$(openssl pkey -in "$KEY_PATH" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 -binary | openssl base64 -A)"
    else
      fp="$(openssl rsa  -in "$KEY_PATH" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 -binary | openssl base64 -A || true)"
    fi
    [[ -n "${fp:-}" && "$CONSOLE_JSON" != "1" ]] && log "[INFO] Public Key SHA256 (base64): $fp"
  fi
}

# ===== Python function: compute SECRET_ID (รองรับทั้ง Python 2/3) =====
compute_secret_python() {
  local pybin=""
  if command -v python3 >/dev/null 2>&1; then pybin="python3"
  elif command -v python >/dev/null 2>&1; then pybin="python"
  else echo "[ERROR] ต้องมี python หรือ python3 เพื่่อคำนวณ SECRET_ID" >&2; exit 127; fi

  PROJECT_SALT_B64="$PROJECT_SALT_B64" HW_SERIAL="$HW_SERIAL" "$pybin" - <<'PY'
import base64, hashlib, os, sys
s=os.environ.get("PROJECT_SALT_B64",""); h=os.environ.get("HW_SERIAL","")
try:
    try: salt=base64.b64decode(s, validate=True)
    except TypeError: salt=base64.b64decode(s)
except Exception as e:
    sys.stderr.write("[ERROR] PROJECT_SALT_B64 base64 decode failed: %s\n"%e); sys.exit(2)
sep=b":" if sys.version_info[0]>=3 else ":"
h_bytes=h.encode("utf-8") if sys.version_info[0]>=3 else h
digest=hashlib.sha256(salt+sep+h_bytes).digest()
enc=base64.b64encode(digest)
if sys.version_info[0]>=3: enc=enc.decode("ascii")
sys.stdout.write(enc)
PY
}

# ===== Generic JSON extractor (.foo.bar) — ทนทาน: jq -> python -> grep/sed =====
extract_json_value() {
  # $1=file, $2=jq_path เช่น ".auth.client_token"
  local file="$1" path="$2" val=""
  # 1) jq
  if command -v jq >/dev/null 2>&1; then
    val="$(jq -r "$path // empty" "$file" 2>/dev/null || true)"
    if [[ -n "$val" && "$val" != "null" ]]; then printf '%s' "$val"; return 0; fi
  fi
  # 2) python
  local pybin=""
  if command -v python3 >/dev/null 2>&1; then pybin="python3"
  elif command -v python  >/dev/null 2>&1; then pybin="python"
  fi
  if [[ -n "$pybin" ]]; then
    val="$("$pybin" - "$path" "$file" <<'PY'
import json, sys, io
path=sys.argv[1].lstrip('.'); fname=sys.argv[2]
try:
    with io.open(fname, 'r', encoding='utf-8', errors='replace') as f:
        data=json.load(f)
except Exception:
    sys.exit(0)
cur=data
for p in [p for p in path.split('.') if p]:
    if isinstance(cur, dict) and p in cur:
        cur=cur[p]
    else:
        cur=None; break
if isinstance(cur, (str, bytes)):
    if isinstance(cur, bytes): cur=cur.decode('utf-8','replace')
    sys.stdout.write(cur)
elif cur is not None:
    sys.stdout.write(str(cur))
PY
)"
    if [[ -n "$val" && "$val" != "null" ]]; then printf '%s' "$val"; return 0; fi
  fi
  # 3) regex เฉพาะฟิลด์ยอดฮิต
  if [[ "$path" == ".auth.client_token" ]]; then
    LC_ALL=C grep -oE '"client_token"[[:space:]]*:[[:space:]]*"[^"]+"' "$file" 2>/dev/null \
      | head -n1 \
      | sed -E 's/.*"client_token"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/' || true
    return 0
  fi
  return 0
}

# ==== Step 5 ====
generate_rsa_keypair
[[ "$CONSOLE_JSON" != "1" ]] && log "===================================================================================="

# ===== Step 6: Retrieve Vault token by AppRole (using Secret ID) =====
if [[ "$CONSOLE_JSON" != "1" ]]; then
  log "===================================================================================="
  log "=== step 6 -- Retrieve Vault token by AppRole authentication using the secret ID ==="
  log "===================================================================================="
  log "[INFO] HW_SERIAL_NUMBER : $HW_SERIAL"
  log "[INFO] PROJECT_SALT_B64 : $PROJECT_SALT_B64"
fi

SECRET_ID="$(compute_secret_python)"
[[ -z "$SECRET_ID" ]] && { echo "[ERROR] คำนวณ SECRET_ID ไม่สำเร็จ" >&2; exit 2; }
[[ -n "$EXPECTED_SECRET_ID" && "$SECRET_ID" != "$EXPECTED_SECRET_ID" ]] && { >&2 echo "[WARN] SECRET_ID ต่างจาก EXPECTED_SECRET_ID (computed=$SECRET_ID expected=$EXPECTED_SECRET_ID)"; }
[[ "$SHOW_SECRET" == "1" && "$CONSOLE_JSON" != "1" ]] && log "[INFO] SECRET_ID       : $SECRET_ID"

payload=$(printf '{"role_id":"%s","secret_id":"%s"}' "$ROLE_ID" "$SECRET_ID")
payload_print="$payload"; [[ "$SHOW_SECRET" != "1" ]] && payload_print="$(printf '%s' "$payload" | sed -E 's/("secret_id":")([^"]+)"/\1***REDACTED***"/')"

require_curl
ts="$(date +%Y%m%d_%H%M%S)"; LOG_FILE="curl_verbose_${ts}.log"; BODY_FILE="$(mktemp)"; trap 'rm -f "$BODY_FILE"' EXIT
META6_FILE="$(mktemp)"; HDR6_FILE="$(mktemp)"; trap 'rm -f "$META6_FILE" "$HDR6_FILE"' EXIT

EXTRA_PARTS=()
if [[ -f "$CERT_PATH" && "$INSECURE" != "1" ]]; then EXTRA_PARTS+=( --cacert "$CERT_PATH" ); else EXTRA_PARTS+=( -k ); fi
[[ "$FORCE_HTTP1" == "1" ]] && EXTRA_PARTS+=( --http1.1 )
[[ "$FORCE_IPV4" == "1" ]] && EXTRA_PARTS+=( -4 )
[[ -n "${HOST_IP:-}" ]] && EXTRA_PARTS+=( --resolve "${HOST}:443:${HOST_IP}" )

CURL_ARGS_BASE=( -q -sS -v -H "Content-Type: application/json" -X POST --dump-header "$HDR6_FILE" --write-out "$CURL_META_FMT" )
CURL_ARGS_RUN=( "${CURL_ARGS_BASE[@]}" "${EXTRA_PARTS[@]}" --data "$payload" )

# โหมด human: โชว์เฉพาะ CURL REQUEST แบบสวย
if [[ "$CONSOLE_JSON" != "1" ]]; then
  print_pretty_curl_step6
fi

TS6_START="$(iso_now_utc)"; rc=0
"$CURL_BIN" "${CURL_ARGS_RUN[@]}" "$ENDPOINT" -o "$BODY_FILE" >"$META6_FILE" 2>"$LOG_FILE" || rc=$?
TS6_END="$(iso_now_utc)"

HTTP_CODE_6="$(meta_get "$META6_FILE" http_code)"

emit_step6_json() {
  jq -n \
    --arg step "6" --arg name "approle_login" \
    --arg ts_start "$TS6_START" --arg ts_end "$TS6_END" \
    --arg method "POST" --arg url "$ENDPOINT" --arg host "$HOST" \
    --argjson insecure $([[ "$INSECURE" == "1" ]] && echo true || echo false) \
    --arg cacert "$([[ -f "$CERT_PATH" && "$INSECURE" != "1" ]] && echo "$CERT_PATH" || echo "")" \
    --arg resolve "${HOST_IP:-}" \
    --argjson force_http1 $([[ "$FORCE_HTTP1" == "1" ]] && echo true || echo false) \
    --argjson force_ipv4 $([[ "$FORCE_IPV4" == "1" ]] && echo true || echo false) \
    --arg req_body "$payload_print" \
    --arg resp_body "$(cat "$BODY_FILE")" \
    --arg resp_headers_raw "$(cat "$HDR6_FILE")" \
    --arg http_code "$(meta_get "$META6_FILE" http_code)" \
    --arg content_type "$(meta_get "$META6_FILE" content_type)" \
    --arg remote_ip "$(meta_get "$META6_FILE" remote_ip)" \
    --arg remote_port "$(meta_get "$META6_FILE" remote_port)" \
    --arg local_ip "$(meta_get "$META6_FILE" local_ip)" \
    --arg local_port "$(meta_get "$META6_FILE" local_port)" \
    --arg scheme "$(meta_get "$META6_FILE" scheme)" \
    --arg http_version "$(meta_get "$META6_FILE" http_version)" \
    --arg ssl_verify_result "$(meta_get "$META6_FILE" ssl_verify_result)" \
    --arg ssl_cipher "$(meta_get "$META6_FILE" ssl_cipher)" \
    --arg size_upload "$(meta_get "$META6_FILE" size_upload)" \
    --arg size_download "$(meta_get "$META6_FILE" size_download)" \
    --arg redirect_url "$(meta_get "$META6_FILE" redirect_url)" \
    --arg num_connects "$(meta_get "$META6_FILE" num_connects)" \
    --arg time_namelookup "$(meta_get "$META6_FILE" time_namelookup)" \
    --arg time_connect "$(meta_get "$META6_FILE" time_connect)" \
    --arg time_appconnect "$(meta_get "$META6_FILE" time_appconnect)" \
    --arg time_pretransfer "$(meta_get "$META6_FILE" time_pretransfer)" \
    --arg time_starttransfer "$(meta_get "$META6_FILE" time_starttransfer)" \
    --arg time_total "$(meta_get "$META6_FILE" time_total)" \
    --arg url_effective "$(meta_get "$META6_FILE" url_effective)" \
    '{
      step: ($step|tonumber), name: $name,
      timestamp: { start: $ts_start, end: $ts_end },
      request: {
        method: $method, url: $url, host: $host,
        headers: {"Content-Type":"application/json"},
        insecure: $insecure, cacert: ( $cacert | select(length>0) ),
        resolve: ( $resolve | select(length>0) ),
        force_http1: $force_http1, force_ipv4: $force_ipv4,
        body: $req_body
      },
      response: {
        http_code: ($http_code|tonumber? // 0),
        content_type: $content_type,
        headers_raw: $resp_headers_raw,
        body: $resp_body
      },
      network: {
        scheme: $scheme,
        http_version: $http_version,
        local: { ip: $local_ip, port: ($local_port|tonumber?) },
        remote:{ ip: $remote_ip, port: ($remote_port|tonumber?) }
      },
      tls: {
        verify_result: ($ssl_verify_result|tonumber? // null),
        verify_ok: (($ssl_verify_result|tonumber? // 1) == 0),
        cipher: ( $ssl_cipher | select(length>0) )
      },
      metrics: {
        time: {
          namelookup: ($time_namelookup|tonumber?),
          connect: ($time_connect|tonumber?),
          appconnect: ($time_appconnect|tonumber?),
          pretransfer: ($time_pretransfer|tonumber?),
          starttransfer: ($time_starttransfer|tonumber?),
          total: ($time_total|tonumber?)
        },
        size: { upload: ($size_upload|tonumber?), download: ($size_download|tonumber?) },
        redirects: { url: ( $redirect_url | select(length>0) ) },
        connects: ($num_connects|tonumber?)
      },
      url_effective: $url_effective
    }'
}

if (( rc != 0 )); then
  [[ "$CONSOLE_JSON" == "1" ]] || {
    >&2 echo "[ERROR] curl failed (code $rc) — ดูท้าย verbose log"
    >&2 tail -n 120 "$LOG_FILE" | sed -E 's/^([<>*])/\1 /'
    case "$rc" in
      6) >&2 echo "[HINT] DNS ล้มเหลว (Could not resolve host)";;
      7) >&2 echo "[HINT] ต่อ TCP ไม่ติด/ถูกบล็อค (Failed to connect)";;
      35) >&2 echo "[HINT] TLS handshake ผิดพลาด/โปรโตคอลไม่ตรงกัน";;
      60|77) >&2 echo "[HINT] ปัญหาใบรับรอง/CA; ตรวจ --cacert หรือเวลาเครื่อง";;
      *)  >&2 echo "[HINT] ดูข้อความใน verbose log เพื่อระบุสาเหตุ";;
    esac
  }
  if command -v jq >/dev/null 2>&1; then emit_step6_json >"$STEP6_JSON"; fi
  [[ "$PROCEED_ON_STEP6_ERROR" == "1" ]] || { [[ "$CONSOLE_JSON" == "1" ]] && jq -n --slurpfile s6 "$STEP6_JSON" '{steps: ( ($s6|length>0) and ($s6[0]!=null) ? [$s6[0]] : [] ) }'; exit "$rc"; }
else
  [[ "$CONSOLE_JSON" != "1" ]] && { echo "===================================================================================="; echo "== HTTP ${HTTP_CODE_6} =="; cat "$BODY_FILE" | eval "$FORMATTER"; }
  # ดึง VAULT_TOKEN อัตโนมัติ (robust)
  VAULT_TOKEN="$(extract_json_value "$BODY_FILE" '.auth.client_token')"
  if [[ -n "$VAULT_TOKEN" ]]; then
    [[ "$CONSOLE_JSON" != "1" ]] && log "[INFO] Vault token (preview): ${VAULT_TOKEN:0:8}… (len=${#VAULT_TOKEN})"
  else
    [[ "$CONSOLE_JSON" != "1" ]] && log "[WARN] ไม่พบ .auth.client_token ใน response"
  fi
  if command -v jq >/dev/null 2>&1; then emit_step6_json >"$STEP6_JSON"; fi
fi

# ===== Step 7: Create CSR (PEM) signed with authentication.key (CN = HW_SERIAL) =====
create_csr() {
  require_openssl
  if [[ "$CONSOLE_JSON" != "1" ]]; then
    log "===================================================================================="
    log "step 7 -- Create CSR (PEM) signed by authentication.key (CN = hardware serial number)"
    log "===================================================================================="
  fi
  mkdir -p "$KEY_DIR"
  if [[ -f "$CSR_PATH" && "$REGEN_CSR" != "1" ]]; then
    [[ "$CONSOLE_JSON" != "1" ]] && log "[INFO] พบ CSR อยู่แล้ว: $CSR_PATH (ข้ามการสร้างใหม่; ตั้ง REGEN_CSR=1 เพื่อเขียนทับ)"
    return 0
  fi
  [[ -f "$KEY_PATH" ]] || { echo "[ERROR] ไม่พบ private key: $KEY_PATH (ต้องมีจาก Step 5)" >&2; return 3; }
  if openssl req -new -key "$KEY_PATH" -subj "/CN=${HW_SERIAL}" -sha256 -out "$CSR_PATH"; then
    [[ "$CONSOLE_JSON" != "1" ]] && { log "[INFO] บันทึก CSR -> $CSR_PATH"; log "[INFO] ตรวจสอบสรุป CSR:"; openssl req -in "$CSR_PATH" -noout -subject -text | sed -n '1,20p'; }
  else
    echo "[ERROR] สร้าง CSR ไม่สำเร็จ" >&2; return 4
  fi
}
create_csr

# ===== Step 8: Send CSR to Vault (sign) and save certificate =====
send_csr_and_save_cert() {
  local token_use="${VAULT_TOKEN:-}"
  if [[ -z "$token_use" ]]; then
    [[ "$CONSOLE_JSON" != "1" ]] && log "[WARN] ไม่มี VAULT_TOKEN — ข้าม Step 8"
    return 0
  fi
  [[ -f "$CSR_PATH" ]] || { echo "[ERROR] ไม่พบ CSR: $CSR_PATH" >&2; return 2; }

  local CSR_ONE_LINE payload8 header_real header_print
  CSR_ONE_LINE="$(awk 'NF {sub(/\r/,""); printf "%s\\n",$0}' "$CSR_PATH")"
  payload8=$(printf '{"common_name":"%s","csr":"%s","format":"PEM"}' "$HW_SERIAL" "$CSR_ONE_LINE")

  header_real="X-Vault-Token: $token_use"
  header_print="X-Vault-Token: ***REDACTED***"
  [[ "$SHOW_TOKEN" == "1" ]] && header_print="$header_real"

  META8_FILE="$(mktemp)"; HDR8_FILE="$(mktemp)"; trap 'rm -f "$META8_FILE" "$HDR8_FILE"' EXIT

  CURL8_ARGS_BASE=( -q -sS -v -H "Content-Type: application/json" -H "$header_real" -X POST --dump-header "$HDR8_FILE" --write-out "$CURL_META_FMT" )
  CURL8_RUN=( "${CURL8_ARGS_BASE[@]}" "${EXTRA_PARTS[@]}" --data "$payload8" )

  if [[ "$CONSOLE_JSON" != "1" ]]; then
    print_pretty_curl_step8 "$header_print"
  fi

  TS8_START="$(iso_now_utc)"; rc8=0
  "$CURL_BIN" "${CURL8_RUN[@]}" "$STEP8_URL" -o "$BODY_FILE" >"$META8_FILE" 2>>"$LOG_FILE" || rc8=$?
  TS8_END="$(iso_now_utc)"
  HTTP_CODE_8="$(meta_get "$META8_FILE" http_code)"

  emit_step8_json() {
    jq -n \
      --arg step "8" --arg name "sign_device_cert" \
      --arg ts_start "$TS8_START" --arg ts_end "$TS8_END" \
      --arg method "POST" --arg url "$STEP8_URL" --arg host "$HOST" \
      --arg header_token "$header_print" \
      --argjson insecure $([[ "$INSECURE" == "1" ]] && echo true || echo false) \
      --arg cacert "$([[ -f "$CERT_PATH" && "$INSECURE" != "1" ]] && echo "$CERT_PATH" || echo "")" \
      --arg resolve "${HOST_IP:-}" \
      --argjson force_http1 $([[ "$FORCE_HTTP1" == "1" ]] && echo true || echo false) \
      --argjson force_ipv4 $([[ "$FORCE_IPV4" == "1" ]] && echo true || echo false) \
      --arg req_body "$payload8" \
      --arg resp_body "$(cat "$BODY_FILE")" \
      --arg resp_headers_raw "$(cat "$HDR8_FILE")" \
      --arg http_code "$(meta_get "$META8_FILE" http_code)" \
      --arg content_type "$(meta_get "$META8_FILE" content_type)" \
      --arg remote_ip "$(meta_get "$META8_FILE" remote_ip)" \
      --arg remote_port "$(meta_get "$META8_FILE" remote_port)" \
      --arg local_ip "$(meta_get "$META8_FILE" local_ip)" \
      --arg local_port "$(meta_get "$META8_FILE" local_port)" \
      --arg scheme "$(meta_get "$META8_FILE" scheme)" \
      --arg http_version "$(meta_get "$META8_FILE" http_version)" \
      --arg ssl_verify_result "$(meta_get "$META8_FILE" ssl_verify_result)" \
      --arg ssl_cipher "$(meta_get "$META8_FILE" ssl_cipher)" \
      --arg size_upload "$(meta_get "$META8_FILE" size_upload)" \
      --arg size_download "$(meta_get "$META8_FILE" size_download)" \
      --arg redirect_url "$(meta_get "$META8_FILE" redirect_url)" \
      --arg num_connects "$(meta_get "$META8_FILE" num_connects)" \
      --arg time_namelookup "$(meta_get "$META8_FILE" time_namelookup)" \
      --arg time_connect "$(meta_get "$META8_FILE" time_connect)" \
      --arg time_appconnect "$(meta_get "$META8_FILE" time_appconnect)" \
      --arg time_pretransfer "$(meta_get "$META8_FILE" time_pretransfer)" \
      --arg time_starttransfer "$(meta_get "$META8_FILE" time_starttransfer)" \
      --arg time_total "$(meta_get "$META8_FILE" time_total)" \
      --arg url_effective "$(meta_get "$META8_FILE" url_effective)" \
      '{
        step: ($step|tonumber), name: $name,
        timestamp: { start: $ts_start, end: $ts_end },
        request: {
          method: $method, url: $url, host: $host,
          headers: {"Content-Type":"application/json", "X-Vault-Token": $header_token},
          insecure: $insecure, cacert: ( $cacert | select(length>0) ),
          resolve: ( $resolve | select(length>0) ),
          force_http1: $force_http1, force_ipv4: $force_ipv4,
          body: $req_body
        },
        response: {
          http_code: ($http_code|tonumber? // 0),
          content_type: $content_type,
          headers_raw: $resp_headers_raw,
          body: $resp_body
        },
        network: {
          scheme: $scheme,
          http_version: $http_version,
          local: { ip: $local_ip, port: ($local_port|tonumber?) },
          remote:{ ip: $remote_ip, port: ($remote_port|tonumber?) }
        },
        tls: {
          verify_result: ($ssl_verify_result|tonumber? // null),
          verify_ok: (($ssl_verify_result|tonumber? // 1) == 0),
          cipher: ( $ssl_cipher | select(length>0) )
        },
        metrics: {
          time: {
            namelookup: ($time_namelookup|tonumber?),
            connect: ($time_connect|tonumber?),
            appconnect: ($time_appconnect|tonumber?),
            pretransfer: ($time_pretransfer|tonumber?),
            starttransfer: ($time_starttransfer|tonumber?),
            total: ($time_total|tonumber?)
          },
          size: { upload: ($size_upload|tonumber?), download: ($size_download|tonumber?) },
          redirects: { url: ( $redirect_url | select(length>0) ) },
          connects: ($num_connects|tonumber?)
        },
        url_effective: $url_effective
      }'
  }

  if (( rc8 != 0 )); then
    [[ "$CONSOLE_JSON" != "1" ]] && { >&2 echo "[ERROR] Step 8 curl failed (code $rc8) — ดูท้าย verbose log"; >&2 tail -n 120 "$LOG_FILE" | sed -E 's/^([<>*])/\1 /'; }
    if command -v jq >/dev/null 2>&1; then emit_step8_json >"$STEP8_JSON"; fi
    return "$rc8"
  fi

  if [[ "$CONSOLE_JSON" != "1" ]]; then
    echo "===================================================================================="
    echo "== HTTP ${HTTP_CODE_8} =="; cat "$BODY_FILE" | eval "$FORMATTER"
  fi

  # save device certificate
  local cert=""
  if command -v jq >/dev/null 2>&1; then
    cert="$(jq -r '.data.certificate // empty' "$BODY_FILE" 2>/dev/null || true)"
  else
    cert="$(sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$BODY_FILE")"
  fi
  if [[ -n "$cert" ]]; then
    printf '%s\n' "$cert" > "$CERT_OUT_PATH"
    [[ "$CONSOLE_JSON" != "1" ]] && log "[INFO] บันทึกอุปกรณ์ certificate -> $CERT_OUT_PATH"
  else
    [[ "$CONSOLE_JSON" != "1" ]] && echo "[WARN] ไม่พบฟิลด์ใบรับรองใน response (คาดหวัง .data.certificate)" >&2
  fi

  if command -v jq >/dev/null 2>&1; then emit_step8_json >"$STEP8_JSON"; fi
  return 0
}
send_csr_and_save_cert || true

# ===== Final output =====
if [[ "$CONSOLE_JSON" == "1" && -x "$(command -v jq)" ]]; then
  jq -n --slurpfile s6 "$STEP6_JSON" --slurpfile s8 "$STEP8_JSON" '
    { steps:
        ( ((($s6|length)>0 and $s6[0]!=null) ? [$s6[0]] : [])
        + ((($s8|length)>0 and $s8[0]!=null) ? [$s8[0]] : []) )
    }'
else
  if [[ "$SHOW_VERBOSE" == "1" ]]; then
    >&2 echo -e "\n---- curl verbose log ($LOG_FILE) ----"
    >&2 sed -E 's/^([<>*])/\1 /' "$LOG_FILE" || true
  else
    >&2 echo "[INFO] Verbose log saved to: $LOG_FILE"
  fi
fi

exit 0
