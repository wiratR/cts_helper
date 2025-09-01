chmod +x enrollment.sh

# ดีฟอลต์: สร้างกุญแจ → คำนวณ SECRET_ID → login (Step 6) → สร้าง CSR (Step 7) → ส่ง CSR (Step 8)
./enrollment.sh

# แสดง secret/token จริง (ระวังข้อมูลอ่อนไหว), บังคับสร้าง key/CSR ใหม่, แก้ DNS ด้วย IP
SHOW_SECRET=1 SHOW_TOKEN=1 REGEN_KEY=1 REGEN_CSR=1 HOST_IP=203.0.113.10 ./enrollment.sh

# ถ้า Step 6 ต่อ Vault ไม่ได้ แต่คุณมี VAULT_TOKEN เองอยู่แล้ว ก็ยังทำ Step 8 ได้
VAULT_TOKEN='paste-your-token' ./enrollment.sh


# แสดง secret/token จริง (ระวังข้อมูลอ่อนไหว), บังคับสร้าง key/CSR ใหม่, สร้าง CSR ใหม่
CURL_BIN=./bin/curl SHOW_SECRET=1 SHOW_TOKEN=1 REGEN_KEY=1 REGEN_CSR=1 HW_SERIAL=414209./enrollment.sh

# ใช้ curl จาก ./bin/curl + override DNS ด้วย IP
CURL_BIN=./bin/curl HOST_IP=203.0.113.10 ./enrollment.sh

# แสดงรายละเอียด

SHOW_SECRET=1 SHOW_TOKEN=1 ./enrollment.sh
# 
CURL_BIN=./bin/curl SHOW_SECRET=1 SHOW_TOKEN=1 ./enrollment.sh

# หรือ JSON:
CONSOLE_JSON=1 ./enrollment.sh | jq .




./sign_batch.sh \
  -i ./batch/transactions.xml \
  -k ./keys/authentication.key \
  -c ./keys/authentication.crt \
  -o ./sigout

./sign_batch.sh -i ./transactions.xml -k ./keys/authentication.key -c ./certs/platform-certificate.crt


# สร้าง clean.xml โดยตัด <dsi:Signature> ออก
./strip_signature.sh -i batch.xml -o clean.xml

# หรือให้ได้ canonical form สำหรับคำนวณ Digest ทันที
./strip_signature.sh -i batch.xml --c14n > clean.c14n.xml