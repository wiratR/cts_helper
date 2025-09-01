# Deny List FlatBuffers Reader (Python)

สคริปต์ Python สำหรับอ่าน **Deny List** ที่จัดเก็บในรูปแบบ **FlatBuffers** พร้อมความสามารถดังนี้:

- อ่านไฟล์ `.bin` ตรง ๆ หรือ `.zip` ที่มี `.bin` ข้างใน
- คลายบีบอัดแบบ `deflate/zlib` อัตโนมัติ
- แสดงรายการ (`--list`), ค้นหาเป็นรายตัว (`--pan`), สรุปสถิติ (`--stats`)
- ส่งออกข้อมูลเป็น **CSV** (`--export-csv`) และ **JSON** (`--export-json`)
- รองรับความแตกต่างของโค้ดที่ `flatc` สร้างหลายเวอร์ชัน (compatible vector getters)
- เลือกปิดคำเตือน `file_identifier` ได้ด้วย `--suppress-id-warn`

> ใช้ได้กับ schema ที่มี namespace `TransCity;` หรือไม่มี namespace ก็ได้ (มี fallback import)

---

## 1) Requirements

- Python 3.8+
- ติดตั้งไลบรารี
  ```bash
  pip install flatbuffers
  ```
- มี **FlatBuffers compiler** (`flatc`) เพื่อ generate Python bindings จากสคีมา
  - macOS: `brew install flatbuffers`
  - Debian/Ubuntu: `sudo apt-get install flatbuffers-compiler`

---

## 2) Generate Python classes จากสคีมา

ไฟล์สคีมาตัวอย่าง (`denyList.fbs`) ที่แนะนำ (หลีกเลี่ยง optional scalar):
```fbs
namespace TransCity;
file_identifier "DNYS";

table DenyList {
  deny_list_entries: [DenyListEntry];
  deny_reasons: [DenyReason];
}

table DenyListEntry {
  surrogate_PAN: string (key);
  deny_reasons_id: [uint8];
  removed: bool = false;   // ใช้ default แทน (optional)
}

table DenyReason {
  id: uint8 (key);
  value: string;
}

root_type DenyList;
```

รันในโฟลเดอร์โปรเจกต์:
```bash
flatc --python denyList.fbs
# (ถ้าใช้ namespace TransCity; จะได้โฟลเดอร์ TransCity/)
# แนะนำให้มี TransCity/__init__.py เพื่อให้ import ได้แน่
```

ตัวอย่างโครงสร้างโฟลเดอร์:
```
denyList/
├─ denyList.fbs
├─ denylist_reader.py
├─ primaryDenyList.bin
└─ TransCity/
   ├─ DenyList.py
   ├─ DenyListEntry.py
   ├─ DenyReason.py
   └─ __init__.py
```

> หากสคีมา **ไม่มี** `namespace TransCity;` โค้ดจะ import ตามไฟล์ที่อยู่รากโปรเจกต์ (fallback)

---

## 3) วิธีใช้งาน CLI

- แสดงรายการทั้งหมด (reasons + entries)
  ```bash
  python denylist_reader.py primaryDenyList.bin --list
  ```

- ตรวจสอบบัตร (surrogate PAN) รายตัว
  ```bash
  python denylist_reader.py primaryDenyList.bin --pan 411111******1111
  ```

- สรุปสถิติ (จำนวนรายการ, นับตาม reason id, จำนวน removed)
  ```bash
  python denylist_reader.py primaryDenyList.bin --stats
  ```

- ส่งออก CSV / JSON
  ```bash
  python denylist_reader.py primaryDenyList.bin --export-csv denylist.csv
  python denylist_reader.py primaryDenyList.bin --export-json denylist.json
  ```

- อ่านจากไฟล์ `.zip` ที่ภายในมี `.bin`
  ```bash
  python denylist_reader.py "primaryDenyList (1).zip" --list
  ```

- ปิดคำเตือนเรื่อง `file_identifier`
  ```bash
  python denylist_reader.py primaryDenyList.bin --list --suppress-id-warn
  ```

---

## 4) หมายเหตุสำคัญ

- ถ้าเห็นคำเตือน `Buffer file_identifier mismatch ...` แปลว่า buffer ไม่ได้ฝัง `file_identifier "DNYS"` ตาม schema (ไม่กระทบการอ่าน)  
  - ปิดได้ด้วย `--suppress-id-warn`
  - หรือแก้สคีมา/ regenerate ให้สอดคล้องกัน

- สำหรับชื่อฟิลด์ `surrogate_PAN` หาก `flatc` เตือนว่าไม่ใช่ snake_case เป็นเพียง warning (คอมไพล์ได้ปกติ)  
  ถ้าจะเปลี่ยนเป็น `surrogate_pan` เมธอดใน Python จะเป็น `SurrogatePan()` (โค้ดรองรับทั้งสองชื่ออยู่แล้ว)

---

## 5) Troubleshooting

- **ModuleNotFoundError: TransCity**  
  รัน `flatc --python denyList.fbs` ให้ได้แพ็กเกจ `TransCity/` และเพิ่ม `TransCity/__init__.py` หรือใช้ fallback (ไม่มี namespace)

- **error: user define attributes must be declared before use: optional**  
  เวอร์ชัน `flatc` ที่ใช้อาจยังไม่รองรับ `(optional)` สำหรับ scalar → ใช้ `removed: bool = false;` แทน

- **TypeError: ... takes 2 positional arguments but 3 were given**  
  ความต่างของ method signature ที่ `flatc` หลายเวอร์ชันสร้าง → โค้ดนี้รองรับแล้วด้วย `_vec_get()`

---

## 6) License

MIT หรือปรับใช้ตามนโยบายภายในของคุณ



```bash
./get_denylist.sh --curl ./bin/curl --base-url https://api.example.com --id 12345 --token "$TOKEN" --stats
```


ใช้ยังไง (ตัวอย่างเร็ว ๆ)

ขอ token แล้วใช้กับ get_denylist.sh

```bash
TOKEN="$(./cts_login.sh --base-url https://<host> --user <u> --pass '<p>')"
./get_denylist.sh --base-url https://<host> --id <denylistId> --token "$TOKEN" --stats --list
```

อยากได้ JSON ทั้งก้อน (ดู expires_in, refresh_token ฯลฯ):
```bash
./cts_login.sh --base-url https://<host> --user <u> --pass '<p>' --json | jq
```

อยากพิมพ์เป็น export TOKEN=... เพื่อ source เข้ามาใน shell:

```bash
./cts_login.sh --base-url https://<host> --user <u> --pass '<p>' --export-env > .env-token
source .env-token
```
