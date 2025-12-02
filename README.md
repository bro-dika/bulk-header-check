# Bulk Header Check

Bulk Header Check adalah skrip Python untuk melakukan pengecekan keamanan header HTTP secara massal. Skrip ini dapat mengecek header keamanan penting (ada/tidak), serta menganalisis versi server, dan menghasilkan laporan dalam format PDF dan JSON.

---

## **Fitur**
- Memeriksa keberadaan **header keamanan wajib**:
  - Content-Security-Policy
  - Strict-Transport-Security
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
- Analisis versi server (Apache, Nginx, IIS, Cloudflare)
- Menangani HTTP 415 (Unsupported Media Type)
- Menyimpan hasil pemeriksaan ke **PDF** dan **JSON**
- Memproses daftar domain dalam format teks (`.txt`)

---

## **Instalasi**

1. Clone atau download skrip:

```bash
git clone <repo-url>
cd <repo-folder>
````

2. Buat virtual environment (opsional tapi disarankan):

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

3. Install dependensi:

```bash
pip install -r requirements.txt
```

---

## **Penggunaan**

1. Siapkan file `domains.txt` berisi daftar domain atau URL, satu per baris:

```
example.com
https://example2.com
```

2. Jalankan skrip:

```bash
python bulk_header_check.py domains.txt
```

3. Skrip akan menampilkan status header keamanan, versi server, dan missing header di terminal.
4. Hasil scan akan otomatis disimpan ke:

   * `report.pdf` → Laporan PDF
   * `report.json` → Hasil JSON

---

## **Contoh Output Terminal**

```
[i] Checking: https://example.com
[+] Status Code : 200
[+] Server      : Apache/2.4.41
[+] Risk        : Apache 2.4.41 — OK
[+] Missing     : X-Frame-Options, Permissions-Policy
--------------------------------------------------
```

---

## **Struktur File**

* `bulk_header_check.py` → Skrip utama
* `domains.txt` → File input daftar domain
* `report.pdf` → Output PDF
* `report.json` → Output JSON

---

## **Requirements**

* Python 3.x
* requests
* reportlab

