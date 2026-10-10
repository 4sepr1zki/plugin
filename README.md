# 🛡️ SecureRedirect Virtual Patch Plugin for OJS (CVE-2024-7902)

[![OJS Compatibility](https://img.shields.io/badge/OJS-3.2.x%20%7C%203.3.x%20%7C%203.4.x-blue.svg)](https://pkp.sfu.ca/ojs/)
[![Vulnerability](https://img.shields.io/badge/Fixes-CVE--2024--7902%20(Open%20Redirect)-red.svg)](https://nvd.nist.gov/vuln/detail/CVE-2024-7902)
[![License](https://img.shields.io/badge/License-GPLv3-green.svg)](LICENSE)

**SecureRedirect** adalah plugin *virtual patch* keamanan untuk Open Journal Systems (OJS) yang menutup celah kritis **Open Redirect (CVE-2024-7902)** pada endpoint `/login/signOut?source=` dan `/login/signIn?source=` tanpa perlu melakukan upgrade versi OJS secara besar-besaran maupun mengotori core code (*no core modification*).

---

## 📌 Penjelasan Kerentanan (CVE-2024-7902)

Pada OJS versi 3.3.x dan sebelumnya, parameter `source` pada proses *sign out* atau *sign in* tidak divalidasi dengan ketat sebelum melakukan redirect HTTP 302:
* Penyerang dapat membuat link phising seperti:
  ```text
  https://journal-victim.com/index.php/journal/login/signOut?source=.attacker.com
  ```
  yang akan me-redirect browser korban secara otomatis ke `https://attacker.com` atau subdomain phising.
* Celah ini sering dimanfaatkan oleh penyerang untuk mencuri kredensial akun reviewer/editor atau menyebarkan malware dengan mencatut nama domain jurnal resmi.

---

## 🔒 Solusi & Strategi Proteksi

Plugin ini mencegat pemanggilan fungsi `Request::redirect` secara terpusat melalui sistem **Hook resmi OJS**:
1. **Host Verification**: Memastikan URL tujuan redirect hanya mengarah ke host server sendiri (`base_url` dan domain context jurnal yang sah).
2. **Subdomain Bypass Filter**: Memblokir manipulasi dot-subdomain seperti `?source=.evil.com`.
3. **Slash-Backslash Normalization**: Memblokir trik `?source=/\evil.com`, `//evil.com`, dan URL-encoded bypass (`%2F`, `%5C`).
4. **Dangerous Scheme Blocker**: Memblokir skema berbahaya seperti `javascript:`, `data:`, dan `vbscript:`.
5. **Userinfo Blocker**: Memblokir karakter `@` dalam path (`https://domain@evil.com`).
6. **Automatic Fallback**: Jika ada request yang mencurigakan, tujuan redirect otomatis di-reset ke root homepage (`/`).

---

## 🖥️ Kompatibilitas Versi OJS

Plugin ini menggunakan **Universal Hybrid Architecture**:
* **OJS 3.2.x & OJS 3.3.x**: Menggunakan legacy driver `SecureRedirectPlugin.inc.php` berbasis `HookRegistry`.
* **OJS 3.4.x & OJS 3.5.x**: Menggunakan modern namespaced driver `SecureRedirectPlugin.php` (`APP\plugins\generic\secureRedirect`).

---

## 🚀 Cara Pemasangan (Installation Guide)

### Metode 1: Upload via Dashboard OJS (Paling Mudah)
1. Login sebagai **Administrator** atau **Journal Manager**.
2. Masuk ke menu **Settings** > **Website** > tab **Plugins** > **Installed Plugins**.
3. Klik tombol **Upload A New Plugin** di pojok kanan atas.
4. Upload file: **`secureRedirect-v1.0.0.tar.gz`**.
5. Klik **Save**.
6. Pada daftar plugin Generic, cari **SecureRedirect Hotfix (CVE-2024-7902)** lalu centang **Enable**.

---

### Metode 2: Manual via Terminal / File Manager (cPanel / aaPanel / SSH)
1. Ekstrak file tar.gz ke direktori generic plugin OJS:
   ```bash
   tar -xzvf secureRedirect-v1.0.0.tar.gz -C /path-ke-ojs/plugins/generic/
   ```
2. Pastikan permission folder disesuaikan:
   ```bash
   chown -R www:www /path-ke-ojs/plugins/generic/secureRedirect
   chmod -R 755 /path-ke-ojs/plugins/generic/secureRedirect
   ```
3. Aktifkan plugin melalui **Website Settings** > **Plugins** di Dashboard OJS.

---

## 🧪 Verifikasi & Pengujian Keamanan

Repository ini menyertakan script tester otomatis [`test_secure_redirect.py`](test_secure_redirect.py) untuk memverifikasi proteksi dari berbagai vektor serangan:

```bash
python3 test_secure_redirect.py
```

### Vektor yang Diuji:
1. **Subdomain Trick** (`?source=.evil.com`) -> *Aman (Di-reset ke home)*
2. **Slash-Backslash Bypass** (`?source=/\evil.com`) -> *Aman (Di-reset ke home)*
3. **Scheme-Relative Bypass** (`?source=//evil.com`) -> *Aman (Di-reset ke home)*
4. **Absolute Off-Host Redirect** (`?source=https://evil.com`) -> *Aman (Di-reset ke home)*
5. **Userinfo Trick** (`?source=https://domain@evil.com`) -> *Aman (Di-reset ke home)*
6. **Dangerous JavaScript Scheme** (`?source=javascript:...`) -> *Aman (Di-reset ke home)*
7. **Legitimate Local Redirect** (`?source=/index.php/...`) -> *Diizinkan Normal*

---

## 📁 Struktur File Repository

```text
├── SecureRedirectPlugin.inc.php    # Driver untuk OJS 3.2.x & 3.3.x
├── SecureRedirectPlugin.php        # Driver untuk OJS 3.4.x & 3.5.x
├── index.php                       # Universal Smart Loader
├── version.xml                     # Metadata Plugin
├── locale/                         # Multi-bahasa (id_ID & en_US)
│   ├── id_ID/locale.po
│   └── en_US/locale.po
├── secureRedirect-v1.0.0.tar.gz    # Arsip siap upload via OJS UI
├── secureRedirect-v1.0.0.zip       # Arsip ZIP
├── test_secure_redirect.py         # Script automated security tester
└── README.md                       # Dokumentasi lengkap
```

---

## 📄 Lisensi
Didistribusikan di bawah lisensi **GNU General Public License v3.0 (GPLv3)**.
