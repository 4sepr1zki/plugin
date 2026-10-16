# 🛡️ OJS Security Hardener & Monitoring Dashboard Suite

[![OJS Compatibility](https://img.shields.io/badge/OJS-2.4.x%20%7C%203.0--3.3.x%20%7C%203.4.x+-blue.svg)](https://pkp.sfu.ca/ojs/)
[![Mitigates](https://img.shields.io/badge/Mitigates-CVE--2024--56525%20%7C%20CVE--2024--7902%20%7C%20CVE--2022--24181%20%7C%20CVE--2026--76572%20%7C%20CVE--2026--19906-red.svg)](https://nvd.nist.gov/)
[![License](https://img.shields.io/badge/License-GPLv3-green.svg)](LICENSE)

**OjsSecurityHardener** adalah suite keamanan dan hardening kelas enterprise untuk Open Journal Systems (OJS). Menggabungkan **Virtual Security Patches** untuk menutup celah CVE kritis, **Anti Brute-Force Protection**, **Login UI Notification**, dan **Secret Web Monitoring Dashboard** tanpa perlu menyentuh core code OJS (*zero core file modifications*).

---

## 🔒 Fitur Keamanan & Mitigasi CVE

### 1. Anti Privilege Escalation & Arbitrary File Read (CVE-2024-56525 & CVE-2026-76572)
* **Kategori**: XML External Entity (XXE) Injection pada `User XML Plugin` dan `XSLTransformer`.
* **Mekanisme**: Mematikan parser entitas eksternal libxml PHP (`libxml_disable_entity_loader(true)`) sejak inisialisasi boot plugin.

### 2. Anti Open-Redirect & SEO Parasite Abuse (CVE-2024-7902 & CVE-2024-46326)
* **Kategori**: Unvalidated URL Redirection pada `/login/signOut?source=` dan `/login/signIn?source=`.
* **Mekanisme**: Mencegat hook `Request::redirect`:
  - Menolak trik subdomain (`.evil.com`), trik backslash (`/\evil`, `//evil`), dan skema berbahaya (`javascript:`).
  - Me-reset request manipulatif kembali ke root homepage (`/`).

### 3. Anti Host Header Injection & Password Reset Poisoning (CVE-2022-24181)
* **Kategori**: Reflected XSS & Host Poisoning via HTTP Header `Host` / `X-Forwarded-Host`.
* **Mekanisme**: Mencegat hook `Request::getServerHost` dan membatasi string hostname strictly sesuai standar RFC hostname.

### 4. Strong Cryptographic API Token Generator (CVE-2026-19906)
* **Kategori**: Low Entropy API Key Generation.
* **Mekanisme**: Mengganti entropy generator lama yang berbasis waktu/timestamp dengan CSPRNG `random_bytes(32)`.

### 5. 🛡️ Anti Brute-Force & Login Throttling (Hybrid IP + Account Lockout)
* **Pencegahan False Positive**: Menggunakan kunci pelacakan kombinasi `md5(IP + Username)`. Jika satu rekan kerja salah password di WiFi kantor, **rekan kerja lain di WiFi yang sama TIDAK AKAN TERKUNCI**.
* **Threshold**: Maksimal 5x percobaan gagal dalam 15 menit.
* **Lockout Action**: Jika tembus 5x salah, akun tersebut dikunci otomatis selama **5 menit** (mengembalikan respon `HTTP 429 Too Many Requests` yang ramah).

### 6. 🎨 Login UI Security Notice Banner
* Otomatis menyuntikkan banner informasi keamanan di bawah form login OJS untuk memberi peringatan ramah kepada pengguna dan efek gentar bagi penyerang.

### 7. 📊 Secret Web Monitoring Dashboard
* **Akses Rahasia**: Cukup buka URL jurnal dengan parameter rahasia:
  `https://journal.domain.com/?sec_dash=1` (atau `?sec_admin=1`)
* **Keamanan Akses**: Dilindungi Master Security Password (Default: `ArimbiSec2026!`).
* **Fitur Dashboard**:
  - Live Threat Counter (Total serangan, Brute-force tertahan, Redirect diblokir).
  - Active Lockouts Table dengan tombol **"Quick Unlock"** instan.
  - Real-time Security Audit Log Viewer (30 insiden terakhir).
  - Status Badge seluruh virtual patch CVE.

### 8. 📝 Dedicated Audit Logger (`data/security_audit.log`)
* Setiap serangan dan percobaan login gagal otomatis dicatat lengkap dengan timestamp, IP asal, tipe ancaman, dan aksi yang diambil.

---

## 🚀 Panduan Instalasi

### Metode 1: Upload via Dashboard OJS (GUI)
1. Download file arsip rilis: **`ojsSecurityHardener-v1.0.0.tar.gz`**.
2. Login ke OJS sebagai **Administrator** / **Journal Manager**.
3. Buka menu **Settings** > **Website** > **Plugins** > **Installed Plugins**.
4. Klik tombol **Upload A New Plugin** di pojok kanan atas.
5. Pilih file `ojsSecurityHardener-v1.0.0.tar.gz` lalu klik **Save**.
6. Pada daftar Generic Plugins, cari **OJS Security Hardener & Monitoring Dashboard** lalu centang **Enable**.

### Metode 2: Manual via Server / CLI
1. Masuk ke direktori plugin generic OJS:
   ```bash
   cd /path-ke-ojs/plugins/generic/
   ```
2. Ekstrak arsip:
   ```bash
   tar -xzvf ojsSecurityHardener-v1.0.0.tar.gz
   ```
3. Sesuaikan kepemilikan user web server:
   ```bash
   chown -R www:www ojsSecurityHardener/
   ```
4. Aktifkan plugin melalui dashboard OJS.

---

## 🔑 Mengakses Dashboard Monitoring
1. Buka browser dan ketik: `https://domain-jurnal-anda.com/?sec_dash=1`
2. Masukkan master key: `ArimbiSec2026!`
3. Anda dapat memantau log ancaman secara live dan membuka kunci akun yang terkunci hanya dengan satu klik!

---

## 📄 Lisensi
Didistribusikan di bawah lisensi [GNU General Public License v3.0](LICENSE).
