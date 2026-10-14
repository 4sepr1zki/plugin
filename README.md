# 🛡️ OJS Security Hardener & Virtual Patch Suite

[![OJS Compatibility](https://img.shields.io/badge/OJS-2.4.x%20%7C%203.0--3.3.x%20%7C%203.4.x+-blue.svg)](https://pkp.sfu.ca/ojs/)
[![Mitigates](https://img.shields.io/badge/Mitigates-CVE--2024--56525%20%7C%20CVE--2024--7902%20%7C%20CVE--2022--24181%20%7C%20CVE--2026--76572%20%7C%20CVE--2026--19906-red.svg)](https://nvd.nist.gov/)
[![License](https://img.shields.io/badge/License-GPLv3-green.svg)](LICENSE)

**OjsSecurityHardener** adalah plugin *virtual security patch* dan hardening komprehensif untuk platform Open Journal Systems (OJS). Didesain khusus untuk menutup celah keamanan kritis (CVE) pada core OJS dan menangkal eksploitasi sindikat parasite SEO / judi online tanpa perlu melakukan modifikasi file core (*no core file modifications*).

---

## 🔒 Fitur Keamanan & Mitigasi CVE

### 1. Anti Privilege Escalation & Arbitrary File Read (CVE-2024-56525 & CVE-2026-76572)
* **Kategori**: XML External Entity (XXE) Injection pada `User XML Plugin` dan `XSLTransformer`.
* **Dampak Asli**: Penyerang berstatus Editor dapat mengunggah file XML manipulatif untuk membuat akun **Super Administrator** baru atau membaca file internal server (seperti `/etc/passwd` dan `config.inc.php`).
* **Mekanisme Patch**: Mematikan parser entitas eksternal libxml PHP (`libxml_disable_entity_loader(true)`) secara global sejak inisialisasi boot plugin.

### 2. Anti Open-Redirect & SEO Parasite Abuse (CVE-2024-7902 & CVE-2024-46326)
* **Kategori**: Unvalidated URL Redirection pada `/login/signOut?source=` dan `/login/signIn?source=`.
* **Dampak Asli**: Sindikat judi online atau penyerang phising memanipulasi parameter redirect untuk menyebarkan link spam atau mencuri kredensial akun akademik.
* **Mekanisme Patch**: Mencegat hook `Request::redirect`:
  - Mengizinkan relative path bersih yang diawali satu slash (`/index`, `/issue`).
  - Menolak dan me-reset trik subdomain (`.evil.com`), trik backslash (`/\evil`, `//evil`), serta encoding bypass (`%2F`, `%5C`).
  - Memastikan redirect absolut hanya mengarah ke host server sah (`base_url` dan host domain vhost).
  - Mengarahkan request mencurigakan kembali ke root homepage (`/`).

### 3. Anti Host Header Injection & Password Reset Poisoning (CVE-2022-24181)
* **Kategori**: Reflected XSS & Host Poisoning via HTTP Header `Host` / `X-Forwarded-Host`.
* **Dampak Asli**: Penyerang menyuntikkan script atau fake host ke header permintaan sehingga link reset password atau tag canonical mengarah ke server penyerang.
* **Mekanisme Patch**: Mencegat hook `Request::getServerHost`:
  - Membatasi hostname hanya boleh mematuhi standar RFC (alfanumerik, titik, strip, dan port).
  - Menolak dan me-reset host yang disusupi tag script atau tanda petik (`<script>`, `"`, `'`) ke nama domain kanonikal resmi server (`SERVER_NAME` / `base_url`).
  - **Zero False Positive**: Hanya memeriksa HTTP Header Host, tidak menyentuh konten/naskah artikel sama sekali.

### 4. Strong Cryptographic API Token Generator (CVE-2026-19906)
* **Kategori**: Low Entropy API Key Generation.
* **Dampak Asli**: Pembuatan token REST API menggunakan entropi lemah berbasis timestamp (`sha1(time())`) sehingga rentan brute-force.
* **Mekanisme Patch**: Mencegat form API profile dan menginjeksi token acak aman berbasis CSPRNG `random_bytes(32)`.

### 5. Security Response Headers
* Menyuntikkan header keamanan HTTP standar untuk mencegah MIME sniffing dan clickjacking:
  - `X-Content-Type-Options: nosniff`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`

---

## ⚖️ Analisis Kelebihan & Kekurangan (Pros & Cons)

Untuk bahan evaluasi teknis, audit, dan presentasi arsitektur keamanan:

### ✅ Kelebihan (Pros)
1. **Zero Core Modifications**:
   Tidak ada satu baris pun file bawaan OJS yang diubah. Sangat aman saat admin sewaktu-waktu ingin melakukan pembaruan berkas aplikasi.
2. **Universal Multi-Version Compatibility**:
   Mendukung OJS mulai dari seri lama (OJS 2.4.x, 3.0.x s/d 3.3.x) hingga arsitektur modern PSR-4 namespaced (OJS 3.4.x+) melalui dynamic wrapper `index.php`.
3. **Zero False Positives pada Artikel Ilmiah**:
   Filter keamanan difokuskan pada protokol HTTP (header host, parameter redirect, parser XML), bukan pada teks artikel. Penulis paper bebas menggunakan istilah seperti "slot", simbol matematika, dan tanda petik tanpa takut ditolak sistem.
4. **Instant Rollback / Toggle**:
   Jika sewaktu-waktu ingin dinonaktifkan, cukup matikan plugin via dashboard OJS tanpa meninggalkan efek samping pada database.
5. **Performa Sangat Ringan**:
   Pengecekan dilakukan secara in-memory melalui sistem Hook native OJS tanpa query database berulang atau regular expression yang membebani CPU.

### ⚠️ Kekurangan & Keterbatasan (Cons)
1. **Ketergantungan pada State Plugin**:
   Proteksi hanya aktif jika plugin berstatus **Enabled** di database (`plugin_settings`). Jika cache OJS corrupt atau tabel setting ter-reset, proteksi bisa non-aktif sementara sampai cache dibersihkan.
2. **Tidak Menutup Celah di Aset Statis Non-PHP**:
   Eksploitasi URL pada file statis client-side (seperti `pdfJsViewer/pdf.js/web/viewer.html` yang di-serve langsung oleh web server) tidak melewati lifecycle PHP OJS. Oleh karena itu, proteksi Nginx (seperti aturan HTTP 410) tetap wajib dipasang berdampingan.
3. **Bukan Pengganti Patch Resmi Jangka Panjang**:
   Meskipun memitigasi CVE secara efektif di pintu masuk aplikasi, virtual patching tetaplah langkah mitigasi pertahanan darurat (*defense-in-depth*). Mengupgrade OJS ke versi LTS terbaru yang sudah dipatch resmi oleh PKP (misal OJS 3.3.0.23+) tetap menjadi rekomendasi jangka panjang terbaik.

---

## 🖥️ Kompatibilitas Versi OJS

| Rumpun Versi | Driver yang Digunakan | Mekanisme Hook |
| :--- | :--- | :--- |
| **OJS 2.4.x - 3.3.x** | `OjsSecurityHardenerPlugin.inc.php` | `HookRegistry::register()` |
| **OJS 3.4.x+** | `OjsSecurityHardenerPlugin.php` | `\PKP\plugins\Hook::add()` |

---

## 🚀 Panduan Instalasi

### Metode 1: Upload via Dashboard OJS (GUI)
1. Download file arsip rilis: **`ojsSecurityHardener-v1.0.0.tar.gz`**.
2. Login ke OJS sebagai **Administrator** / **Journal Manager**.
3. Buka menu **Settings** > **Website** > **Plugins** > **Installed Plugins**.
4. Klik tombol **Upload A New Plugin** di pojok kanan atas.
5. Pilih file `ojsSecurityHardener-v1.0.0.tar.gz` lalu klik **Save**.
6. Pada daftar Generic Plugins, cari **OJS Security Hardener & Virtual Patch** lalu centang **Enable**.

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

## 📄 Lisensi
Didistribusikan di bawah lisensi [GNU General Public License v3.0](LICENSE).
