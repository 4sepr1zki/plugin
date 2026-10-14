# 🛡️ OJS Security Hardener & Virtual Patch Suite

[![OJS Compatibility](https://img.shields.io/badge/OJS-2.4.x%20%7C%203.0--3.3.x%20%7C%203.4.x+-blue.svg)](https://pkp.sfu.ca/ojs/)
[![Fixes](https://img.shields.io/badge/Mitigates-CVE--2024--7902%20%7C%20CVE--2022--24181%20%7C%20CVE--2026--76572%20%7C%20CVE--2026--19906-red.svg)](https://nvd.nist.gov/)
[![License](https://img.shields.io/badge/License-GPLv3-green.svg)](LICENSE)

**OjsSecurityHardener** adalah plugin *virtual security patch* dan hardening murni untuk Open Journal Systems (OJS). Didesain khusus untuk memitigasi kerentanan keamanan kritis (CVE) pada core OJS tanpa perlu melakukan modifikasi file core (*no core modifications*).

---

## 🔒 Fitur Keamanan & Mitigasi CVE

### 1. Anti Open-Redirect (CVE-2024-7902 / CVE-2024-46326)
* **Target Endpoint**: `/login/signOut?source=` dan `/login/signIn?source=`.
* **Mekanisme**: Memvalidasi URL tujuan redirect via hook `Request::redirect`:
  - Mengizinkan relative path bersih yang berawalan satu slash (`/index`, `/issue`).
  - Menolak dan me-reset trik subdomain (`.evil.com`), trik backslash (`/\evil`, `//evil`), serta encoding bypass (`%2F`, `%5C`).
  - Memastikan redirect absolut hanya mengarah ke host server sah (`base_url` dan host domain vhost).
  - Mengarahkan request mencurigakan kembali ke root homepage (`/`).

### 2. Anti Host Header Injection & X-Forwarded-Host XSS (CVE-2022-24181)
* **Target Header**: HTTP `Host` dan `X-Forwarded-Host`.
* **Mekanisme**: Mencegat resolusi domain server via hook `Request::getServerHost`:
  - Membatasi format hostname hanya boleh sesuai standar RFC (alfanumerik, titik, strip, dan port).
  - Menolak dan me-reset header yang disusupi payload script/HTML (`<script>`, quotes `"`, `'`) ke nama host kanonikal resmi server.
  - Mencegah password reset link poisoning dan reflected XSS pada canonical link.
  - **Zero False Positive**: Hanya memeriksa string HTTP Header Host, tidak menyentuh konten/naskah artikel.

### 3. Anti XML External Entity / XXE Injection (CVE-2026-76572 & CVE-2024-56525)
* **Target**: Parser XML/XSLT OJS (`XSLTransformer`, User XML Plugin, dan libxml).
* **Mekanisme**: Mematikan parser entitas eksternal (`libxml_disable_entity_loader(true)`) sejak inisialisasi boot plugin untuk mencegah penyerang mengeksploitasi parser XML guna membaca file internal server atau privilege escalation ke Super Admin.

### 4. Strong Cryptographic API Token Generator (CVE-2026-19906)
* **Target**: Generator token REST API user/profile.
* **Mekanisme**: Mengganti entropy generator lama yang berbasis waktu/timestamp dengan CSPRNG `random_bytes(32)` yang aman dari brute-force.

### 5. Security Response Headers
* Menyuntikkan header keamanan HTTP standar:
  - `X-Content-Type-Options: nosniff`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`

---

## 🖥️ Kompatibilitas Versi OJS

Plugin ini menggunakan **Universal Hybrid Architecture**:
* **OJS 2.4.x & OJS 3.0.x - 3.3.x**: Menggunakan legacy loader `OjsSecurityHardenerPlugin.inc.php` (`HookRegistry`).
* **OJS 3.4.x+**: Menggunakan modern namespaced driver `OjsSecurityHardenerPlugin.php` (`APP\plugins\generic\ojsSecurityHardener`).

---

## 🚀 Panduan Instalasi

### Metode 1: Upload via Dashboard OJS
1. Download file arsip rilis: **`ojsSecurityHardener-v1.0.0.tar.gz`**.
2. Login ke OJS sebagai **Administrator** / **Journal Manager**.
3. Masuk ke menu **Settings** > **Website** > **Plugins** > **Installed Plugins**.
4. Klik tombol **Upload A New Plugin**.
5. Unggah file `ojsSecurityHardener-v1.0.0.tar.gz` lalu klik **Save**.
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
3. Sesuaikan kepemilikan folder webserver (misal `www:www` atau `apache:apache`):
   ```bash
   chown -R www:www ojsSecurityHardener/
   ```
4. Aktifkan plugin melalui dashboard OJS.

---

## 📄 Lisensi
Didistribusikan di bawah lisensi [GNU General Public License v3.0](LICENSE).
