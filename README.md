# 🛡️ OJS Security Hardener & Virtual Patch Suite

[![OJS Compatibility](https://img.shields.io/badge/OJS-2.4.x%20%7C%203.0--3.3.x%20%7C%203.4.x+-blue.svg)](https://pkp.sfu.ca/ojs/)
[![Fixes](https://img.shields.io/badge/Mitigates-CVE--2024--7902%20%7C%20CVE--2026--76572%20%7C%20CVE--2026--19906-red.svg)](https://nvd.nist.gov/)
[![License](https://img.shields.io/badge/License-GPLv3-green.svg)](LICENSE)

**OjsSecurityHardener** adalah plugin *virtual security patch* dan hardening menyeluruh untuk Open Journal Systems (OJS). Didesain untuk memitigasi kerentanan keamanan kritis dan menangkal serangan sindikat parasite SEO / judi online tanpa perlu merombak core code OJS (*no core modifications*).

---

## 🔒 Fitur Keamanan & Mitigasi CVE

### 1. Anti Open-Redirect (CVE-2024-7902)
* **Target Endpoint**: `/login/signOut?source=` dan `/login/signIn?source=`.
* **Mekanisme**: Memvalidasi URL tujuan redirect via hook `Request::redirect`:
  - Mengizinkan relative path bersih yang berawalan satu slash (`/index`, `/issue`).
  - Menolak dan me-reset trik subdomain (`.evil.com`), trik backslash (`/\evil`, `//evil`), serta encoding bypass (`%2F`, `%5C`).
  - Memastikan redirect absolut hanya mengarah ke host server sah (`base_url` dan host domain vhost).
  - Mengarahkan request mencurigakan kembali ke root homepage (`/`).

### 2. Anti XML External Entity / XXE Injection (CVE-2026-76572)
* **Target**: Parser XML/XSLT OJS (libxml).
* **Mekanisme**: Mematikan parser entitas eksternal (`libxml_disable_entity_loader(true)`) sejak inisialisasi boot plugin untuk mencegah attacker membaca file sensitif internal server (seperti `/etc/passwd` atau `config.inc.php`).

### 3. Strong Cryptographic API Token Generator (CVE-2026-19906)
* **Target**: Generator token REST API user/profile.
* **Mekanisme**: Mengganti entropy generator lama yang berbasis waktu/timestamp dengan CSPRNG `random_bytes(32)` yang aman dari brute-force.

### 4. Anti-Spam Registrasi & Parasite Bio Judol
* **Target**: Form registrasi user OJS.
* **Mekanisme**: Memfilter field input (`biography`, `affiliation`, `signature`, `homepage`, `orcid`) terhadap kata kunci sindikat judi online (seperti `slot`, `gacor`, `judi`, `sbobet`, `depo`, `wd`, linktree spam, dll). Form registrasi otomatis ditolak dengan pesan error jika mengandung kata kunci tersebut.

### 5. Security Response Headers
* Menyuntikkan header keamanan HTTP:
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
