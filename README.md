# 🛡️ OJS Security Hardener & Monitoring Dashboard Suite

[![OJS Compatibility](https://img.shields.io/badge/OJS-2.4.x%20%7C%203.0--3.3.x%20%7C%203.4.x+-blue.svg)](https://pkp.sfu.ca/ojs/)
[![Mitigates](https://img.shields.io/badge/Mitigates-CVE--2024--56525%20%7C%20CVE--2024--7902%20%7C%20CVE--2022--24181%20%7C%20CVE--2026--76572%20%7C%20CVE--2026--19906-red.svg)](https://nvd.nist.gov/)
[![License](https://img.shields.io/badge/License-GPLv3-green.svg)](LICENSE)

**OjsSecurityHardener** adalah suite keamanan dan hardening kelas enterprise untuk Open Journal Systems (OJS). Menggabungkan **Virtual Security Patches** untuk menutup celah CVE kritis, **Anti Brute-Force Protection**, **Anti IP Spoofing Validation**, **Concurrency Locking (Atomic Flocks)**, **Login UI Notification**, dan **Secret Web Monitoring Dashboard** tanpa perlu menyentuh core code OJS (*zero core file modifications*).

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
* **Anti IP Spoofing**: IP klien diverifikasi secara ketat. Header `X-Forwarded-For` dan proxy hanya dipercaya bila setting `trust_x_forwarded_for` di OJS aktif dan berasal dari proxy terpercaya.
* **Pencegahan False Positive**: Menggunakan kunci pelacakan kombinasi `md5(IP + Username)` serta memeriksa status otentikasi aktual saat shutdown. Jika login sukses, riwayat kesalahan langsung di-reset otomatis. Rekan kerja di WiFi kantor yang sama **TIDAK AKAN IKUT TERKUNCI**.
* **Threshold**: Maksimal 5x percobaan gagal dalam 15 menit.
* **Lockout Action**: Jika tembus 5x salah, akun tersebut dikunci otomatis selama **5 menit** (mengembalikan respon `HTTP 429 Too Many Requests`).

### 6. 🎨 Login UI Security Notice Banner
* Otomatis menyuntikkan banner informasi keamanan di form login OJS untuk memberi edukasi ramah kepada pengguna dan peringatan bagi penyerang brute force.

### 7. 📊 Secret Web Monitoring Dashboard
* **Akses Rahasia**: Cukup buka URL jurnal dengan parameter rahasia:
  `https://journal.domain.com/?sec_dash=1` (atau `?sec_admin=1`)
* **Keamanan Akses Kredensial Unik**: Tidak menggunakan default password statis publik. Password acak berkekuatan tinggi di-generate secara otomatis saat pertama kali diinstalasi dan disimpan aman di `config.json` privat atau tabel database `plugin_settings`.
* **Anti Brute-Force Dashboard**: Dilengkapi rate limiting tersendiri (maksimal 5x salah password dashboard -> pemblokiran akses selama 10 menit).
* **Fitur Dashboard**:
  - Live Threat Counter (Total serangan, Brute-force tertahan, Redirect diblokir).
  - Active Lockouts Table dengan tombol **"Quick Unlock"** instan.
  - Real-time Security Audit Log Viewer (30 insiden terakhir).
  - Status Badge seluruh virtual patch CVE.

### 8. 📝 Dedicated Audit Logger & Concurrency Safety
* Setiap operasi baca-tulis file JSON dilindungi **Exclusive Atomic File Locking (`flock()`)** untuk mencegah race condition / korupsi data pada traffic tinggi.
* File log dan data otomatis dilindungi oleh file `.htaccess` (`Require all denied`), `web.config`, dan `index.html` kosong untuk mencegah *Information Disclosure*.

---

## 🚀 Panduan Instalasi

### Metode 1: Upload via Dashboard OJS (GUI)
1. Unduh arsip rilis terbaru dari [GitHub Releases](https://github.com/4sepr1zki/plugin/releases).
2. Login ke OJS sebagai **Administrator** / **Journal Manager**.
3. Buka menu **Settings** > **Website** > **Plugins** > **Installed Plugins**.
4. Klik tombol **Upload A New Plugin** di pojok kanan atas.
5. Upload file arsip plugin lalu klik **Save**.
6. Pada daftar Generic Plugins, cari **OJS Security Hardener & Monitoring Dashboard** lalu centang **Enable**.

### Metode 2: Manual via Server / CLI
1. Masuk ke direktori plugin generic OJS:
   ```bash
   cd /path-ke-ojs/plugins/generic/
   ```
2. Clone repository:
   ```bash
   git clone https://github.com/4sepr1zki/plugin.git ojsSecurityHardener
   ```
3. Sesuaikan kepemilikan user web server:
   ```bash
   chown -R www:www ojsSecurityHardener/
   ```
4. Aktifkan plugin melalui dashboard OJS atau database.

---

## 🔑 Mengakses Dashboard Monitoring
1. Buka browser dan ketik: `https://domain-jurnal-anda.com/?sec_dash=1`
2. Masukkan master key yang digenerate di server (tersimpan di `[files_dir]/security_hardener/config.json` atau tabel `plugin_settings` OJS).
3. Anda dapat memantau log ancaman secara live dan membuka kunci akun yang terkunci hanya dengan satu klik!

---

## 📄 Lisensi
Didistribusikan di bawah lisensi [GNU General Public License v3.0](LICENSE).
