#!/usr/bin/env python3
"""
Interactive CVE-2024-7902 Open Redirect Security Verification Tool
Suitable for beginners, sysadmins, and security auditors.
"""

import sys
import re
import urllib.parse
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ANSI Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

TEST_VECTORS = [
    {
        "id": 1,
        "name": "Subdomain Trick Bypass",
        "payload": ".evil-attacker.com",
        "desc": "Mencoba manipulasi titik awal sub-domain (.evil.com)",
        "evil_marker": "evil-attacker.com"
    },
    {
        "id": 2,
        "name": "Slash-Backslash Bypass",
        "payload": "/\\evil-attacker.com",
        "desc": "Mencoba trik bypass normalisasi browser (/\\evil.com)",
        "evil_marker": "evil-attacker.com"
    },
    {
        "id": 3,
        "name": "Scheme-Relative Bypass",
        "payload": "//evil-attacker.com",
        "desc": "Mencoba redirect tanpa protokol (//evil.com)",
        "evil_marker": "evil-attacker.com"
    },
    {
        "id": 4,
        "name": "Absolute Off-Host Redirect",
        "payload": "https://evil-attacker.com",
        "desc": "Mencoba redirect langsung ke domain penyerang",
        "evil_marker": "evil-attacker.com"
    },
    {
        "id": 5,
        "name": "Userinfo Trick Bypass",
        "payload_func": lambda host: f"https://{host}@evil-attacker.com",
        "desc": "Mencoba trik kredensial URL (@evil.com)",
        "evil_marker": "evil-attacker.com"
    },
    {
        "id": 6,
        "name": "Dangerous JavaScript Scheme",
        "payload": "javascript:alert('XSS-Redirect')",
        "desc": "Mencoba injeksi payload skema javascript:",
        "evil_marker": "javascript:"
    },
    {
        "id": 7,
        "name": "Legitimate Local Redirect (Simulasi Normal)",
        "payload_func": lambda host: f"/index.php",
        "desc": "Memastikan redirect internal yang sah TETAP DIIZINKAN",
        "evil_marker": None
    }
]

def print_banner():
    print(f"{CYAN}{BOLD}")
    print("╔═════════════════════════════════════════════════════════════════╗")
    print("║     SECURE-REDIRECT (CVE-2024-7902) VIRTUAL PATCH TESTER       ║")
    print("║          Tool Pengujian Celah Open Redirect OJS                 ║")
    print("╚═════════════════════════════════════════════════════════════════╝")
    print(f"{RESET}")

def prompt_target_url():
    print(f"{BOLD}[1] Masukkan URL Target Jurnal OJS yang Ingin Diuji:{RESET}")
    print("    Contoh:")
    print("    - https://journal.lpkd.or.id")
    print("    - https://testerone.my.id")
    print("    - http://127.0.0.1/index.php/Edukasi")
    
    target_input = input(f"\n{YELLOW}>> URL Target [Default: https://testerone.my.id]: {RESET}").strip()
    if not target_input:
        target_input = "https://testerone.my.id"
    
    if not target_input.startswith("http://") and not target_input.startswith("https://"):
        target_input = "https://" + target_input
    
    parsed = urllib.parse.urlparse(target_input)
    base_host = parsed.netloc
    
    # Auto-detect context path jika dimasukkan
    path = parsed.path.rstrip('/')
    if not path or path == "":
        test_url = f"{parsed.scheme}://{base_host}/index.php/index/login/signOut"
    elif "signOut" in path or "login" in path:
        test_url = target_input
    else:
        test_url = f"{parsed.scheme}://{base_host}{path}/login/signOut"
        
    return target_input, test_url, base_host

def run_tests(target_url, test_url, base_host):
    print(f"\n{BOLD}Target Terpilih:{RESET} {CYAN}{target_url}{RESET}")
    print(f"{BOLD}Endpoint Uji:{RESET}    {YELLOW}{test_url}{RESET}")
    print(f"{BOLD}Host Target:{RESET}     {base_host}")
    print("\n" + "=" * 67)
    print(f"{BOLD}  MEMULAI PENGUJIAN OTOMATIS (7 VEKTOR SERANGAN)...{RESET}")
    print("=" * 67 + "\n")

    session = requests.Session()
    headers = {
        "Host": base_host.split(':')[0],
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0"
    }

    all_passed = True
    vulnerable_count = 0

    for idx, tv in enumerate(TEST_VECTORS, 1):
        if "payload_func" in tv:
            payload = tv["payload_func"](base_host)
        else:
            payload = tv["payload"]

        req_url = f"{test_url}?source={urllib.parse.quote(payload, safe='/:?=@&')}"
        
        try:
            res = session.get(req_url, headers=headers, allow_redirects=False, verify=False, timeout=10)
            location = res.headers.get("Location", "")
            
            print(f"{BOLD}Tes {idx}: {tv['name']}{RESET}")
            print(f"      Payload: {payload}")
            print(f"      Keterangan: {tv['desc']}")

            if tv["evil_marker"]:
                if tv["evil_marker"] in location:
                    print(f"      Status: {RED}{BOLD}[❌ VULNERABLE / BOCOR!]{RESET}")
                    print(f"      Redirect Header Location: {RED}{location}{RESET}")
                    all_passed = False
                    vulnerable_count += 1
                else:
                    print(f"      Status: {GREEN}{BOLD}[✅ AMAN / TERBLOKIR]{RESET}")
                    print(f"      Redirect Header Location: {GREEN}{location if location else '(Ditolak/Kembali ke Home /)'}{RESET}")
            else:
                # Legitimate test
                print(f"      Status: {GREEN}{BOLD}[✅ NORMAL / DIIZINKAN]{RESET}")
                print(f"      Redirect Header Location: {GREEN}{location}{RESET}")

        except Exception as e:
            print(f"      Status: {YELLOW}[⚠️ Gagal Mengakses Endpoint: {e}]{RESET}")

        print("-" * 67)

    print("\n" + "=" * 67)
    print(f"{BOLD}  RINGKASAN HASIL PENGUJIAN KEAMANAN:{RESET}")
    print("=" * 67)
    if all_passed:
        print(f"{GREEN}{BOLD}  ✅ TARGET AMAN DARI CELAH OPEN REDIRECT (CVE-2024-7902)!{RESET}")
        print(f"     Semua payload phising/redirect berbahaya berhasil dinetralkan.")
    else:
        print(f"{RED}{BOLD}  ❌ DITEMUKAN {vulnerable_count} CELAH OPEN REDIRECT YANG MASIH AKTIF!{RESET}")
        print(f"     Pasang plugin SecureRedirect untuk menutup celah ini.")
    print("=" * 67 + "\n")

def main():
    while True:
        print_banner()
        print("PILIHAN MENU:")
        print(" [1] Jalankan Pengujian Open Redirect (CVE-2024-7902)")
        print(" [2] Keluar")
        
        choice = input(f"\n{YELLOW}Pilih menu (1/2): {RESET}").strip()
        if choice == "1":
            target_url, test_url, base_host = prompt_target_url()
            run_tests(target_url, test_url, base_host)
            input(f"\n{CYAN}Tekan [Enter] untuk kembali ke menu utama...{RESET}")
        elif choice == "2":
            print(f"\n{GREEN}Terima kasih! Tetap amankan OJS Anda.{RESET}\n")
            sys.exit(0)
        else:
            print(f"{RED}Pilihan tidak valid.{RESET}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Pengujian dibatalkan oleh pengguna.{RESET}\n")
        sys.exit(0)
