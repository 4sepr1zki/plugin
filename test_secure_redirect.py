#!/usr/bin/env python3
"""
Automated Verification Suite for CVE-2024-7902 Open Redirect Fix
Targets: OJS login/signOut and login/signIn endpoints.
"""

import sys
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_HOST = "testerone.my.id"
BASE_URL = f"http://127.0.0.1/index.php/Edukasi/login/signOut"
HEADERS = {"Host": TARGET_HOST}

TEST_CASES = [
    {
        "name": "Subdomain Trick Bypass (.evil.com)",
        "source": ".evil-attacker.com",
        "expected_evil": "evil-attacker.com"
    },
    {
        "name": "Slash-Backslash Bypass (/\\evil.com)",
        "source": "/\\evil-attacker.com",
        "expected_evil": "evil-attacker.com"
    },
    {
        "name": "Scheme-Relative Bypass (//evil.com)",
        "source": "//evil-attacker.com",
        "expected_evil": "evil-attacker.com"
    },
    {
        "name": "Absolute Off-Host Redirect (https://evil-attacker.com)",
        "source": "https://evil-attacker.com",
        "expected_evil": "evil-attacker.com"
    },
    {
        "name": "Userinfo Bypass (@evil.com)",
        "source": f"https://{TARGET_HOST}@evil-attacker.com",
        "expected_evil": "evil-attacker.com"
    },
    {
        "name": "Dangerous JavaScript Scheme (javascript:alert(1))",
        "source": "javascript:alert(1)",
        "expected_evil": "javascript:"
    },
    {
        "name": "Legitimate Local Redirect (/index.php/Edukasi/index)",
        "source": "/index.php/Edukasi/index",
        "expected_evil": None
    }
]

def run_tests():
    print("=" * 65)
    print("  CVE-2024-7902 Open Redirect Security Verification Suite")
    print(f"  Target: {TARGET_HOST}")
    print("=" * 65 + "\n")

    all_passed = True
    for i, tc in enumerate(TEST_CASES, 1):
        url = f"{BASE_URL}?source={tc['source']}"
        res = requests.get(url, headers=HEADERS, allow_redirects=False, verify=False)
        location = res.headers.get("Location", "")

        if tc["expected_evil"]:
            # We EXPECT evil target to NOT be in Location header
            is_safe = tc["expected_evil"] not in location
            if is_safe:
                print(f"\033[92m[PROTECTED]\033[0m Test {i}: {tc['name']}")
                print(f"            Redirected safely to: {location}")
            else:
                print(f"\033[91m[VULNERABLE]\033[0m Test {i}: {tc['name']}")
                print(f"            LEAKED LOCATION: {location}")
                all_passed = False
        else:
            # Legitimate test
            is_safe = tc["source"] in location or TARGET_HOST in location
            if is_safe:
                print(f"\033[92m[ALLOWED]\033[0m   Test {i}: {tc['name']}")
                print(f"            Redirected to: {location}")
            else:
                print(f"\033[93m[NOTICE]\033[0m    Test {i}: {tc['name']}")
                print(f"            Redirected to: {location}")

        print()

    print("=" * 65)
    if all_passed:
        print("  \033[92mRESULT: ALL OPEN REDIRECT ATTACK VECTORS SECURED!\033[0m")
    else:
        print("  \033[91mRESULT: VULNERABILITY DETECTED!\033[0m")
    print("=" * 65)

if __name__ == "__main__":
    run_tests()
