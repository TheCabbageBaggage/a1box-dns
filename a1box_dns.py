#!/usr/bin/env python3
"""
a1box_dns — read and write the LAN DNS servers of an A1 WLAN Box (Zyxel DX3301-T0)
whose configuration page A1 removed from the web UI.

The box still implements the settings (LAN Setup page + DAL object `oid=lan`); this
tool talks to the box's own encrypted JSON API, exactly like its web UI does.

It does NOT flash firmware, does NOT touch the WAN configuration, and every write
can be undone with `restore` (you get a timestamped backup before each change).

Usage:
    export A1BOX_HOST=http://192.168.1.1        # optional, this is the default
    export A1BOX_USER=admin                    # optional
    export A1BOX_PW='your-admin-password'      # required

    ./a1box_dns.py show
    ./a1box_dns.py backup
    ./a1box_dns.py set --dns1 192.168.1.10 --dns2 192.168.1.1
    ./a1box_dns.py set --dns1 192.168.1.10 --ipv6-dns none
    ./a1box_dns.py restore a1box-lan-20260101-120000.json
    ./a1box_dns.py default                      # back to A1's DNS-proxy behaviour

Requires: python3, cryptography
"""

import argparse
import base64
import datetime
import json
import os
import sys
import time

import http.cookiejar
import urllib.error
import urllib.request

try:
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
except ImportError:  # pragma: no cover
    sys.exit("missing dependency: pip install cryptography")

DEFAULT_HOST = "http://192.168.1.1"
BACKUP_PREFIX = "a1box-lan"

# Fields we care about, for readable output.
DNS_FIELDS = ("DNS_Type", "DNS_Servers1", "DNS_Servers2")
IPV6_FIELDS = ("IPv6_DNSAssign", "Ipv6_DNSServer1", "Ipv6_DNSServer2", "Ipv6_DNSServer3")


def _pkcs7(data: bytes, block: int = 16) -> bytes:
    pad = block - len(data) % block
    return data + bytes([pad]) * pad


class A1Box:
    """Minimal client for the A1/Zyxel web API (Session cookie + AES/RSA payloads)."""

    def __init__(self, host, user, password, timeout=25):
        self.host = host.rstrip("/")
        self.user = user
        self.password = password
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )
        self.aeskey = None      # base64 AES-256 key, set during login
        self.sessionkey = None  # CSRF token, rotates on every response

    # ---------------- transport ----------------

    def _http(self, path, obj=None, method=None):
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Referer": self.host + "/",
            "Accept": "application/json, text/plain, */*",
        }
        if self.sessionkey:
            headers["CSRFToken"] = self.sessionkey
        data = None
        if obj is not None:
            data = json.dumps(obj).encode()
            headers["Content-Type"] = "application/json;charset=UTF-8"
        req = urllib.request.Request(
            self.host + path, data=data, headers=headers, method=method
        )
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")

    def _decrypt(self, content_b64, iv_b64):
        key = base64.b64decode(self.aeskey)
        iv = base64.b64decode(iv_b64)[:16]
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        out = dec.update(base64.b64decode(content_b64)) + dec.finalize()
        return out[: -out[-1]].decode("utf-8", "replace")

    def _encrypt(self, plain: bytes):
        iv = base64.b64encode(os.urandom(32)).decode()
        key = base64.b64decode(self.aeskey)
        enc = Cipher(algorithms.AES(key), modes.CBC(base64.b64decode(iv)[:16])).encryptor()
        return {
            "content": base64.b64encode(enc.update(_pkcs7(plain)) + enc.finalize()).decode(),
            "iv": iv,
        }

    def _parse(self, status, body):
        try:
            payload = json.loads(body)
        except ValueError:
            return status, body
        if isinstance(payload, dict) and "content" in payload and self.aeskey:
            payload = json.loads(self._decrypt(payload["content"], payload["iv"]))
        if isinstance(payload, dict) and payload.get("sessionkey"):
            self.sessionkey = payload["sessionkey"]  # rotated by the box
        return status, payload

    # ---------------- api ----------------

    def login(self):
        status, body = self._http("/getRSAPublickKey")   # yes, the typo is in the firmware
        if status != 200:
            raise RuntimeError(f"could not fetch RSA key (HTTP {status})")
        pubkey = load_pem_public_key(json.loads(body)["RSAPublicKey"].encode())

        aes_key = base64.b64encode(os.urandom(32)).decode()
        iv = base64.b64encode(os.urandom(32)).decode()

        credentials = {
            "Input_Account": self.user,
            "Input_Passwd": base64.b64encode(self.password.encode()).decode(),
            "currLang": "de",
            "RememberPassword": 0,
            "SHA512_password": False,
        }
        enc_key = pubkey.encrypt(aes_key.encode(), padding.PKCS1v15())
        cipher = Cipher(algorithms.AES(base64.b64decode(aes_key)),
                        modes.CBC(base64.b64decode(iv)[:16])).encryptor()
        payload = {
            "content": base64.b64encode(
                cipher.update(_pkcs7(json.dumps(credentials).encode())) + cipher.finalize()
            ).decode(),
            "key": base64.b64encode(enc_key).decode(),
            "iv": iv,
        }

        status, body = self._http("/UserLogin", payload)   # NOT /cgi-bin/UserLogin
        if status != 200:
            raise RuntimeError(
                f"login failed (HTTP {status}); wrong password or a lockout is active"
            )
        self.aeskey = aes_key
        _, result = self._parse(status, body)
        if result.get("result") != "ZCFG_SUCCESS":
            raise RuntimeError(f"login rejected: {result}")
        return result

    def get_lan(self):
        status, body = self._http("/cgi-bin/DAL?oid=lan")
        status, payload = self._parse(status, body)
        if status != 200 or not isinstance(payload, dict) or "Object" not in payload:
            raise RuntimeError(f"unexpected answer for oid=lan: HTTP {status} {str(payload)[:120]}")
        return payload["Object"][0]

    def put_lan(self, lan_object):
        obj = dict(lan_object)
        obj["logout"] = 0
        # the UI normalises this value before sending; without it the box rejects the write
        if obj.get("IPv6_IdentifierType") == "EUI-64":
            obj["IPv6_IdentifierType"] = "EUI64"
        status, body = self._http(
            "/cgi-bin/DAL?oid=lan", self._encrypt(json.dumps(obj).encode()), method="PUT"
        )
        status, payload = self._parse(status, body)
        if status != 200:
            raise RuntimeError(f"write failed (HTTP {status}): {str(payload)[:200]}")
        if isinstance(payload, dict) and payload.get("result") != "ZCFG_SUCCESS":
            raise RuntimeError(
                f"write rejected: {payload.get('result')} "
                f"(field: {payload.get('ReplyMsg')})"
            )
        return payload


# ---------------- helpers ----------------

def print_settings(lan):
    print("LAN DNS settings")
    for field in DNS_FIELDS:
        print(f"  {field:<16} {lan.get(field)!r}")
    for field in IPV6_FIELDS:
        print(f"  {field:<16} {lan.get(field)!r}")
    print(f"  {'DHCP':<16} {lan.get('EnableDHCP')} "
          f"({lan.get('DHCP_MinAddress')} - {lan.get('DHCP_MaxAddress')})")


def write_backup(lan, directory="."):
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(directory, f"{BACKUP_PREFIX}-{stamp}.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(lan, handle, indent=2, sort_keys=True)
    return path


def connect(args):
    password = os.environ.get("A1BOX_PW")
    if not password:
        sys.exit("set A1BOX_PW to the box's admin password")
    box = A1Box(
        host=os.environ.get("A1BOX_HOST", args.host),
        user=os.environ.get("A1BOX_USER", args.user),
        password=password,
    )
    box.login()
    return box


# ---------------- commands ----------------

def cmd_show(args):
    lan = connect(args).get_lan()
    print_settings(lan)


def cmd_backup(args):
    lan = connect(args).get_lan()
    path = write_backup(lan)
    print(f"backup written: {path}")


def cmd_set(args):
    box = connect(args)
    lan = box.get_lan()
    before = {f: lan.get(f) for f in DNS_FIELDS + IPV6_FIELDS}

    updated = dict(lan)
    if args.dns1:
        updated["DNS_Type"] = "Static"
        updated["DNS_Servers1"] = args.dns1
        if args.dns2:
            updated["DNS_Servers2"] = args.dns2
        else:
            updated.pop("DNS_Servers2", None)
    if args.ipv6_dns:
        value = args.ipv6_dns
        if value in ("none", "proxy"):
            for field in ("Ipv6_DNSServer1", "Ipv6_DNSServer2", "Ipv6_DNSServer3"):
                updated[field] = value.capitalize()
        elif value == "static":
            if not args.ipv6_dns1:
                sys.exit("--ipv6-dns static needs --ipv6-dns1")
            updated["Ipv6_DNSServer1"] = args.ipv6_dns1
            updated["Ipv6_DNSServer2"] = args.ipv6_dns2 or "None"
            updated["Ipv6_DNSServer3"] = "None"

    after = {f: updated.get(f) for f in DNS_FIELDS + IPV6_FIELDS}
    if before == after:
        print("nothing to do — values already match")
        return

    print("planned change:")
    for field in DNS_FIELDS + IPV6_FIELDS:
        if before.get(field) != after.get(field):
            print(f"  {field:<16} {before.get(field)!r} -> {after.get(field)!r}")

    if args.dry_run:
        print("dry run, nothing written")
        return

    if not args.no_backup:
        print(f"backup: {write_backup(lan)}")
    box.put_lan(updated)
    time.sleep(2)
    print_settings(box.get_lan())


def cmd_restore(args):
    with open(args.file, encoding="utf-8") as handle:
        lan = json.load(handle)
    box = connect(args)
    print(f"restoring DNS settings from {args.file}")
    box.put_lan(lan)
    time.sleep(2)
    print_settings(box.get_lan())


def cmd_default(args):
    """A1's factory behaviour: the box itself is the DNS server for LAN clients."""
    box = connect(args)
    lan = dict(box.get_lan())
    lan["DNS_Type"] = "DNSProxy"
    lan.pop("DNS_Servers1", None)
    lan.pop("DNS_Servers2", None)
    for field in ("Ipv6_DNSServer1", "Ipv6_DNSServer2", "Ipv6_DNSServer3"):
        lan[field] = "Proxy"
    print(f"backup: {write_backup(box.get_lan())}")
    box.put_lan(lan)
    time.sleep(2)
    print_settings(box.get_lan())


def main():
    parser = argparse.ArgumentParser(
        description="Read/write LAN DNS servers on an A1 WLAN Box (Zyxel DX3301-T0)."
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="box address (default %(default)s)")
    parser.add_argument("--user", default="admin", help="admin user (default admin)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("show", help="print the current LAN DNS settings").set_defaults(
        func=cmd_show)
    sub.add_parser("backup", help="write the current LAN object to a JSON file").set_defaults(
        func=cmd_backup)

    p_set = sub.add_parser("set", help="set DNS servers handed out by DHCP")
    p_set.add_argument("--dns1", help="primary DNS server (IPv4), e.g. your Pi-hole")
    p_set.add_argument("--dns2", help="secondary/fallback DNS server (IPv4)")
    p_set.add_argument("--ipv6-dns", choices=["none", "proxy", "static"],
                       help="how the box should answer IPv6 DNS requests")
    p_set.add_argument("--ipv6-dns1", help="IPv6 DNS server for --ipv6-dns static")
    p_set.add_argument("--ipv6-dns2", help="second IPv6 DNS server (optional)")
    p_set.add_argument("--dry-run", action="store_true", help="show the change, write nothing")
    p_set.add_argument("--no-backup", action="store_true", help="skip the automatic backup")
    p_set.set_defaults(func=cmd_set)

    p_restore = sub.add_parser("restore", help="write a previously saved LAN object back")
    p_restore.add_argument("file", help="JSON file created by backup (or 'a1box_dns.py backup')")
    p_restore.set_defaults(func=cmd_restore)

    sub.add_parser("default", help="restore A1's default (box is its own DNS)").set_defaults(
        func=cmd_default)

    args = parser.parse_args()
    try:
        args.func(args)
    except RuntimeError as exc:
        sys.exit(f"error: {exc}")


if __name__ == "__main__":
    main()
