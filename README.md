# Security Research

This repository will contain security-related stuff I am doing.

Here you can find my writeups and proof of concepts for the vulnerabilities I have discovered. You can also find more information on my blog: <https://hackerask.com>

## Vulnerabilities

| Title | Severity | References | Software |
|-------|----------|------------|----------|
| [Root RCE via Arbitrary File Write in GeoIP Alias Importer](disclosures/001_opnsense-rce-file-write-geoip/README.md) | Critical (9.9) |- [CVE-2026-57155](https://nvd.nist.gov/vuln/detail/CVE-2026-57155) <br>- [GHSA-wjqq-rfmm-v5h3](https://github.com/opnsense/core/security/advisories/GHSA-wjqq-rfmm-v5h3) <br>- [Blog Post](https://hackerask.com/posts/opnsense/) | OPNsense |
| [Stored XSS in Firewall Rules/NAT pages via a HTML-attribute breakout](disclosures/002_opnsense-stored-xss-firewall-rules-nat-attribute/README.md) | Moderate (5.4) |- tba <br>- [GHSA-2xrm-p255-p43h](https://github.com/opnsense/core/security/advisories/GHSA-2xrm-p255-p43h) <br>- [Blog Post](https://hackerask.com/posts/opnsense/) | OPNsense |
| [Stored XSS in Services: NTP GPS](disclosures/003_opnsense-stored-xss-ntp-gps/README.md) | Moderate (5.4) |- tba <br>- [GHSA-h793-67jm-j4m5](https://github.com/opnsense/core/security/advisories/GHSA-h793-67jm-j4m5) <br>- [Blog Post](https://hackerask.com/posts/opnsense/) | OPNsense |
