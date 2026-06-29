# Security Research

This repository will contain security-related stuff I am doing.

Here you can find my writeups and proof of concepts for the vulnerabilities I have discovered. You can also find more information on my blog: <https://hackerask.com>

## Vulnerabilities

| Title | Severity (CVSS) | References (CVE, GHSA, etc.) |
|-------|----------|------------|
| [Root RCE via Arbitrary File Write in GeoIP Alias Importer](disclosures/001_opnsense-rce-file-write-geoip/README.md) | Critical (9.9) |- [CVE-2026-57155](https://nvd.nist.gov/vuln/detail/CVE-2026-57155) <br>- [GHSA-wjqq-rfmm-v5h3](https://github.com/opnsense/core/security/advisories/GHSA-wjqq-rfmm-v5h3) <br>- [Blog Post](https://hackerask.com/posts/opnsense/) |
| [Stored XSS in Firewall Rules/NAT pages via a HTML-attribute breakout](disclosures/002_opnsense-stored-xss-firewall-rules-nat-attribute/README.md) | Moderate (5.4) |- `TBA` <br>- [GHSA-2xrm-p255-p43h](https://github.com/opnsense/core/security/advisories/GHSA-2xrm-p255-p43h) <br>- [Blog Post](https://hackerask.com/posts/opnsense/) |
| [Stored XSS in Services: NTP GPS](disclosures/003_opnsense-stored-xss-ntp-gps/README.md) | Moderate (5.4) |- `TBA` <br>- [GHSA-h793-67jm-j4m5](https://github.com/opnsense/core/security/advisories/GHSA-h793-67jm-j4m5) <br>- [Blog Post](https://hackerask.com/posts/opnsense/) |
| [XPath injection in MVC safe-delete](disclosures/004_opnsense-xpath-injection-mvc-safe-delete/README.md) | Moderate (4.3) |- `TBA` <br>- [GHSA-98h6-479q-9q3w](https://github.com/opnsense/core/security/advisories/GHSA-98h6-479q-9q3w) <br>- [Blog Post](https://hackerask.com/posts/opnsense/) |
| [Stored XSS in Administration Settings via Certificate Description](disclosures/005_opnsense-stored-xss-admin-certificate-description/README.md) | Moderate (5.2) |- `TBA` <br>- [GHSA-8pgr-x852-qx4j](https://github.com/opnsense/core/security/advisories/GHSA-8pgr-x852-qx4j) <br>- [Blog Post](https://hackerask.com/posts/opnsense/) |
