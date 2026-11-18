AI-Assisted Attack Detection Rules — v1.1 (November 18, 2026)
===================================================================
Stellar Cyber Open XDR 7.0 / Suricata 8.0.1

Full rules: local-web-attack-ai-v1.1-339.rules
Rule count: 339 (original 333 unchanged + 6 Java4Shell CVE-2026-114938 indicators)
SHA-256: 2478ffd6b3dbdfbb527695f07e00e1a106a554d8bb898a0f9584bb3845b07483
New SIDs: 9006101-9006106

Actual sensor test: 339/339 parsed by Suricata -T, six new SIDs
triggered in isolated offline PCAP replay; 10/10 synthetic controls passed.
The previous original 333 rules have 331 individually verified live alerts.
The 2 unconfirmed original SIDs (9005017, 9005055) remain unchanged.

The new 6 rules have not been installed in the operating IDS or verified
through live sensor capture or the Data Processor UI. This is not a
production detection rate, false-positive rate, or confirmed exploit test.

Before use: Back up custom_defined.rules. Importing a rules file through
Stellar Cyber replaces the ENTIRE custom-defined rules file.
Do not import the six-only supplemental review file by itself.
Plaintext or decrypted HTTP visibility is needed.

Technical QA, test scripts, and limitations:
https://github.com/xdr-labs/xdr-labs-portal/tree/main/validation/java4shell-20261118
