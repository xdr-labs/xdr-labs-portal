AI-Assisted Attack Detection Rules v0.9 (November 8, 2026)
========================================================

Suricata signature bundle for Stellar Cyber 7.0 lab evaluation.

Release contents
- 333 alert-only Suricata rules: 322 from v0.8 + 11 tested additions
- Network/port header: any any -> any any
- v0.9 is LAB-VALIDATED; actual Stellar Cyber sensor import is NOT verified.

Rules filename: local-web-attack-ai-v0.9-validated-333.rules
Rules SHA-256:
8b902126044224089cd367a47c58c98290563f0816972272086fb79e8b1c77a6

Verification performed
- Suricata 8.0.8 -T --init-errors-fatal: PASS
- 19 PCAP fixtures compared across v0.8 and v0.9: 38/38 successful runs
- All 11 added SIDs observed on targeted synthetic positive stimuli
- OAST DNS: 4/4 matching domains detected; 4/4 lookalike controls quiet
- Additional 146 benign-intent HTTP/DNS sessions: no new alerts over v0.8
- Included 10 official OISF Suricata-Verify SMB/DCERPC/Kerberos PCAPs
- Existing v0.8 XSS signature can alert on benign HTML; this is unchanged
- Actual Stellar Cyber Sensor Import, built-in IDS overlap and live alert
  generation: NOT VERIFIED

Before importing
1. Back up the existing custom_defined.rules. Import may overwrite the file.
2. Confirm your sensor's Suricata version and application-protocol support.
3. Review enabled built-in ET/IDS signatures to avoid duplicate detection.
4. Import first on an isolated non-production sensor and verify actual alerts.
5. OAST traffic can also arise during authorized penetration tests.
6. Inspect HTTP content only where plaintext or decrypted traffic is visible.
7. New AD/DCERPC lateral movement candidates were excluded because safe
   separation from normal domain administration remains unverified.
8. Rules are static signatures, not an embedded AI detection model.

Previous v0.8 (322 rules) remains available from the portal.

Sources/licensing: ET Open and Theori AIPT Detections. Refer to the header
and source notices in the .rules file for applicable attribution and terms.
