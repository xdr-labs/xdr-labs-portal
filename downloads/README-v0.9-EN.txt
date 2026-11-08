AI-Assisted Attack Detection Rules v0.9 (November 8, 2026)
========================================================

Suricata signature bundle for Stellar Cyber 7.0 lab evaluation.

Release contents
- 333 alert-only Suricata rules: 322 from v0.8 + 11 tested additions
- Network/port header: any any -> any any
- v0.9 sensor import and IDS detection verified on a controlled Stellar Cyber 7.0 Modular Sensor (Suricata 8.0.1).

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
- Live sensor HTTP/DNS: 18 test sessions, all 11 new SIDs observed in eve.json
- Seven negative-control sessions produced zero new custom-rule alerts
- Captured on eth0: 110 packets, zero kernel capture drops
- Replay of identical captured PCAP: v0.8 = 0, v0.9 = 11 new-pattern alerts
- Five official OISF SMB/DCERPC/Kerberos PCAPs replayed on the actual sensor
- Built-in ET SID 2034825 alerted on an OAST lookalike domain (not a new-rule alert)
- Two built-in ETPRO rules, SIDs 2868495 and 2868498, failed to load because
  krb5 and nfs are disabled; those rules/config were left unchanged
- Stellar Cyber DP/UI alert delivery and real-world false-positive rate: NOT VERIFIED

Before importing
1. Back up the existing custom_defined.rules. Import may overwrite the file.
2. Confirm your sensor's Suricata version and application-protocol support.
3. Review enabled built-in ET/IDS signatures to avoid duplicate detection.
4. For a different sensor, first import in a non-production environment and verify alerts.
5. OAST traffic can also arise during authorized penetration tests.
6. Inspect HTTP content only where plaintext or decrypted traffic is visible.
7. New AD/DCERPC lateral movement candidates were excluded because safe
   separation from normal domain administration remains unverified.
8. Rules are static signatures, not an embedded AI detection model.

Previous v0.8 (322 rules) remains available from the portal.

Sources/licensing: ET Open and Theori AIPT Detections. Refer to the header
and source notices in the .rules file for applicable attribution and terms.
