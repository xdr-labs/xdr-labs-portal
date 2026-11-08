AI-Assisted Attack Detection Rules v1.0 (November 8, 2026)
========================================================

Suricata signature bundle for Stellar Cyber 7.0 lab evaluation.

Release contents
- 333 alert-only Suricata rules, including 11 newly confirmed sensor detections
- Network/port header: any any -> any any
- All 333 signatures included in v1.0 were verified on a controlled Stellar Cyber 7.0 Modular Sensor (Suricata 8.0.1); only release comments changed.

Rules filename: local-web-attack-ai-v1.0-333.rules
Rules SHA-256:
5947a64a6b45ee122537a1ea166ebf383307302cf210b63d24b350b0df98eb96

Verification performed
- Suricata 8.0.8 -T --init-errors-fatal: PASS
- 19 PCAP fixtures compared across a baseline configuration and the 333-rule candidate: 38/38 successful runs
- All 11 added SIDs observed on targeted synthetic positive stimuli
- OAST DNS: 4/4 matching domains detected; 4/4 lookalike controls quiet
- Additional 146 benign-intent HTTP/DNS sessions: no new alerts over baseline rules
- Included 10 official OISF Suricata-Verify SMB/DCERPC/Kerberos PCAPs
- Existing XSS signature can alert on benign HTML; this is unchanged
- Live sensor HTTP/DNS: 18 test sessions, all 11 new SIDs observed in eve.json
- Seven negative-control sessions produced zero new custom-rule alerts
- Captured on eth0: 110 packets, zero kernel capture drops
- Replay of identical captured PCAP: baseline configuration = 0, 333-rule set = 11 new-pattern alerts
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


Sources/licensing: ET Open and Theori AIPT Detections. Refer to the header
and source notices in the .rules file for applicable attribution and terms.

Release note: The 333 detection signatures and SIDs are identical to those validated on the lab sensor. The v1.0 file only updates version comments; its SHA-256 differs from the sensor-tested copy.
