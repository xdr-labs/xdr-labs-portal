AI-Assisted Attack Detection Rules — v1.0 (November 9, 2026)
==============================================================

333 Suricata detection signatures for Stellar Cyber 7.0.

- Distributed: 333 signatures in both the .rules file and the ZIP.
- Confirmed individual alerts on a real Stellar Cyber 7.0 Modular Sensor:
  331 of 333 signatures.
- The remaining two (SID 9005017 and SID 9005055) are included but did
  not have an individually confirmed live-sensor alert.
- Evaluation used controlled traffic with Suricata 8.0.1.
- All 333 signature lines and SIDs match the installed sensor rulepack.
- This is not a real-world attack detection rate or an accuracy claim.

Rule file: local-web-attack-ai-v1.0-333.rules
SHA-256: 5947a64a6b45ee122537a1ea166ebf383307302cf210b63d24b350b0df98eb96

Before importing
1. Back up existing custom_defined.rules: import may overwrite it.
2. Check for duplicated detection conditions with built-in IDS/ET rules.
3. Encrypted HTTPS bodies require visible plaintext or decrypted traffic.
4. Separately evaluate production false positives, attack coverage, and
   Stellar Cyber DP/UI alert delivery.
5. The tested operating sensor already has all 333 original signatures;
   reimport is not necessary there.

See the header of the .rules file for attribution and licensing notices.
