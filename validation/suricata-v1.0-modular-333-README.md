# Suricata v1.0 — full 333-rule sensor verification

- Tested on November 8, 2026 using a controlled Stellar Cyber 7.0 Modular Sensor (Suricata 8.0.1).
- All 333 SIDs received purpose-built synthetic test input. **331 SIDs produced observed actual sensor alerts; 2 were not reproduced.** This is a per-SID replay result, not a production attack-detection rate.
- Two unconfirmed original SIDs: `9005017` (Next.js WebSocket SSRF URI-buffer mismatch), `9005055` (PHP multipart repetition PCRE). Test-only variants of both match under isolated offline replay; deployed rules remain unchanged.
- The verification CSV lists all 333 SIDs, protocol, category, signature, test evidence sources, and final disposition.
- Evidence: test PCAPs, generators, and Suricata `eve.json` on the controlled sensor under `/tmp/modular-suricata-333-validation-20261108/`.
- No changes were made to the installed sensor rules, Suricata configuration, or production process. Temporary test listeners were stopped.
- The downloadable public v1.0 file retains the same 333 detection signature lines and SIDs as the sensor-tested rulepack; its release comments and file SHA-256 differ.
- Stellar Cyber DP/UI delivery, operational false-positive rates and end-to-end attack efficacy were not established.

## Subsequent live sensor evidence (November 9, 2026 KST)

- `9005035` DCE/RPC: valid bind/ack/request from OISF fixture with inert WMIExec marker, observed as original SID in live `eve.json` from `192.168.219.121:38101` to `192.168.219.126:18888`.
- `9005027` / `9005029` SMB: non-executable, NetBIOS-framed SMB1 test messages were sent only to isolated lab listener `192.168.219.126:18890`. Both original SIDs alerted live; `9005027` used three test connections for its threshold.
- Sensor packet captures and JSON: `/tmp/modular-suricata-333-validation-20261108/`, including `dcerpc-inert-live.pcap`, `smb1-inert-live.pcap` and corresponding results JSON.
- No exploit execution, actual SMB service connection, rule reload, or sensor configuration change.
