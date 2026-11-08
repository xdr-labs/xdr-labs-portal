# Suricata v1.0 — full 333-rule sensor verification

- Tested on November 8, 2026 using a controlled Stellar Cyber 7.0 Modular Sensor (Suricata 8.0.1).
- All 333 SIDs received purpose-built synthetic test input. **328 SIDs produced observed actual sensor alerts; 5 were not reproduced.** This is a per-SID replay result, not a production attack-detection rate.
- The five unreproduced SIDs: `9005017` (HTTP normalized-URI conditions), `9005027` and `9005029` (native SMB scenarios), `9005035` (native DCE/RPC scenario), `9005055` (complex multipart repetition; PCRE diagnostic timed out). They have not been proven defective.
- The verification CSV lists all 333 SIDs, protocol, category, signature, test evidence sources, and final disposition.
- Evidence: test PCAPs, generators, and Suricata `eve.json` on the controlled sensor under `/tmp/modular-suricata-333-validation-20261108/`.
- No changes were made to the installed sensor rules, Suricata configuration, or production process. Temporary test listeners were stopped.
- The downloadable public v1.0 file retains the same 333 detection signature lines and SIDs as the sensor-tested rulepack; its release comments and file SHA-256 differ.
- Stellar Cyber DP/UI delivery, operational false-positive rates and end-to-end attack efficacy were not established.
