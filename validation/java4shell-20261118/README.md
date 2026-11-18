# Java4Shell (CVE-2026-114938) — Suricata v1.1 public rulepack — offline QA

**Published v1.1 rulepack.** The package has been validated on the actual Modular Sensor with isolated offline PCAP replay, but is **not** installed in the operating IDS. Public distribution and live deployment are separate.

- Original v1.0 333 rules: unchanged bytes and SID values. Published SHA256 `5947a64a6b45ee122537a1ea166ebf383307302cf210b63d24b350b0df98eb96`.
- Six new SID `9006101–9006106`, SHA256 `e05bcf3dc56bb0331481dbec8c4cad92561b66133e1fd274421886472e33cd03`.
- Combined 339-rule v1.1 SHA256 `2478ffd6b3dbdfbb527695f07e00e1a106a554d8bb898a0f9584bb3845b07483`.
- Sensor used for QA: `modular` through DRLink managed endpoint `AT Secu MDS`, Suricata 8.0.1.
- Provenance: adapted from the public Java4Shell detection concepts at https://github.com/ikow/java4shell-poc/blob/main/detection/java4shell.rules ; corrected false positives arising from regex matching valid padded token lengths. Do not treat rules as official Talos signatures.
- Rule license attributions for original 333 are preserved in the unchanged original header. The six new rules are authored as local alert-only signatures.

## Detection types and offline evidence

| SID | Coverage | Expected test fixture |
| --- | --- | --- |
| 9006101 | Invalid-length Basic auth Base64 token | basic-malformed |
| 9006102 | Exact 64 A bytes with invalid padding, bounded to header value | exact-64-header |
| 9006103 | Exact 128 A bytes with invalid padding | exact-128-header |
| 9006104 | High rate of Basic auth (> = 1,000 requests / 60 s per source) | burst-1000 (alert), burst-999 (no alert) |
| 9006105 | JVM crash strings surfaced in plaintext HTTP response | crash-response |
| 9006106 | Invalid-length padded JWT payload segment | jwt-padded |

Validation on November 18, 2026: `suricata -T` accepted six-only and combined 339 rules, and **10/10 distinct offline PCAP fixture expectations passed** on the actual Suricata 8.0.1 sensor. `basic-valid-padded`, `jwt-valid-padded`, and `benign-normal` produced no new Java4Shell alerts. The original community regex did produce false positives on padded tokens with a valid length; the RC1 rules correct that observed behavior.

**Sensor operations:** No change to `/etc/suricata/rules/custom_defined.rules`, no full import/reload requested. The operating 333-rule file hash still matched the v1.0 release. Suricata service was active at final check. Existing operational live confirmation remains **331/333 original rules**; **none of the six new rules was counted as live-verified.**

## Reproduce in an authorized offline Suricata 8.x lab

```bash
python3 validation/java4shell-20261118/verify_package.py
python3 validation/java4shell-20261118/run_offline.py \
  --config /etc/suricata/suricata.yaml \
  --rules downloads/local-web-attack-ai-v1.1-339.rules \
  --output /tmp/java4shell-offline-qa
```

The scripts generate 10 **inert** HTTP/TCP PCAP fixtures; they do not contact a target Java host or exploit any Java vulnerability. The offline runner creates temporary Suricata log directories. It never updates an operating sensor configuration.

## Limitations / release gates

1. Network signatures only observe requests/responses if HTTP plaintext is visible. HTTPS/QUIC without decryption is not covered.
2. Basic request burst (9006104) can be emitted by high-volume legitimate clients/NAT gateways; crash string rule (9006105) requires unusually exposed log text in HTTP response. Treat both as low-confidence heuristics.
3. Content patterns cannot confirm Java runtime version, AVX-512 VBMI hardware support, or actual execution.
4. A sensor's custom-rule import **replaces** `custom_defined.rules`. **Never import the six-only supplement**. Review and back up the complete 339 file first.
5. Public website publication has been authorized; operating sensor import/restart remains separately approval-gated. Live EVE/DP/UI acceptance is outstanding. Offline QA is not evidence of full live-sensor deployment.
6. Keep legacy 9005017 and 9005055 validation status unchanged; they remain unreproduced in the v1.0 live baseline.

JSON evidence is in `suricata-8.0.1-results.json`; SHA256 values above provide a byte-exact gate.
