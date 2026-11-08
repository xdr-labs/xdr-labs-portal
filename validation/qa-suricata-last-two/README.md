# Suricata v1.0 — last two SID regression gate

These are **test-only** regression fixtures for Suricata 8.0.1. They are **not a replacement download** and must not be imported into a running sensor.

## Scope

The published v1.0 file retains **333 unchanged signatures**. `run_offline.py` verifies SHA-256, generates a temporary copy differing in only two SID rules, and checks actual Suricata syntax and offline PCAP behavior.

- 9005017: inspect raw URI with an anchored http/https regex, support single/double percent-encoded slashes, and require GET method. Generic WebSocket proxy requests might alert without proving exploitation of vulnerable Next.js.
- 9005055: retain the 100-or-more empty-filename condition but inspect a structured MIME Content-Disposition header, up to 8 extra header lines, a single-line body up to 4096 bytes, and a subsequent multipart boundary. This QA-only regex matches 105 wide-gap parts; valid multiline part bodies remain an explicit detection gap.

Both are review candidates only, not published or sensor-installed rules. Actual original sensor verification remains 331/333.

## Running the gate

Static integrity (works without Suricata):

```
python3 validation/qa-suricata-last-two/run_offline.py
```

Offline engine verification (Suricata 8.0.1 required):

```
python3 validation/qa-suricata-last-two/run_offline.py --run \
  --suricata /usr/bin/suricata \
  --config /path/to/suricata.yaml \
  --report /tmp/suricata-last-two-result.json
```

The runner uses temporary files and does not send network packets, reload a sensor, or modify distributed assets.

## Expected SID alerts

| Test fixture | SID 9005017 | SID 9005055 |
| --- | ---: | ---: |
| Absolute URI with WebSocket headers | 1 | 0 |
| Origin-form URI | 0 | 0 |
| Missing Upgrade header | 0 | 0 |
| Missing WebSocket key | 0 | 0 |
| Absolute https:// URI | 1 | 0 |
| Single-percent-encoded HTTP URI | 1 | 0 |
| Single-percent-encoded HTTPS URI | 1 | 0 |
| Double-percent-encoded HTTP URI | 1 | 0 |
| WebSocket-like POST method | 0 | 0 |
| 99 empty file fields | 0 | 0 |
| 100 empty file fields | 0 | 1 |
| 105 empty file fields | 0 | 1 |
| 105 empty parts with long header gaps | 0 | 1 |
| 105 nonempty filenames | 0 | 0 |
| 105 parts, empty file body | 0 | 1 |
| 105 parts, no per-part Content-Type | 0 | 1 |
| 105 parts, variable MIME boundary | 0 | 1 |
| 105 parts, lowercase Content-Disposition | 0 | 1 |
| 105 parts, multiline body (known detection gap) | 0 | 0 |
| Wrong Content-Type with 105 fields | 0 | 0 |

**Observed on modular / Suricata 8.0.1: 20/20 PASS** using a temporary 333-rule copy with exactly two changes. The multiline-body negative is an explicit known detection gap, not an attack detection. All 20 fixture SHA256 values and exact SID-specific offline engine output are verified by the pinned runner.

A prior wide-gap wildcard PCRE failed under the stock engine limits. The structured MIME candidate matched both compact and wide-gap multipart samples, but still has a one-line body constraint, can miss unusual MIME variations, and is not production-performance- or false-positive-validated. Offline process startups of about 0.5 seconds each are not throughput benchmarks.

**Before release:** assess false positives from legitimate WebSocket proxy requests and multipart forms, valid multiline file-part bodies, optional MIME variations, PCRE CPU under load, and independent owner approval for any new rule version and real sensor deployment. No public v1.0 or deployed rule was modified.

## Expanded regression findings

- Original 9005017: normalized URI loses the absolute-form URL scheme. The original repeated-slash regex also excludes single percent-encoded %2f but includes doubly encoded %252f. A QA-only raw-URI/GET/anchored-regex variant covers 6 positive / 5 negative HTTP cases.
- Original 9005055: 100+ repeated multipart filename-empty controls failed with the original broad PCRE on valid MIME inputs. QA-only structured MIME header/body/boundary matching covers compact and wide-gap single-line cases, while documented multiline body cases still miss. Not a production-complete replacement.
- Neither candidate was installed, imported, or distributed. Original live sensor remains 331/333; QA-only results cannot raise the verified-original count.
