# Suricata v1.0 — last two SID regression gate

These are **test-only** regression fixtures for Suricata 8.0.1. They are **not a replacement download** and must not be imported into a running sensor.

## Scope

The published v1.0 file retains **333 unchanged signatures**. `run_offline.py` verifies SHA-256, generates a temporary copy differing in only two SID rules, and checks actual Suricata syntax and offline PCAP behavior.

- 9005017: inspect raw URI with an anchored http/https regex, support single/double percent-encoded slashes, and require GET method. Generic WebSocket proxy requests might alert without proving exploitation of vulnerable Next.js.
- `9005055`: retain the 100-or-more empty-filename condition but reduce the PCRE gap from 4096 to **128 bytes**. This detects compact multipart fields with the stock sensor PCRE limits, but misses a verified 105-part MIME case when neighboring filename markers are separated by more than 128 bytes. This is a bounded detection tradeoff, not complete equivalence.

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
| 105 valid empty parts with >128-byte gaps (known detection gap) | 0 | 0 |
| 105 nonempty filenames | 0 | 0 |
| Wrong Content-Type with 105 fields | 0 | 0 |

**Observed on modular / Suricata 8.0.1: 15/15 PASS** using a temporary 333-rule copy with exactly two changes. The wide-gap negative case is an explicit known detection gap, not a successful attack detection. Full runner evidence should be refreshed before shipping any package.

Additional spacing study on actual 100/105-field multipart fixtures: a 128-byte bound matched, whereas greedy gaps 160–1024 bytes did not under the existing PCRE budget. This does not prove the precise root cause or guarantee detection of all payload layouts. Process runtimes of approximately 0.5 seconds per test are not high-throughput benchmarks.

**Before release:** assess possible false positives from legitimate WebSocket proxies, multipart fields wider than 128 bytes, PCRE CPU impact under load, and then perform an independently authorized rule release and live sensor Alert verification. No public v1.0 or deployed rule was modified.

## Expanded regression findings

- Original 9005017: normalized URI loses the absolute-form URL scheme. The original repeated-slash regex also excludes single percent-encoded %2f but includes doubly encoded %252f. A QA-only raw-URI/GET/anchored-regex variant covers 6 positive / 5 negative HTTP cases.
- Original 9005055: 100+ repeated multipart filename-empty controls fail with wide PCRE gaps. Bounded QA variant (128-byte gap) detects compact MIME parts but misses valid wide-gap parts; not a complete replacement.
- Neither candidate was installed, imported, or distributed. Original live sensor remains 331/333; QA-only results cannot raise the verified-original count.
