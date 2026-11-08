# Suricata v1.0 — last two SID regression gate

These are **test-only** regression fixtures for Suricata 8.0.1. They are **not a replacement download** and must not be imported into a running sensor.

## Scope

The published v1.0 file retains **333 unchanged signatures**. `run_offline.py` verifies SHA-256, generates a temporary copy differing in only two SID rules, and checks actual Suricata syntax and offline PCAP behavior.

- `9005017`: change `http.uri` to `http.uri.raw`. Normalized URIs omit the scheme and host of absolute-form URIs by default. A generic WebSocket proxy request could generate an alert without proving exploitation of a vulnerable Next.js host.
- `9005055`: retain the 100-or-more empty-filename condition but reduce the PCRE gap from 4096 to **128 bytes**. This detects compact multipart fields with the stock sensor PCRE limits, but can miss variants with wider spacing. This is a bounded detection tradeoff, not complete equivalence.

Both are review candidates only, not published or sensor-installed rules. Actual sensor verification remains **331/333**.

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
| 99 empty file fields | 0 | 0 |
| 100 empty file fields | 0 | 1 |
| 105 empty file fields | 0 | 1 |
| 105 nonempty filenames | 0 | 0 |
| Wrong Content-Type with 105 fields | 0 | 0 |

**Observed on modular / Suricata 8.0.1: 9/9 PASS.** Exactly two test-only signatures changed; all 333 SIDs retained and Suricata syntax check passed. Results are preserved in `suricata-8.0.1-results.json` and fixtures are SHA-256 checked against `manifest.json`.

Additional spacing study on actual 100/105-field multipart fixtures: a 128-byte bound matched, whereas greedy gaps 160–1024 bytes did not under the existing PCRE budget. This does not prove the precise root cause or guarantee detection of all payload layouts. Process runtimes of approximately 0.5 seconds per test are not high-throughput benchmarks.

**Before release:** assess possible false positives from legitimate WebSocket proxies, multipart fields wider than 128 bytes, PCRE CPU impact under load, and then perform an independently authorized rule release and live sensor Alert verification. No public v1.0 or deployed rule was modified.
