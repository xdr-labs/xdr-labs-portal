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

**Initial targeted cases: 9/9 PASS. Extended release-risk checks: 13/13 PASS for expected observations; release readiness is BLOCKED.** Exactly two test-only signatures changed; all 333 SIDs retained and Suricata syntax check passed. Results are preserved in `suricata-8.0.1-results.json` and fixtures are SHA-256 checked against `manifest.json`.

Additional spacing study on actual 100/105-field multipart fixtures: a 128-byte bound matched, whereas greedy gaps 160–1024 bytes did not under the existing PCRE budget. This does not prove the precise root cause or guarantee detection of all payload layouts. Process runtimes of approximately 0.5 seconds per test are not high-throughput benchmarks.

**Before release:** assess possible false positives from legitimate WebSocket proxies, multipart fields wider than 128 bytes, PCRE CPU impact under load, and then perform an independently authorized rule release and live sensor Alert verification. No public v1.0 or deployed rule was modified.

## Confirmed release-risk witness cases (13/13 tests)

These four inert PCAPs are not success conditions for a safe release. They deliberately record known limitations of the two temporary detection candidates.

| Test fixture | Candidate 9005017 Alert | Candidate 9005055 Alert | Interpretation |
| --- | ---: | ---: | --- |
| Normal-shaped absolute HTTP WebSocket proxy request | 1 | 0 | Non-specific proxy traffic can trigger the SSRF signature |
| Normal-shaped absolute HTTPS WebSocket proxy request | 1 | 0 | Same non-specificity with HTTPS target |
| 100 empty multipart fields with extra valid MIME headers | 0 | 0 | **Miss** despite reaching the threshold |
| 105 empty multipart fields with extra valid MIME headers | 0 | 0 | **Miss** despite exceeding the threshold |

The full engine result sets `release_ready: false` and `release_status: BLOCKED_BY_KNOWN_FP_AND_FN_RISKS` in `suricata-8.0.1-risk-assessment.json`.

These benign proxy fixtures use ordinary WebSocket upgrade syntax for documentation-only hosts, not evidence of a vulnerable Next.js deployment. They demonstrate a lack of specificity, not a production false-positive rate. Extra MIME headers increase spacing beyond 128 bytes; the multipart syntax remains valid.

Source context: [Next.js advisory](https://github.com/advisories/GHSA-c4j6-fc7j-m34r) and [PHP2Shell bulletin](https://access.redhat.com/security/vulnerabilities/RHSB-2026-013).

## Limited resource replay

`generate_risk_fixtures.py --stress 100 --output-dir /tmp/qa-risk` creates 100 distinct compact multipart sessions without any network sends. In one isolated Suricata 8.0.1 replay using the full 333-rule pack, the original PHP SID alerted 0 times and the bounded candidate alerted 100 times. CPU user time was 0.67 s (original) and 0.70 s (candidate); peak resident memory ~88 MB. See `suricata-8.0.1-stress100.json`.

The recorded CPU includes Suricata startup and cannot demonstrate sustained traffic throughput. Additional performance and evasion testing would be required before release.

**Release conclusion:** Neither candidate is release-approved. Public v1.0 and the live sensor remain at 331/333 confirmed original SID alerts, unchanged.
