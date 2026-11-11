# Suricata v1.0 — two unreproduced signatures (test-only)

Date: November 9, 2026 KST. Test sensor: modular / Suricata 8.0.1. Installed rules SHA-256: `8b902126044224089cd367a47c58c98290563f0816972272086fb79e8b1c77a6` (unchanged).

**331/333 original installed SID alerts verified live.** Neither diagnostic SID below was counted as a live original alert. All condition changes were temporary, limited to offline `suricata -r` and `-T` tests.

| Original SID | Original condition | Same-PCAP diagnostic |
| --- | --- | --- |
| `9005017` | `http.uri` buffer, WebSocket absolute-URI request; 0 original alerts across 13 variants | Change only first `http.uri;` to `http.uri.raw;`: 6 candidate alerts |
| `9005055` | Greedy `.{0,4096}` within 100+ repeated multipart fields: 0 original alerts | Use lazy `.{0,4096}?`: 4 candidate alerts with same test input |

Temporary 333-rule candidate: Suricata syntax test PASS. Next.js PCAP produced 6 candidate SID 9005017 alerts, PHP PCAP 4 candidate SID 9005055 alerts, and a separate benign-control capture produced 0 alerts for these two SIDs. This is not full production false-positive/performance verification.

Artifacts remain on the test sensor under `/tmp/modular-suricata-333-validation-20261108/`: `candidate-fix-2-sids-333.rules`, `candidate-two-fixes-offline-results.json`, `nextjs-absolute-uri-variants.pcap`, and `targeted-http-v6.pcap`. None were installed or distributed.

Before any public release or sensor import, evaluate detection equivalence, false positives, PCRE CPU/cost, and release/rollback procedures. No existing ETPRO rule was changed.

## Reproducible offline release-candidate QA (November 9, 2026)

An isolated regression package now lives in `validation/qa-suricata-last-two/` with **nine inert PCAPs**, SHA-256 manifest, a stdlib Python test runner, and real Suricata 8.0.1 execution results. The runner generates a temporary 333-rule candidate; it does not alter published or installed rules.

- `9005017`: `http.uri.raw` detects the absolute-form WebSocket sample, while origin-form, absent Upgrade and missing key remain negative. **Possible legitimate forward-proxy WebSocket false positives** require review because the sensor alone does not establish the target is a vulnerable self-hosted Next.js server.
- `9005055`: test-only 100-repetition PCRE with a **128-byte** greedy gap detected complete multipart samples with 100 and 105 empty filename fields. The 99-field, nonempty-filename and wrong Content-Type controls were negative. Greedy bounds of 160–1024 bytes failed on the same representative fixture with the stock PCRE budget. The shorter bound may **miss larger or differently formatted multipart payloads**; it is not demonstrated as generally equivalent to the original 4096-byte condition.
- **Nine of nine targeted engine tests PASS**, candidate `suricata -T` PASS, exactly two temporary detection lines differ and the other 331 original signatures remain unchanged. No on-sensor Alert from either revised original SID was counted.

Recheck the risk of protocol-specific false positives, PCRE resource use and alternate real payload layouts before any release or reimport. Current **331/333 real-sensor results remain unchanged**.

## Extended candidate risk assessment (November 9, 2026 KST)

The deterministic QA suite now verifies **13/13 expected observations on Suricata 8.0.1**, explicitly with `release_ready: false`.

1. `9005017`: normal-shaped HTTP and HTTPS WebSocket absolute proxy requests each produced an Alert despite the absence of specific Next.js SSRF exploit evidence. The candidate cannot differentiate these legitimate-shaped proxy uses. Advisory: https://github.com/advisories/GHSA-c4j6-fc7j-m34r.
2. `9005055`: valid multipart requests containing 100 or 105 empty file fields and extra MIME headers both failed to alert with the 128-byte bound. A shorter PCRE bound is not equivalent to broad detection coverage.

A 100-session compact multipart isolated test produced 100 candidate alerts versus 0 original alerts; CPU user time 0.70 vs 0.67 seconds. **This is not a sustained performance benchmark.** Generator and evidence live under `validation/qa-suricata-last-two/`.

**Disposition: BLOCK_RELEASE** for both candidate edits. Public v1.0, installed sensor, 331/333 verification count, and built-in ETPRO signatures remain unchanged.

### Additional PCRE architecture experiments

Five negative-lookahead variants of the 4096-byte repeated filename pattern failed Suricata PCRE2 compilation with "regular expression is too large". Two DEFINE/subroutine-based PCRE variants compiled but did not alert on either compact or wide-gap 100/105-field fixtures. This further supports not publishing an unproven rewrite. Sensor-side QA artifacts are under `/tmp/modular-suricata-333-validation-20261108/risk-controls-20261109/` (`php-tempered-results.json`, `php-subroutine-test-results.json`).

The production sensor config and existing custom rules were never modified.

## Latest 24-case QA candidate (November 9, 2026 KST)

The original 333-rule v1.0, live modular configuration and ETPRO signatures
remain unchanged. The preceding 9-case/13-case and 100-session resource
figures are historical results for prior experimental candidates, not
claims for this later structured MIME implementation.

- The current 9005017 **test-only** rule uses a raw absolute URI, GET method,
  an anchored HTTP/HTTPS regex and single/double percent-encoded slash support.
  Two normal-shaped WebSocket forward-proxy controls still produce Alerts;
  this is a **known non-specific/false-positive release risk**.
- The current 9005055 **test-only** rule counts at least 100 structurally
  formatted empty-filename MIME parts with bounded per-part header and
  single-line body matching. Both original wide-header adversarial fixtures
  now alert, along with normal compact forms. A valid 105-part multipart
  request with multiline file content does **not** alert, demonstrating a
  **known incomplete-coverage/false-negative release risk**.
- All 24 SHA256-verified offline PCAPs passed Suricata 8.0.1 actual
  per-SID alert expectations with temporary 333-rule copy and only
  those two SID lines changed. The runner returns release_ready=false,
  release_status=BLOCKED_BY_KNOWN_FP_AND_FN_RISKS.
- The exact sensor runner evidence is in
  validation/qa-suricata-last-two/suricata-8.0.1-results.json
  (SHA256 a1d259a3ec14e8edfd440950df6f6f4c656fd243e41c2ee092dd2a86b959cb11).

Neither test candidate is ready for general distribution or live import.
**331/333 original real sensor Alerts** remains the supported public metric;
no QA-only candidate Alert is included.

## QA security-gate hardening and structured-rule measurement

The QA test runner now evaluates **behavioral-regression success
separately** from safe release acceptance, with required benign proxy
and valid multiline-form witnesses. On modular / Suricata 8.0.1:
24/24 expected offline rule matches PASS, **security acceptance BLOCKED**
with two potential false-positive proxy alerts and one multipart
false-negative witness (see
validation/qa-suricata-last-two/suricata-8.0.1-security-acceptance.json).
The Python stdlib policy contract has 5 passing unit tests.

For the same inert 100-session compact multipart PCAP, the original SID
9005055 generated zero alerts while the structured-MIME QA candidate
generated 100. CPU user was 0.70s/0.69s and RSS 88776/89388 KB for
original/candidate respectively, in a single isolated replay. See
validation/qa-suricata-last-two/suricata-8.0.1-structured-stress100.json.
These figures do **not** establish sensor throughput or deployed safety.

The operating sensor uses Suricata 8.0.1; OISF identifies its separate
HTTP Content-Disposition parsing DoS vulnerability CVE-2026-45759 as
patched in 8.0.5:
https://github.com/OISF/suricata/security/advisories/GHSA-cfq5-g2v5-6652
A runtime upgrade would require separate maintenance authorization;
none was attempted during QA. Original v1.0 release and 331/333 live
sensor validation remain unchanged.
