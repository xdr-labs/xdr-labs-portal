# Suricata v1.0 — final two SID isolated QA and release-risk gate

These tests are offline-only and are not installable detection rules.
Public v1.0 and the installed sensor retain all 333 original signatures;
331/333 original live SID Alerts are verified. SID 9005017 and SID 9005055
are the two remaining original unverified rules.

## QA-only candidate changes

- 9005017: use a raw absolute HTTP/HTTPS URI, GET method, corrected
  percent-encoded-slash regex and existing WebSocket headers. Ordinary
  benign-shaped HTTP/HTTPS WebSocket proxy requests ALSO trigger it.
  This is a known non-specificity and false-positive risk witness.
- 9005055: use a structured MIME Content-Disposition/empty filename,
  bounded additional MIME header lines, a single-line body of up to
  4096 bytes, and a subsequent part boundary, repeated 100 times.
  The candidate detects compact and long-header 100/105-part requests,
  empty bodies, omitted Content-Type, variable boundary and lowercase
  Content-Disposition. VALID multipart with multiline file-part content
  can still fail detection, confirmed with a 105-part fixture.

The runner must always return release_ready=false and
release_status=BLOCKED_BY_KNOWN_FP_AND_FN_RISKS. A passing regression
case is not a successful original live sensor Alert.

## Run

Static SHA256, 333-SID and fixture validation:

    python3 validation/qa-suricata-last-two/run_offline.py

Offline Suricata 8.0.1 engine validation (no packets sent):

    python3 validation/qa-suricata-last-two/run_offline.py --run --suricata /usr/bin/suricata --config /etc/suricata/suricata-aelladata.yaml --report /tmp/suricata-last-two-results.json

The QA test runner builds a temporary 333-signature copy, modifies only
the 2 targeted SIDs, runs Suricata syntax validation, hashes 24 PCAP
fixtures and checks the expected SID-specific EVE Alert counts.

## Test coverage and risk records

The combined 24-case suite has 9 Next.js URI/handshake positive and
negative controls, 11 MIME compact/wide/99/100/105/headers/boundary/body
cases, two benign WebSocket proxy positives that indicate a release-risk
false positive, and two older wide-gap MIME fixtures that DO match with
the newer structured-MIME candidate.

The historical suricata-8.0.1-risk-assessment.json and
suricata-8.0.1-stress100.json capture the earlier 128-byte-wildcard
candidate's evasion and small benchmark results, NOT the updated
structured-MIME candidate's performance. Preserve them as a past
risk-finding record but never claim they evaluate the new regex.

No user-facing detection count, distributed ZIP/rules, live Suricata
configuration or ETPRO signatures changed. Remaining work includes
benign WebSocket proxy false-positive discrimination, multiline body
coverage, real sustained PCRE throughput, and an independently
approved release/deploy process. The current candidates are
NOT release ready.
\n## Security acceptance is separate from replay success

The fixture comparison may report 24/24 behavioral regression PASS while
security acceptance remains **BLOCKED**. The runner computes
security_acceptance.status and security_failure_count directly from three
must-fix witnesses: benign HTTP/HTTPS WebSocket proxy Alerts (two false-
positive risks), and the valid 105-part multiline-body multipart miss
(one false-negative risk). The expected *safe* outcomes are tracked
separately from currently observed behavior. The status can at best advance
to REQUIRES_MANUAL_REVIEW in QA; it can never grant production release.

Run the stdlib policy unit tests without a sensor:

    PYTHONDONTWRITEBYTECODE=1 python3 validation/qa-suricata-last-two/test_security_acceptance.py

Full Suricata replay is still required for observed results. This prevents
a misleading 24/24 regression green check from implying that either
candidate is production-ready.

## Sensor software version

The controlled test sensor runs Suricata 8.0.1. OISF advisory
GHSA-cfq5-g2v5-6652 / CVE-2026-45759 identifies an unrelated
HTTP Content-Disposition CPU denial-of-service affecting Suricata
versions below 8.0.5 (patched in 8.0.5). Any sensor upgrade is
a separate authorized maintenance task; this QA does not modify it.
Source: https://github.com/OISF/suricata/security/advisories/GHSA-cfq5-g2v5-6652

## Current QA security verdict and limited structured-rule resource comparison

On modular, Suricata 8.0.1, the exact 24-case engine runner produced
**behavioral_regression=PASS (24/24)** but
**security_acceptance.status=BLOCKED (3 security failures)**.
The three observed release blockers were two benign-shaped WebSocket
proxy Alerts and one valid 105-part multiline multipart request that
failed to trigger the PHP candidate. See
suricata-8.0.1-security-acceptance.json for the exact observed/safe
comparison and hashes.

A single isolated 100-session compact multipart PCAP replay produced
0 original PHP SID alerts and 100 QA-only structured-MIME PHP SID alerts.
Original vs candidate: CPU user 0.70s vs 0.69s, elapsed 0.65s vs 0.65s,
peak RSS 88776 KB vs 89388 KB. See
suricata-8.0.1-structured-stress100.json (sha256
8e9a5da64359399f6ba750d85c8421b453142f368f2d211fc3d7cb7c750c00db).
These single-process measurements include startup overhead and are
**not sustained throughput, a load safety certification, or evidence of
real-world attack detection accuracy**.

The official Next.js advisory
https://github.com/vercel/next.js/security/advisories/GHSA-c4j6-fc7j-m34r
limits CVE-2026-44578 to affected self-hosted Node.js server versions;
a WebSocket URI and header match alone cannot establish this exposure.
The official PHP advisory and AWS response guidance likewise describe
multiple memory-exhaustion paths, not just empty-filename multipart parts:
https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
https://aws.amazon.com/blogs/security/using-aws-waf-to-apply-mitigations-for-php2shell-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619/
