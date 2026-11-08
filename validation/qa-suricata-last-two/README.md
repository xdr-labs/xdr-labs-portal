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
