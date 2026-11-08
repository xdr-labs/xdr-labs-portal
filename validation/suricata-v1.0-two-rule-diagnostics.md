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
