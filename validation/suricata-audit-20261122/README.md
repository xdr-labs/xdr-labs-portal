# Suricata 383-rule full audit and risk-witness reproducibility

**Reference:** the public v1.2 unified 383-rule file, SHA-256 `0cb8e39aef5251f28d0a12354797c2068812bdb6d9be8ec911fb43baee1f4d92`. This audit is read-only: it must **not** alter the 383 rules, downloadable ZIP, site pages, deployed Sensor configuration, or DP.

## Full per-SID inventory and evidence truth

Run `python3 validation/suricata-audit-20261122/audit_inventory.py`. The checked-in `inventory-383.csv` contains one row for **each of the 383 actual SIDs** with protocol, description, verification-source type and any observed or hypothesized risk. Statuses must remain distinct:

| Evidence group | SIDs | Meaning |
| --- | ---: | --- |
| Initial original rules | 331 | Historical individual live Modular Sensor EVE Alert observed in the November 2026 controlled lab; **not freshly re-run as 331 PCAPs against v1.2 in this audit** |
| Initial original unresolved | 2 | `9005017`, `9005055` — not live-reproduced, FP/FN risks documented |
| Java4Shell v1.1 | 6 | Historical Sensor offline PCAP fixtures (10/10) plus current CI regression |
| Agentic additions v1.2 | 44 | Current isolated Suricata 7.0.3 and 8.0.1 per-SID synthetic PCAP positives (49/49 including 5 benign controls) |

Full 383-rule `suricata -T` checks on both 7/8 assert syntax/keyword load, **not** individual behavioral detection for 383 SIDs.

## Duplicates / false-positive and attribution findings

- **Three OAST pairs overlap**: existing `9006065` with new `9876109` (`interact.sh`); `9006064` with `9876110` (`oast.fun`); `9006067` with `9876111` (`burpcollaborator.net`). A single authorized OAST lookup can generate duplicate Alerts. The new signatures have different source/threshold scopes; they are not text-identical, but their matched events overlap.
- `9876104` is **port-only**: any established outbound TCP flow destined for 28000–29999 can Alert regardless of PentAGI evidence.
- `9876107` and `9876108` detect **legitimate Claude Code and Qwen Code User-Agents**; `9876101` `norma/0.4` is a non-exclusive client fingerprint.
- `9876102/03`, `9876112`: generic management/WSUS URL patterns can Alert for legitimate use. `9876105/06`: ordinary PentAGI update DNS/SNI can Alert; suffix-boundary near-miss cases are included to study lookalike false positives.
- `9876029/30` are named **BLOODALCHEMY/VAPOR PANDA** in rule metadata yet include an unverified `(ARTEX campaign)` label. Do not represent the domain detections as proof of ARTEX attribution. `9876114` references older Gh0stRAT-related infrastructure, not necessarily ARTEX.
- `9876024/25` can both trigger for one PentAGI certificate, which is valid multi-signal detection but can create two Alerts.
- The two original outstanding SIDs `9005017` (absolute URI normalization/ordinary WebSocket proxy FP on modified candidates) and `9005055` (100 multipart file PCRE FN/budget limitation) remain unaccepted. Their **test-only modifications** are not in v1.2.

## What is tested now

- Entire 383 individual SID *inventory* and fingerprints cross-reconciled against v1.0/v1.1 history, v1.2 source and full public CSV.
- Isolated Suricata 7.0.3/8.0.1 syntax and each of 44 new SID synthetic positive fixtures, five benign controls.
- Six Java4Shell rules with 10 current PCAP fixtures on Suricata 7.0.3.
- **20 additional benign-looking/near-miss HTTP, TLS SNI, DNS and TCP risk scenarios on both Suricata 7/8**: risk-positive witnesses are expected to alert and are not counted as FP acceptance.
- **13 historical risk PCAPs against the exact unchanged public 383 rules** on all tested engines, recording original SIDs `9005017`/`9005055` without claiming their false-negative limitations have been fixed. Previous test-only modified-SID evaluations remain historical evidence, not a release candidate.
- The 331 historical per-SID input PCAPs were created on the prior controlled Sensor and are not stored in this repository. They cannot be independently re-executed against current v1.2 while the Sensor development host is unavailable. Report this limitation explicitly.

For local execution (Suricata 7/8 installed):
```sh
python3 validation/suricata-audit-20261122/audit_inventory.py
python3 validation/suricata-audit-20261122/risk_witnesses.py
python3 validation/suricata-audit-20261122/replay_original_legacy.py
```

**Interpretation:** a PASS for risk witnesses means the *dangerous match can be reproduced*, not that operating deployment is approved. All 383 remain unified and `alert`-only; no automatic blocking. Publication and Sensor deployment are out of scope for this audit.

**Audit acceptance:** explicit review required for low-specificity indicators, overlap, existing two SIDs and live Modular Sensor + DP E2E. This audit provides deterministic evidence and does not imply `release_ready=true`.

## Engine security note (not caused by the signatures)

The laboratory Sensor-compatible Suricata **8.0.1** is within the affected range for OISF's [GHSA-cfq5-g2v5-6652](https://github.com/OISF/suricata/security/advisories/GHSA-cfq5-g2v5-6652), a high-severity HTTP header parsing DoS. OISF fixed it in **8.0.5** (or 7.0.16). Suricata **8.0.8** is the published stable version as of November 22, 2026 (October 29 release); the CI therefore also performs signature, individual new SID, normal/risk-witness and old-legacy observation tests on 8.0.8. This is **not an instruction to upgrade a Stellar Cyber-managed Sensor independently**: vendor-supported component upgrades require their own compatibility and maintenance approval.

**100-session stress measurement note:** CI wall-time and RSS counters describe the host Docker invocation/client. They are not measurements of the containerized Suricata engine's peak resident set or sustainable EPS; only successful bounded PCAP completion is asserted.

## 2026-11-22: actual Modular Sensor 8.0.1 exhaustive offline revalidation

**New authoritative offline evidence**, collected directly from connected DRLink host `AT Secu MDS` (hostname `modular`). No published signature, running IDS service or `/etc/suricata/rules/custom_defined.rules` was modified. All `-S` candidate loads, `-r` PCAPs and `-l` EVE logs were isolated under `/tmp/suricata-383-revalidation-20261122` on the authorized Sensor. Running operational file still has SHA-256 `5947a64a6b45ee122537a1ea166ebf383307302cf210b63d24b350b0df98eb96` (v1.0 333). Candidate SHA matches the published 383 file.

**Result: 381/383 distinct SIDs produced an Alert on the actual Sensor engine using controlled, offline PCAPs**: original v1.0 **331/333**, Java4Shell **6/6** (10/10 PCAP cases), Agentic Attack **44/44** (49/49 PCAP cases: 44 positive + 5 benign). Two original SIDs `9005017` and `9005055` remain unreproduced and not release-accepted; separately observed in 24 targeted legacy PCAPs with zero hits.

- **77 legacy curated PCAPs, 154 independent comparator executions**: the 333-rule operational baseline and 383-rule candidate triggered the same 331 original SIDs, with **zero per-PCAP original-rule Alert regressions** and zero execution errors. Mixed multi-PCAP directory replay had some threshold-state nondeterminism, so this assertion uses separate processes for every source PCAP and each candidate/baseline.
- **44 new per-SID positives**, **5 benign controls**, and **10 Java4Shell boundary regressions** all passed on actual Sensor 8.0.1.
- **20 benign/near-miss scenarios** replicated OAST duplicate Alerts (three pairs), port-only PentAGI Alert, normal Claude/Qwen User-Agent Alerts, broad API/WSUS signatures, and `notupdate.pentagi.com` suffix lookalikes triggering `9876105/6106`.
- Evidence files in this PR: `sensor-383-summary-20261122.json`, `sensor-383-per-sid-20261122.csv`. They contain only SID-level metadata and counters; **no captured PCAP or sensitive packet content is published**. `verify_sensor_evidence.py` asserts provenance, exact rule SHA and each SID's observed state.

**Acceptance boundary:** 381/383 is detection reproduction on a live *Sensor appliance's isolated offline engine*, **not** deployment of v1.2 into live capture, not Data Processor UI/Case E2E and not a real-traffic false-positive or false-negative rate. **No production sign-off.**
