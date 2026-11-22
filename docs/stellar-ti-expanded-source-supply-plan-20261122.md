# Stellar Cyber OSINT TI: expanded real-source supply plan (2026-11-22)

## Product decision

Build a continuously updated threat-intelligence *curation service*, NOT a mirror of 40 public blocklists. The machine-readable 41-source audit is at [osint-source-catalog.json](../validation/agentic-20261122/osint-source-catalog.json). Catalogue admission is separate from source reachability, redistribution rights, individual IOC credibility and customer deployment. Today's authorized work is confined to a Draft PR and isolated GitHub Actions QA artifacts.

The Stellar Cyber built-in Proofpoint/ET, OTX, URLhaus, PhishTank and OpenPhish feeds must be inventoried in the specific customer tenant and deduplicated by IOC type/value/source. Never claim zero overlap from a provider name alone.

## Coverage beyond network IPs

| Detection domain | Evidence types | Primary usable candidates | Secondary / licensing and quality constraints |
|---|---|---|---|
| Phishing, banking fraud, smishing | active domain, full URL, last-added and removal | CERT Polska currently active 24h new domains | PhishDestroy PRIMARY HTTP content-verified 12h; large list needs per-entry freshness/delta and commercial source provenance check |
| Crypto wallet drainers and Web3 phishing | phishing domain with victim brand and content signals | PhishDestroy original primary content (pending isolated source verification) | MetaMask eth-phishing-detect updates but its DBAD license needs legal review; do NOT republish it by default |
| Real exploitation, web attacks, RDP/SSH/DB intrusion | source IPv4, last_seen, concrete attack taxonomy, sensor count | OffSeq Mirage recent high-impact multi-sensor, Jacobrakai original credential/loader sensor | emth361h honeypot date granularity, xfeeds clean independent votes, ReportedIP 48h-delay |
| Malware C2 and distribution | dedicated C2 domains/IP, payload URL, malware family | OffSeq original payload URL stream as research; highly curated live observed domains where verified | ThreatFox/MalwareBazaar commercial API rights, C2IntelFeeds noncommercial, static ARTEX IP snapshot; exclude until reviewed |
| File hashes and ransomware loader artifacts | SHA256 plus sample provenance, classification, first observed | No independent commercial-use+live-hash provider admitted to strict pipeline yet | codelake confirmed-malicious package hashes (availability probe), MalwareBazaar paid commercial API, attributed Cobalt Strike tracker (license/recency pending) |
| Software supply chain | malicious OSV package version, compromise indicators | OpenSSF malicious-packages (open data, actively maintained); use for software risk context | Codelake package-derived hashes/C2 links; verify accessible feed and per-package evidence before Stellar TIP admission |
| AI/agentic offensive tooling | signature of tool behavior; infrastructure IOC with last_seen | Existing 398-rule Suricata QA, 43 upstream already integrated | ThreatDefence report date != last_seen; Cisco Talos historical IP hunt only |
| Exploitation CVEs / emerging vulnerabilities | observed exploit CVE, EPSS, KEV, technical signatures | OffSeq exploited CVE telemetry, CISA KEV, FIRST EPSS | Not direct Stellar 4-column IOC; feed a correlation/hunting system instead |
| Korea-specific phishing, C2, smishing | reported IP/domain/hash | KISA C-TAS institution/member APIs where licensed | Member/organization use ONLY, no default global commercial redistribution |
| Scanner and shared-infrastructure exclusions | known research scanners, CDN, proxy/Tor, legitimate SaaS | OffSeq published known scanner list; MISP warninglists | Classification filters, NEVER issue a malicious verdict simply for VPN/Tor presence |

## First three autonomous QA collectors (actually live tested)

1. CERT Polska: owner-validated commercial-use permission. Collect currently active domains first added within 24h. Do not automatically conflate DNS resolution with verified malicious HTTP content.
2. OffSeq Mirage: IP last_seen under 24h, score at least 85, at least 3 sensors and 2 independent networks, high-impact exploitation/ransom/shell/SIP-fraud behavior, exclude research scans/VPN/Tor/CGNAT and validate publisher SHA256 snapshots.
3. Jacobrakai original honeypot: 24h observed IP, malware loader or repeated credential attack, no scanner-only. Verify JSON-vs-CSV exact IP/tier/last_seen consistency. CC0.

At 2026-11-22 06:11 UTC GitHub Actions sampled 9 OffSeq and 14 Jacobrakai qualifying source records, zero overlap, and 441 CERT Polska domains. After a later precision guard, the 14 Jacob-only credential IPs are held in HUNT-ONLY instead of being promoted to Stellar TIP; newly observed loader events or corroborated IPs remain eligible. This reduces the strict attack-IP candidate feed to 9 in this snapshot, subject to exact-head CI confirmation. All are QA ONLY; *no true-positive precision measurement or Proofpoint OEM-content overlap data has been measured*.

The original ThreatDefence 514 and Talos 2546 historical snapshots are maintained as research/hunting-only. They are excluded from the strictly-live customer candidate TSV.

## Next eligible source adapters — not silently activated

* PhishDestroy original primary/content-verified (CC0 dataset): a live daily/hourly publisher, HTTP content re-verification every 12 hours. Do not forward its entire tens-of-thousands-of-domains dataset into Stellar TIP. Admit only with per-indicator verified current content, a bounded daily delta and strict OEM overlap. Community-derived list rights need separate review.
* Codelake supply-chain IOC provider: first-party package/version-attributed malicious domains, IPs and hashes. Publisher advertises commercial use and hourly beta, but direct endpoints must be reachability-tested; a dated webpage sample is not recent evidence.
* DNSBunker CTI: claims CC0, frequent publication and own detection. Millions of domains with huge daily additions are NOT evidence of comparable precision. Use as context only until independent precision and per IOC timestamps.
* xfeeds clean: provider publishes a commercial-rights-clean derivative tier and independence-weighted confidence, useful corroboration rather than stand-alone observed attack ground truth.
* OpenSSF malicious-packages: Apache-2.0 curated OSV advisory stream; CVE/package records are NOT Stellar TSV types. Use for file/software exposure enrichment and hunting.
* Commercial-quality upgrade: when explicitly licensed, ThreatFox/MalwareBazaar, GreyNoise for scanner suppression, and KISA C-TAS customer-only context can materially improve coverage; do not use their APIs/feeds for OEM until terms are verified.

See the machine-readable catalogue for all 41 investigated source IDs, including built-in, license-pending, snapshot/stale, research, and customer-only classes.

## Proposed customer-facing deliverables

- One HTTPS Custom TSV IP feed with source score and per-source provenance sidecar; expire IPs when last malicious observation is beyond source TTL.
- One HTTPS Custom TSV domain feed from current active verified phishing/crypto-drainer operators; support removals/rapid expiry; keep full URL feed separate only for full path-specific malicious URLs.
- One high-specificity file SHA256 feed only after live, licensed hash evidence is available; stale but confirmed immutable malware hashes can use a much longer TTL than IP infrastructure.
- One versioned and independently QA tested Suricata custom rule bundle, never automatically copied from upstream into live sensors.
- One richer TAXII 2.1 / sidecar evidence API for first_seen, last_seen, confidence, source/campaign, license and review decisions; test Stellar TIP object acceptance before claiming TAXII enrichment parity.
- Signed manifests (Ed25519) and SHA256 per feed, TLS certificate validation, origin Basic Auth, allowlisted host, freshness alarm, immutable provenance and rollback detection. Stellar Cyber polls validated HTTPS files; it does not independently verify our detached signatures.
- Customer-specific built-in-source overlap and incremental novelty reports: the numerator is ONLY indicators not already present in that customer's Proofpoint/ET/other feeds, not simply new entries in our sources.

## Gate to production

1. Licensing and resale rights established separately from code license (written permission where required).
2. Source heartbeat and actual per-item last_seen/current-active health, not GitHub push activity.
3. At least one primary observed malicious behavior or documented authoritative verification, plus false-positive screening.
4. Bounded per-source scores and TTL; no records without expiry policy.
5. Exact-head CI, real benign/attack traffic replay, false-positive telemetry and source drop/removal semantics validated.
6. Stellar DP Custom TIP ingestion, disappearance/retention behavior, enrichment matches and modular Sensor to DP Alert/Case E2E.
7. Authorized public release and production feed import.

The source availability probe at tools/probe_ti_candidates.py checks only vetted publisher metadata and whether optional URLs serve bytes; it never visits IOC destination domains or alters the tenant. A successful HTTP response alone does not qualify a threat feed.
