# Stellar Cyber Agentic Attack QA Candidate — 2026-11-21

- **Candidate**: `downloads/local-web-attack-ai-v1.2-369-rc1.rules` = exact v1.1 339 rules + 30 new agentic framework alerts.
- **Optional**: `agentic-hunting-optional-14.rules` = additional 14 low-specificity hunt rules, intentionally **not merged**.
- **Sources**: [ThreatDefence agentic-attack-detections](https://github.com/ThreatDefence/agentic-attack-detections), MIT license; source-to-local SID map in `source-map.csv`. Detection design context: Elastic Security Labs.
- **Scope**: ARTEX, CyberStrikeAI, HexStrike, PentAGI, Cairn, related campaign DNS/TLS.
- **Safety**: no blocking actions, only inert HTTP strings in synthetic PCAPs.
- **Behavioral correlation is not covered**: Elastic's 60-second 3-tool/20-request logic needs Stellar Cyber ATH/multi-event aggregation, not these packet signatures.
- **Previous QA is preserved**: 331/333 historical sensor alerts confirmed, 2 original source SIDs unresolved; Java4Shell +6 offline verification separate. Never report these as newly reverified.

## Offline tests
```sh
python3 validation/agentic-20261121/run_offline.py --static-only
python3 validation/agentic-20261121/run_offline.py
```
The second command needs the Suricata executable and default Suricata configuration. CI uses an isolated Ubuntu runner; actual Modular Sensor Suricata 8.0.1 and Stellar Cyber Alert/DP UI remain unverified.

## Deployment guardrails
Do **NOT** publish or deploy this RC automatically. Stellar Cyber *Import Security Rules* replaces the **whole** `custom_defined.rules` content. Back up any site-local additions and merge prior rules. Test specific Suricata runtime and validate HTTP cleartext/decryption visibility, SNI/ECH limitations, historical IOC false positives, and 14 optional rule FP baseline before enablement.

## Attribution / license
MIT License

Copyright (c) 2026 ThreatDefence Pty Ltd

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

