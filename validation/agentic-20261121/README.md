# Stellar Cyber Agentic Attack 383-rule combined candidate — 2026-11-21

## Unified rule file
- `downloads/local-web-attack-ai-v1.2-383-rc1.rules`: **339 existing rules, unchanged byte-for-byte; 44 new agentic rules in the same .rules file**.
- New SIDs `9876001-9876030` (30 framework-specific) and `9876101-9876114` (14 broader / hunting indicators). All 44 are enabled in this **QA candidate**.
- License: upstream ThreatDefence MIT. This repo also retains its existing AIPT and ET Open notices. `source-map.csv` documents the original SID mapping.
- We did not convert Elastic's multi-event velocity/correlation analytics into a packet signature. Those require Stellar Cyber ATH.
- This commit replaces the old split 369+14 candidate with one unified 383 signature file. No production import, release, or website downloads were changed.

## Verification
```bash
python3 validation/agentic-20261121/run_offline.py --static-only
python3 validation/agentic-20261121/run_offline.py
```
Additional engine tests are performed by CI for Suricata 7.0.3 and containerized 8.0.1. Synthetic PCAP coverage is not proof of production precision. Previous 331/333 source signature live-sensor observations and two unresolved SIDs remain unchanged.

## Risk and applicability
- The 14 newly included hunting signatures can flag legitimate developer agents, WebFetch, security scanners, OAST services, PentAGI updates and administrative endpoints.
- Distinguish alert-generation from automated blocking: all 383 rules use `alert`, no `drop` or `reject`.
- HTTPS bodies and HTTP headers require decrypted traffic. DNS over HTTPS and ECH also reduce visibility.
- On Stellar Cyber, `Import Security Rules` **overwrites the whole** `custom_defined.rules`. A Sensor-specific backup/merge and lab confirmation are mandatory.
- User's request to merge all 44 into one file is complete at RC level; production publication or installation remains separate.

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
