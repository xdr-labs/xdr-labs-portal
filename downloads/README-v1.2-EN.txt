AI-Assisted Attack Detection v1.2 (2026-11-21)
Stellar Cyber 7.0 - Suricata 383 integrated alert-only signatures.
339 prior rules preserved byte-for-byte; 44 new (30 targeted + 14 extended).
New families: ARTEX incl. campaigns 14, CyberStrikeAI 9, HexStrike 6,
PentAGI 6, Cairn 3, general AI/OAST/WSUS hunting 6.
All 44 included in ONE file: local-web-attack-ai-v1.2-383-rc1.rules.
SHA256: 0cb8e39aef5251f28d0a12354797c2068812bdb6d9be8ec911fb43baee1f4d92
Isolated Suricata 7.0.3 & 8.0.1: 383 loaded, 49/49 synthetic PCAP
cases and 44/44 new SIDs per engine. Java4Shell 10/10 regression.
NOT deployed to a live Modular Sensor or validated in DP/Case;
no production detection/FP claims. Previous 9005017/9005055 unresolved.
WARNING: 14 broad rules may alert on benign AI dev tools, OAST, admin.
Back up custom_defined.rules: Stellar Cyber import replaces it entirely.
Details: https://xdr.ooo/products/ai-assisted-attack-detection-rules
