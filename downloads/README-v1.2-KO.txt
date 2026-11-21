AI 지원 공격 탐지 v1.2 (2026-11-21)
Stellar Cyber 7.0 - Suricata Alert 룰 383개 통합.
기존 339개 원본 보존 및 신규 44개(전용 30 + 확장 헌팅 14) 단일 파일.
그룹: ARTEX/연관 지표 14, CyberStrikeAI 9, HexStrike 6, PentAGI 6,
Cairn 3, 일반 AI/OAST/WSUS 헌팅 6.
파일: local-web-attack-ai-v1.2-383-rc1.rules
SHA-256: 0cb8e39aef5251f28d0a12354797c2068812bdb6d9be8ec911fb43baee1f4d92
Suricata 7.0.3/8.0.1 격리 환경: 전체 로딩, 49/49 합성 PCAP,
신규 SID 44/44; Java4Shell 회귀 10/10 PASS.
실운영 Sensor 적용 및 DP/Case E2E 미검증; 운영 오탐률/탐지율 아님.
기존 미해결 SID 9005017/9005055 위험 유지.
주의: 14개 확장 헌팅은 정상 AI 개발·진단·관리 트래픽도 탐지 가능.
Import Security Rules는 기존 custom_defined.rules 전체 교체.
https://xdr.ooo/ko/products/ai-assisted-attack-detection-rules
