AI 지원 공격 탐지 룰 — v1.1 (2026-11-18)
==========================================
Stellar Cyber Open XDR 7.0 / Suricata 8.0.1

전체 파일: local-web-attack-ai-v1.1-339.rules
룰 개수: 총 339개 (기존 333개 원본 보존 + Java4Shell 6개 추가)
SHA-256: 2478ffd6b3dbdfbb527695f07e00e1a106a554d8bb898a0f9584bb3845b07483
신규 SID: 9006101-9006106

실제 Modular Sensor의 Suricata -T에서 전체 339개 구문 로드 성공,
오프라인 PCAP 재생으로 신규 6개 개별 SID 탐지 및 10/10 샘플 확인.
기존 333개 중 실시간 센서 Alert 개별 확인은 331개이며,
미재현 SID 9005017/9005055의 검증 상태는 변경되지 않았습니다.

신규 6개 룰은 운영 IDS에 적용하지 않았으며, 실시간 수집 또는
Data Processor UI에서의 Alert 검증을 완료했다는 의미가 아닙니다.
이 결과는 운영환경의 탐지율/오탐률을 나타내지 않습니다.

Stellar Cyber Import Security Rules는 custom_defined.rules 파일을
전체 교체하므로 기존 룰을 백업하세요. 추가 6개 파일만 단독으로
임포트하면 안 됩니다. HTTP 페이로드 탐지에는 평문/복호화
트래픽이 필요합니다.

검증 스크립트 및 참고:
https://github.com/xdr-labs/xdr-labs-portal/tree/main/validation/java4shell-20261118
