AI 지원 공격 탐지 룰 v0.8 (2026-11-08)
========================================

파일: local-web-attack-ai-v0.8-full.rules
룰 수: 322개 (alert 전용)
대상: Suricata 8 호환 IDS 환경, Stellar Cyber 7.0 테스트 센서
주소 조건: any any -> any any

SHA-256
056c70389580c69431351dc287352e6f6836969aca8e2eba47ed6b30f19f6dbb

검증
- Suricata 8.0.8 전체 룰 로딩: PASS
- 합성 공격 PCAP: 12/12 탐지
- 합성 정상 PCAP: 7/7 무경고
- 실제 Stellar Cyber 센서 Import: 미검증

적용 주의
1. 기존 custom_defined.rules와 설정을 먼저 백업하세요.
2. Stellar Cyber Sensor Profile에서 IDS 활성 ET 룰을 확인해 중복 탐지를 검토하세요.
3. 테스트 센서에서 룰 Import 및 alert 발생 여부를 확인하세요.
4. HTTP URI/본문 탐지는 평문 트래픽 또는 복호화가 필요합니다.
5. 이 룰은 AI 모델을 사용하지 않으며 정적인 네트워크 탐지 시그니처입니다.
6. 검증된 소수의 합성 PCAP 결과가 전체 탐지율을 보장하지 않습니다.

공개 룰 원본
- https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz
- https://github.com/theori-io/aipt-detections

라이선스와 저작자 고지는 .rules 파일에 포함되어 있습니다.
