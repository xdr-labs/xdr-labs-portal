AI 지원 공격 탐지 룰 v0.9 (2026-11-08)
========================================

Stellar Cyber 7.0 테스트 환경용 Suricata 룰
- 전체 333개: 기존 v0.8 322개 + 신규 11개
- 모두 alert 전용 / any any -> any any
- Lab-validated candidate: 실제 Stellar Cyber 센서 Import는 미검증

파일: local-web-attack-ai-v0.9-validated-333.rules
SHA-256: 8b902126044224089cd367a47c58c98290563f0816972272086fb79e8b1c77a6

검증:
- Suricata 8.0.8 -T --init-errors-fatal: PASS
- 19종 PCAP x v0.8/v0.9 비교: 38/38 실행 PASS
- 신규 SID 11/11 합성 패턴 매칭 성공
- OAST DNS: 실제 도메인 4/4 탐지, 유사 도메인 4/4 무경고
- 추가 정상 의도 146세션: 기존 대비 신규 경고 없음
- 이전 v0.8과 동일한 정상 HTML 예시 경고 1건은 그대로 존재
- 공식 OISF SMB/DCERPC/Kerberos PCAP 10종: 기존 탐지 결과와 동일

주의:
1. Import는 기존 custom_defined.rules 전체를 교체할 수 있으므로 백업하세요.
2. 실제 센서의 Suricata 버전, 앱 프로토콜 지원, 기본 IDS SID와 중복을 확인하세요.
3. OAST DNS는 승인된 모의해킹 도구 사용 시에도 발생합니다.
4. HTTPS 페이로드 탐지는 평문 또는 외부 복호화가 필요합니다.
5. AD 공격(DCSync/PsExec/Kerberoasting 등) 신규 룰은 오탐 구별 실패 가능성으로 제외했습니다.
6. AI 모델은 포함되지 않으며 도구 지문 시그니처는 회피 가능합니다.

이전 v0.8 (322개) 다운로드도 별도로 유지됩니다.
출처 및 라이선스는 .rules 파일 상단에 포함되어 있습니다.
