AI 지원 공격 탐지 룰 v1.0 (2026-11-08)
========================================

Stellar Cyber 7.0 테스트 환경용 Suricata 룰
- 총 333개 탐지 룰 · 실센서에서 315개 개별 SID Alert 확인
- 모두 alert 전용 / any any -> any any
- 실제 Stellar Cyber 7.0 Modular Sensor(Suricata 8.0.1) Import 및 IDS 탐지 확인

파일: local-web-attack-ai-v1.0-333.rules
SHA-256: 5947a64a6b45ee122537a1ea166ebf383307302cf210b63d24b350b0df98eb96

검증:
- Suricata 8.0.8 -T --init-errors-fatal: PASS
- 19종 PCAP x 기준 룰/v1.0 비교: 38/38 실행 PASS
- 신규 SID 11/11 합성 패턴 매칭 성공
- OAST DNS: 실제 도메인 4/4 탐지, 유사 도메인 4/4 무경고
- 추가 정상 의도 146세션: 기존 대비 신규 경고 없음
- 기존 룰과 동일한 정상 HTML 예시 경고 1건은 그대로 존재
- 공식 OISF SMB/DCERPC/Kerberos PCAP 10종: 기존 탐지 결과와 동일

실제 Stellar Cyber 7.0 센서 PoC (2026-11-08)
- 센서 검증 당시 333개 탐지 규칙·SID가 v1.0과 동일(파일의 버전 주석 및 SHA-256은 변경됨)
- 초기 HTTP/DNS 테스트에서 신규 룰 11/11 Alert 확인
- 추가 전체 룰 테스트: 실제 센서에서 315/333 SID의 개별 Alert 확인
- 미재현 18개: HTTP 15개, SMB 2개, DCE/RPC 1개 (추가 검증 필요)
- 합성 트래픽 재현 수치이며 운영망 실제 공격 탐지율을 뜻하지 않음
- 정상/유사 도메인 대조군 7개: 신규 커스텀 룰 Alert 0건
- 테스트 시 eth0 캡처 110패킷, 커널 캡처 드롭 0
- 동일 캡처 PCAP을 기준 탐지 구성으로 재생: 신규 테스트 패턴 Alert 0건
- 같은 PCAP을 333개 탐지 룰셋으로 재생: 신규 테스트 패턴 Alert 11건
- OISF 공식 SMB/DCERPC/Kerberos PCAP 5개 실제 센서 재생 성공
- 기본 ET SID 2034825는 유사 OAST 도메인에 경고(신규 커스텀 룰과 무관)
- 기본 ETPRO SID 2868495/2868498: krb5/nfs 탐지 비활성화로 로딩 실패
- 위 두 기본 ETPRO 룰과 센서 설정은 수정/삭제하지 않았음
- Stellar Cyber DP/UI까지 Alert 전달, 운영망 오탐률은 미검증

주의:
1. Import는 기존 custom_defined.rules 전체를 교체할 수 있으므로 백업하세요.
2. 새 센서에서도 Suricata 버전, 앱 프로토콜 지원, 기본 IDS SID와 중복을 확인하세요.
3. OAST DNS는 승인된 모의해킹 도구 사용 시에도 발생합니다.
4. HTTPS 페이로드 탐지는 평문 또는 외부 복호화가 필요합니다.
5. AD 공격(DCSync/PsExec/Kerberoasting 등) 신규 룰은 오탐 구별 실패 가능성으로 제외했습니다.
6. AI 모델은 포함되지 않으며 도구 지문 시그니처는 회피 가능합니다.

출처 및 라이선스는 .rules 파일 상단에 포함되어 있습니다.

배포 참고: v1.0은 실센서 PoC에서 확인한 333개 탐지 규칙과 SID를 그대로 유지하며, 버전 주석만 갱신했습니다. 기존 센서 파일의 SHA-256과 공개 v1.0의 SHA-256은 다릅니다.
