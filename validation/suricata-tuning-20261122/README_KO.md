# Suricata 품질 개선 후보 (2026-11-22)

이 폴더는 **검토 전용(QA Review)** 입니다. 운영 Sensor, `xdr.ooo` 다운로드, GitHub Release를 변경하거나 자동 배포하지 않습니다.

## 후보 구성
| 프로파일 | Alert SID | 용도 |
| --- | ---: | --- |
| `suricata-core-365-review.rules` | **365** | 기존 339 중 미재현 2개 제외 + 신규 Agentic 고유 시그니처 28개 |
| `suricata-hunting-12-optin.rules` | **12** | 정상 도구 사용으로도 탐지될 수 있는 지표 및 과거 C2 IOC; 반드시 선택적으로 사용 |
| `suricata-core-plus-hunting-377-review.rules` | **377** | 두 프로파일의 검토 전용 결합본 |

**공개 원본 383개는 바이트 변경 없이 유지**됩니다. 제외된 SID는 총 6개입니다. `9005017` (Next.js WebSocket SSRF) 및 `9005055` (PHP2Shell Multipart)는 원래 패턴의 탐지 미재현 및 검증된 FP/FN 위험으로 인해 기본 프로파일에서 제외했습니다. 해당 취약점을 예방하거나 완전 탐지한다는 의미가 아니며, 자산 버전/애플리케이션·WAF 로그 기반의 별도 탐지가 필요합니다. `9876104`는 PentAGI 확인 증거 없는 포트 범위만으로 Alert를 발생시켜 제외했습니다. `9876109/10/11`은 기존 `9006065/64/67` OAST DNS와 중복되어 제외했습니다.

옵션에서 `9876105/06`의 DNS 질의/SNI 문자열을 완전한 호스트명 `update.pentagi.com`과만 일치하도록 수정하여 `notupdate.pentagi.com`의 잘못된 매칭을 제거했습니다. 이 공식 업데이트 도메인의 이용 자체는 악의적 행위의 증거가 아닙니다. `9876029/30`의 BLOODALCHEMY 인프라는 ARTEX 공격에 귀속하지 않고 별도 역사적 IOC로 표시했습니다.

`9876101/02/03/07/08/12/13/14` 등은 합법적인 AI 도구, 관리 API, WSUS, OAST·레드팀 툴과 중첩되므로 Core에서 의도적으로 빠졌으며, 선택형 Hunting에만 둡니다. 이 파일 역시 오탐이 없다는 뜻이 아닙니다.

## 재현 및 검증
```sh
python3 validation/suricata-tuning-20261122/build_profiles.py --verify
python3 validation/suricata-tuning-20261122/verify_profile_eve.py --logs /tmp/suricata-quality-eve
```

두 번째 명령은 `suricata -T`가 통과한 뒤 CI가 Suricata 8.0.1 및 8.0.8에서 **49개 신규 룰 양성/음성 + 정상·경계 20개 PCAP**을 Core/Combined에 각각 재생한 로그를 읽습니다. `review-disposition-383.csv`에는 383개 SID별 유지·옵션·제외 사유가 있습니다. 활성화된 각 SID의 synthetic Alert 검출과 정상 사용·유사 도메인 재현을 구분하며, 이 검증이 운영 탐지율·오탐률을 대신하지 않습니다.

기존 331개 원래 탐지 룰은 수정하지 않았고, 실제 Modular Sensor의 77개 PCAP 154회 독립 비교에서 기존 SID의 Alert 감소가 0건이었다는 증적은 기존 감사 PR #57에 있습니다. 위 파일은 **배포 및 공개 승인 대상이 아닙니다**.
