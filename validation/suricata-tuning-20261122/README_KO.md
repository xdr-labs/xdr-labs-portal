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


## 실험 전용 SID 9005017 / 9005055 — 기본 배포 미포함

**Next.js WebSocket SSRF 검토 룰:** `suricata-nextjs-websocket-internal-review.rules` (SID `9005017`, rev2)은 기존 미재현 룰과 달리 **HTTP GET + WebSocket Upgrade 헤더 + 명확한 AWS/GCP 메타데이터 또는 루프백 대상 URL**로 한정했습니다. 일반 외부 프록시 요청·lookalike URL·불완전 헤더는 제외합니다. `nextjs_experimental.py`의 합성 PCAP **14/14(양성 5·음성 9)**가 Suricata 8.0.1, 8.0.8에서 각각 PASS입니다. 그러나 대상이 실제 Next.js인지, 영향을 받는 버전인지, SSRF가 성공했는지까지 증명하지 않습니다. 일반 내부 관리 프록시에도 매칭할 수 있어 실환경 검증 전 기본 룰로 편입하지 않습니다.

**PHP2Shell multipart 검토 룰:** `suricata-php2shell-lua-experimental.rules` (SID `9005055`, rev3)은 **외부 `php2shell_100_empty_filename.lua` 파일이 반드시 필요한 별도 탐지 방식**입니다. Suricata 8의 `http1:request_complete` 훅에서 HTTP 요청의 `Content-Type`과 MIME `Content-Disposition`을 검사하고, 본문 조각 배열을 최대 2 MiB까지 제한해 합친 뒤 `filename=""` 파라미터가 있는 실제 multipart 파트 **100개 이상**을 집계합니다. 헤더 위장 및 잘못된 boundary를 실제 파트로 계산하지 않습니다.

- Suricata **8.0.1/8.0.8**에서 기존 multipart 경계 테스트 **13/13(양성 4·음성 9)**, 추가 TCP 분할·boundary·헤더 위장 테스트 **14/14(양성 6·음성 8)**, 한 PCAP의 **100세션 반복에서 Alert 정확히 100건** 모두 PASS입니다. 분할 전송은 독립 PCAP에서 TCP 재조립을 거쳐 확인했습니다.
- Lua API `tx:request_body()`는 이 버전에서 **문자열이 아니라 조각 문자열 배열**을 반환합니다. Suricata 8의 구식 `init()["http.request_body"]` 등록은 사용 불가능하므로, 현재 코드가 지원하는 HTTP/1 요청 완료 훅 및 명시적인 크기 제한을 사용합니다.
- **`.rules`만 복사하면 동작하지 않습니다.** 별도 Lua 파일의 `default-rule-path` 배치, Lua 샌드박스 권한, HTTP 본문 검사 한도, 전송 경로/트랜잭션 처리 상태 확인이 필요합니다. 특히 **HTTP/2, 본문 검사 한도 초과, 2 MiB 초과, 기타 PHP OOM 벡터는 검증/탐지 범위에 포함하지 않습니다.**
- 이 패턴은 **빈 파일명 파트 100개 이상이라는 HTTP 요청 특징**만 나타냅니다. 악성 의도·취약 PHP 버전·성공적인 CVE-2026-109618 악용을 보장하지 않고, 정상 대용량 업로드의 오탐 가능성도 별도 분석해야 합니다.
- 따라서 두 실험 SID는 **Core 365 / 선택형 Hunting 12 / 결합 377 어느 곳에도 포함하지 않습니다.** 개발용 스크립트를 운영 Stellar Cyber Sensor에 업로드하거나 설정/서비스를 바꾸지 않았고, Data Processor Alert/Case E2E도 진행하지 않았습니다.

재현 증거는 `.github/workflows/suricata-quality-review.yml`의 Suricata 8.0.1·8.0.8 매트릭스, `verify_php_lua.py`, `php_lua_extended_qa.py`, `nextjs_experimental.py`에 있습니다. Lua 엔진 훅/청크 반환형 진단은 `.github/workflows/suricata-lua-diagnostic.yml`에 별도로 보존합니다. **검증 PASS는 운영 적용 승인으로 간주하지 않습니다.**
