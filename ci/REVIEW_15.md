# 15번 증거 판독 결함 수정

착수 시 원격 main은 `93194ecfcea47d79e2b9a87a68f76cd88d3e3d63`이었다. PR #21의 검토 head `78bc38bb01c13561f21a11f67e09baf22d7ae609`과 이 병합 커밋의 파일 트리가 같다. 아래의 수정 전 열은 동일 트리에서 확인한 14번 재현과 호출 경로를 기준으로 한다.

| 항목 | 수정 전 재확인 | 변경 경로와 수정 후 검증 | OCI·WSL 원본 재판독 및 재실행 조건 |
|---|---|---|---|
| 1. 공개 artifact | 비공개 표지가 들어간 TLS 관측도 루트 JSON 업로드 패턴에 포함 | `ci/public_receipt.py`, `ci/verify_uploaded_receipt.py`, 두 workflow. 검증된 이름·열거값·해시로 영수증을 새로 작성한다. ZIP 전체 파일 목록과 내용까지 대조한다. 실패 시 부분 증거를 허용하며 성공으로 승격하지 않는다. | GitHub 업로드 경로의 검사다. 플랫폼 키·평문·원본 stdout은 게시 대상에서 제외한다. |
| 2. 장기 부하 | 1,800초를 주장하는 final 한 줄, 단조 시간 0.014초, 표본 1개가 통과 | `load_campaign.py`, `load_readback.py`, `short_operations.py`. 소켓 제한, 각 연결 교체·트래픽·종료 단계, 메시지 진전, KEM·종료 계수, 단조 시간과 /proc 표본을 대조한다. final 단독, 단계·표본 삭제와 잘못된 시간·종료 계수를 거부한다. | 아래의 두 30분 원본 수용. WSL 호스트 시계 일치가 필요한 결론에는 독립 시계 관측을 갖춘 재실행이 필요하다. |
| 3. 인가 | 쓰기 거부를 TLS 거부로 치환하고 설정 거부 4건을 삭제해도 19건을 인정 | `ci/evidence.py`, `client_auth_contract.json`. 20개 연결 사례와 4개 설정 사례에서 순서·사유·KEM 수·정리·stdout 검사. 단계 변경, 설정 누락, 정리 플래그 변형, 추가 stdout 거부. | 양쪽 `client_auth_platforms_20261119/*/result.json`에 `server_stderr`가 없어 사유 확인 불가. 새 runner로 재실행 필요. |
| 4. TLS | 31개 관측 전체를 삭제해도 35개 시험 성공으로 판독 | `adversarial.py`, `interop.py`, `ci/evidence.py`, `tls_contract.json`. v0.4에서 시험·반복·양단 역할·종료 사유·회수 계수를 대조한다. 정상 세션의 인증된 종료 및 Rust 양단의 바인딩을 비교한다. 누락·사유 교체·남은 키·바인딩 불일치 거부. | 양쪽 `secret_state_platforms_20261108` 원본은 v0.3으로 필수 관측 확인 불가. 플랫폼별 v0.4 실측 필요. |
| 5. 필수 시험 | Python·Rust의 필수 이름을 다른 이름으로 치환해도 개수가 같으면 통과 | `ci/test_inventory.json`, `ci/evidence.py`, `ci/validate.py`. 시험 이름과 실행·ignored 상태를 고정하고 대체 이름과 상태 뒤바꿈 거부. | 첨부한 양쪽 release 키 시험에서 11+20개 이름과 결과 수용. 저장소 11월 9~10일 키 아카이브도 해당 키 시험 수용. 과거 Rust library 시험 수는 현재 목록과 달라 전체 현행 인벤토리는 확인 불가. |
| 6. scratch-cleanup | 하위 파일 없이 빈 출력과 exit 0만으로 상위 검사가 통과 | `ci/evidence.py`, `ci/validate.py`, `scratch_cleanup.py`. 7개 Cargo 선택과 기능 옵션, 23개 시험 식별자·상태, stdout/stderr 해시와 하위 결과를 확인한다. 정상 Cloud 하위 묶음 수용, 하위 결과 누락 거부. | 양쪽의 해당 7개 실행에 대한 하위 결과와 분리된 스트림 묶음은 확인 불가. 플랫폼별 판정에는 해당 matrix 재실행 필요. |
| 7. 메모리 진단 출처 | 빌드·도구 영수증과 로그를 삭제한 clean fixture가 통과 | `ci/check_memory_result.py`, `diagnostics/libtest_memory.py`. 고정 소스·생산자, 도구 버전과 빌드 스트림, 실제 명령, 빌드와 실행 전후 바이너리 해시를 대조한다. 새 실행은 출처가 빠지면 거부한다. | 양쪽의 TLS 메모리 후속 시험은 별도 시험이다. 이 6개 std/libtest controls의 플랫폼별 출처 확인 불가. 11월 7일의 보존된 별도 원본은 전체 입력 해시가 일치하는 경우 기존 진단 경고를 재현한다. |
| 8. 판정과 영수증 | 파일을 두 번 읽어 정상 판정에 교체된 파일의 해시가 붙음 | `ci/check_memory_result.py`. 동일한 한 번의 읽기로 판정과 SHA-256을 생성한다. 시험에서 읽기 직후 경로를 교체해도 판정에 사용한 바이트의 해시를 기록한다. 실패한 재검토의 이전 성공 무효화 회귀도 유지한다. | 판독기 로컬에서 재현 가능. 옛 OCI·WSL 메모리 영수증의 입력 바이트는 확인 불가하며 플랫폼 실적에 추가하지 않는다. |

## 보존된 30분 자료

| 플랫폼 | 아카이브 SHA-256 | 수집기 단조 시간 | 자원 표본 | 교체·회수 | 시계 판정 |
|---|---|---:|---:|---|---|
| OCI ARM64 | `3d28f178901c9cb2cb1ba2432bd9b112a3edf3051647a5b68e1a5da533a52f23` | 1,812.529초 | 1,610 | 8 epoch, 7회 교체, 518/518 인증 종료 | locally_consistent |
| WSL x86-64 | `bc0f9467e3213aa00912be5a30e72334ab0a4012b852c886905c74467d347fa4` | 1,817.072초 | 1,613 | 8 epoch, 7회 교체, 518/518 인증 종료 | insufficient |

두 원본 모두 요청한 트래픽 시간 1,800초, 64연결, 메시지 2,304,000개다. 원본 매니페스트 및 실행 전후 소스 스냅샷을 대조했다. 이 과거 형식은 바이너리 불변 플래그와 최초 해시를 보관한다. 두 번째 바이너리 해시를 독립 대조할 수 없다. 호스트에서 이번에 새로 수행한 장기 실행은 없다.

## 검증과 재판독

저장소 루트에서 원본 파일을 그대로 지정한다. 첫 명령은 CI 판독 회귀, 두 번째는 저장된 부하 결과의 재생이다.

```bash
python3 -B -m unittest discover -s ci -p 'test_*.py' -v
python3 -B protocol_rust/validation/load_readback.py /path/to/results.tar.gz
```

[GitHub 기능 CI 정상 실행](https://github.com/1xvn/Spiral-KEM/actions/runs/45621727273) · [누락 회귀로 실패했으나 영수증은 업로드한 실행](https://github.com/1xvn/Spiral-KEM/actions/runs/45606073695) · [Memcheck 경고로 실패하고 업로드된 영수증의 파일·바이트 대조까지 통과한 실행](https://github.com/1xvn/Spiral-KEM/actions/runs/45621852159)

이전 기능 실패 실행에서는 업로드 직후 이름 조회가 실패했다. GitHub API를 통해 원본 ZIP을 따로 받아 유일한 항목 `receipt.json`과 실패 판정을 확인했다. 이후 workflow는 업로드가 반환한 artifact ID로 조회한다. 해시는 바이트 일치의 증거다. 암호 설계 검증과 운영 승인은 이 작업의 범위 밖에 있다.
