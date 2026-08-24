# 내 TA — Secure MAC Service (`secure_mac`)

SecOC 스타일: **키는 secure world 에서 생성돼 밖으로 안 나가고**, normal world 는
"메시지 -> MAC" 결과만 받는다. UUID `82a856b1-5b26-4746-8fec-318d1360ffad`.

## 명령
| id | 명령 | 파라미터 | 하는 일 |
|----|------|----------|---------|
| 0 | `GEN_KEY` | 없음 | HMAC-SHA256 256bit 키를 TA 안에서 생성(`TEE_GenerateKey`), `TEE_USAGE_MAC` 로 제한 -> 반출 불가 |
| 1 | `MAC` | in: 메시지 / out: 태그 32B | 프레임에 MAC 부착 |
| 2 | `VERIFY` | in: 메시지, in: 태그 / out: valid(0\|1) | `TEE_MACCompareFinal` 로 위조 판정 |
| 3 | `EXPORT_KEY` | out: 버퍼 | **공격 데모** — 키 자체를 요구한다. 성공하면 설계 실패 |

CA(`host/main.c`)는 `[CAN id 2B][freshness 4B][payload 8B]` 프레임을 만들어
MAC -> 정상검증(valid=1) -> 1바이트 변조 후 재검증(valid=0) -> 키 탈취 시도 순으로 돈다.

## 내가 채울 곳 (규칙 5)
`ta/secure_mac_ta.c` 의 **TODO 2개**. 나머지(파라미터 검사·디스패치·엔트리포인트·CA·빌드)는 배관.
1. `gen_key()` — AllocateTransientObject -> GenerateKey -> RestrictObjectUsage
2. `mac_do()` — AllocateOperation -> SetOperationKey -> MACInit/Update -> ComputeFinal 또는 CompareFinal

참고 구현: `/data/optee/optee_examples/hotp/ta/hotp_ta.c` 의 `hmac_sha1()` (6단계 주석).
길이 인자가 `size_t` 가 아니라 `uint32_t` 인 이유는 `ta/Makefile` 의 `CFG_TA_OPTEE_CORE_API_COMPAT_1_1=y`(GP 1.1 시그니처).

## 빌드 · 실행
```sh
../build/run-secure-mac.sh          # 동기화 + 빌드 + QEMU 부팅 + 게스트에서 CA 실행
../build/run-secure-mac.sh build    # 빌드만
../build/run-secure-mac.sh run      # 실행만
```
- 소스는 `/data/optee/optee_examples/secure_mac/` 로 rsync 되고 buildroot 가 TA(`/lib/optee_armtz/<uuid>.ta`)와
  CA(`/usr/bin/optee_example_secure_mac`)를 rootfs 에 넣는다.
- 실행은 `build/lab-run.exp`(qemu-check.exp 를 내 명령용으로 축소) + `build/lab-run.mk`.

## 현재 상태 (스텁 상태로 배관 검증 완료)
```
[1] GEN_KEY      -> 0xffff0009 (실패)      <- TEE_ERROR_NOT_IMPLEMENTED = 아직 TODO
secure world 로그: I/TA: secure_mac: session opened / closed
```
-> TA 서명·설치·세션 오픈·world switch 까지는 동작. 이제 TODO 2개를 채우면 진짜 MAC 이 나온다.

## 함정 메모
- `/data/optee` 를 **root 로 빌드하면 소유권이 섞여** 다음 빌드가 깨진다(cmake relink 실패).
  항상 컨테이너를 `-u 1000:1000` 으로 띄운다(`run-secure-mac.sh` 가 그렇게 한다).
