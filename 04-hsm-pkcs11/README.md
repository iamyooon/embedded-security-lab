# 04 · HSM (SoftHSM + PKCS#11)

키가 **HSM 밖으로 안 나가고**, 서명/복호만 HSM 안에서 일어나는 구조를 PKCS#11로 구현한다.

## 목표 / 완료 기준
- [x] SoftHSM 토큰 생성, 키 쌍을 HSM 안에 생성(추출 불가 플래그)
- [x] PKCS#11로 서명 — 개인키를 앱이 못 읽음을 확인(규칙 3)
- [x] 02의 FIT 이미지를 **SoftHSM 키로 서명** → 02↔04 연결
- [ ] writeup + "왜": HSM vs TEE vs TPM 역할 분담
- [ ] (선택) YubiHSM 2 / 클라우드 HSM(AWS CloudHSM)로 실물 확장

## 위협모델 (← 내가 작성)
- 무엇을 지키나: FIT 서명 개인키
- 어떤 공격자로부터: 개인키가 보관된 빌드서버에 침입해 root 를 얻은 공격자
- 무엇이 깨지면 실패: HSM 밖에서 키가 보인다. 허가되지 않은 서명이 만들어진다.

## 실험 결과 (2026-11-19, hsm-lab 컨테이너: Ubuntu 22.04, softhsm2 2.6.1 OpenSSL 백엔드)
키: `fitkey` RSA-2048, 속성 `sensitive, always sensitive, never extractable, local`. 공격자는 PIN 을 가진 root.

| 실험 | 방법 | 예측 | 결과 |
|---|---|---|---|
| [H1] API 로 꺼내기 | `C_GetAttributeValue(CKA_PRIVATE_EXPONENT)` ([src/read_priv.c](src/read_priv.c)) | 막힘 | 막힘. `rv=0x11` CKR_ATTRIBUTE_SENSITIVE, 길이 -1. 막은 것은 권한이 아니라 키 속성(SoftHSM 이 검사) |
| [H2] API 우회 (메모리) | 서명 중 `RSA_sign` 진입 시점에 gcore -> n 을 나누는 128B 조각 탐색 ([src/h2_dump.sh](src/h2_dump.sh), [src/h2_recover.py](src/h2_recover.py)) | 뚫림 | 뚫림. p, q 각 2벌(SoftHSM 복호 바이트열 BE + OpenSSL BIGNUM LE). `p*q == n`, 복원 키 서명 == HSM 서명 |

- 참고: pkcs11-tool `--read-object --type privkey` 는 "not (yet) supported" 로 툴이 자체 거절 -> SoftHSM 까지 요청이 안 감. 그래서 [H1] 은 C 로 직접 호출.
- 참고: 서명 "후" 덤프(C_Sign 반환, C_CloseSession, C_Finalize)는 0건. SoftHSM 이 사용 후 지움. 노출 창은 서명 연산 중.
- 실패 기준 대조: "HSM 밖에서 키가 보인다" -> SoftHSM 은 깨짐(키가 앱 프로세스 메모리에서 연산됨). 별도 칩 HSM 이면 연산이 칩 안이라 이 덤프로는 안 나옴(일반론, 미확인).
  "허가되지 않은 서명" -> PIN 을 가진 root 는 `C_Sign` 을 부르면 됨. 진짜 HSM 도 못 막음. PIN 을 서버에 두지 않기, 서명 승인 절차, 로그가 필요(일반론, 미확인).

## 02 FIT 를 SoftHSM 키로 서명 (2026-11-19)
빌드: [fit/build-fit-hsm.sh](fit/build-fit-hsm.sh). 토큰 `fit` 안에 `fithsm`(RSA-2048, never extractable) 생성 ->
`mkimage -N pkcs11 -k "pkcs11:token=fit;pin-value=..."` 가 OpenSSL pkcs11 engine -> SoftHSM `C_Sign` 으로 conf-1 서명.
개인키 파일 없음. 공개키는 `ctrl-hsm.dtb` 의 `/signature/key-fithsm`(required=conf) -> u-boot-nodtb.bin 뒤에 붙여 BL33 -> TF-A 재빌드로 bl33 해시가 공개키를 덮는다.
부팅 쪽(U-Boot 검증)은 02 와 동일 -- 서명이 파일 키로 됐는지 HSM 으로 됐는지 U-Boot 는 모른다.

| 실험 | 예측 | 결과 |
|---|---|---|
| [F1] 새 U-Boot(key-fithsm) + HSM 서명 itb | 동작 -- 맞음 | `sha256,rsa2048:fithsm+ OK` -> 이미지 해시 OK -> 커널 login |
| [F2] 02 U-Boot(key-fitdev) + HSM 서명 itb | 동작 안 함 -- 맞음 | `fithsm- error!` / `Failed to verify required signature 'key-fitdev'` -> `resetting ...` 반복 (02 하드닝) |

- 오프라인 검증도 같은 결과: `fit_check_sign -k ctrl-hsm.dtb` OK, `-k ctrl.dtb`(fitdev) `Signature check bad`.
- 한계: PIN 을 명령줄 URI 에 넣음 -> `ps` 로 보임. 빌드 서버 root 는 이 PIN 으로 `C_Sign` 을 불러 아무 itb 에나 서명 가능(오용). 실습 편의이고, 실제는 서명 서버 분리 / m-of-n 승인 / 로그(일반론, 미확인).
- 토큰 저장소 `optee/out/fit/hsm-tokens`, 02 산출물 백업 `optee/out/fit/bak-02` (둘 다 git 제외).

