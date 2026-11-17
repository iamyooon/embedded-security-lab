# 실무 TA 명령 레퍼런스 (첫 TA 구현용)

hello_world의 `INC_VALUE`(받은 값 +1)는 왕복만 보여주는 뼈대. 실제 TA는 아래 같은 **보안 명령**을 제공한다. 이 틀(연결→세션→명령→파라미터→결과)은 동일하고 "하는 일"만 진짜로 바뀐다.

## 범주별 대표 명령
| 범주 | 대표 명령 | 하는 일 |
|---|---|---|
| 키·암호 | `GENERATE_KEY` / `SIGN`·`VERIFY` / `ENCRYPT`·`DECRYPT` / **`HMAC`(MAC)** / `DERIVE_KEY` / `GET_RANDOM` | 키를 secure world에 두고 서명·암복호·인증코드 계산. **키는 안 나옴** |
| secure storage | `STORE_SECRET` / `LOAD_SECRET` | 기기고유키로 봉인 저장·조회 |
| 인증·신원 | `VERIFY_PIN`(rate-limit) / `ATTEST`(챌린지 서명) / 생체매칭 | 비밀 노출 없이 판정 |
| 부팅·무결성 | `MEASURE`·`VERIFY_IMAGE` / `ROLLBACK_COUNTER` | 펌웨어 해시·서명 검증, 롤백방지 |

실제 제품: Android Keystore/KeyMint(HW 키·attestation), Gatekeeper(PIN검증), Widevine(DRM), 지문매칭.

## 자동차 매핑 (타깃 = 모비스 차량보안)
- **SecOC** — CAN 메시지 **MAC 계산/검증**(키는 TEE/HSM) ← `HMAC` 명령
- **Secure Boot 검증** — ECU 펌웨어 서명검증 (`VERIFY_IMAGE`)
- **Secure OTA** — 업데이트 패키지 서명검증 + 롤백카운터
- **UDS Security Access(0x27)/Authentication(0x29)** — 챌린지-응답(비밀키 secure 보관)
- **V2X / 디지털키(CCC)** — 메시지 ECDSA 서명·인증서 처리

## "간단하지만 진짜"인 첫 구현 (난이도 낮은 순)
1. **`HMAC` 서비스** ⭐ — 데이터(MEMREF in) + 키(TEE 보관) → MAC(MEMREF out). **SecOC 직결**. 첫 실무명령으로 최적.
2. **`AES` 암복호** — TEE 키로 데이터 암복호.
3. **`GENERATE_KEY` + `SIGN`(ECDSA)** — 키 생성(안 나옴) + 서명. secure boot/OTA/V2X 매핑.

## 레퍼런스 구현 (OP-TEE 기본 제공)
`<리포>/optee/optee_examples/` 에 이미 있음 → 읽고 참고:
- `aes/` (AES 암복호) · `acipher/`(RSA 비대칭) · **`hotp/`(HMAC 기반 OTP)** · `secure_storage/` · `ecdsa/` · `ecdh/`

## 추천 첫 TA
**"Secure MAC Service"** = `GEN_KEY`(secure world에 키 생성·보관) + `HMAC`(데이터 받아 MAC 계산·반환).
- 키는 secure world 밖으로 안 나감 → TEE 가치 증명.
- 자동차 **SecOC** 스토리로 포트폴리오·면접 어필.
- 나중에 B-2 단계에서 **이 TA를 RE·퍼징으로 공격**(키 추출 시도→차단 확인).

구현 위치: `01-optee-qemu/ta/`(내 TA) + `host/`(내 CA). hello_world를 복제해 UUID 교체 후 `INC_VALUE` 자리에 `HMAC` 구현.
