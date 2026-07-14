# TrustZone / OP-TEE 프라이머

## 한 문장
ARMv8-A는 하나의 칩을 **Secure World(신뢰)** 와 **Normal World(일반)** 로 나누고, TEE는 secure world에서 비밀·암호연산을 처리해 **normal world OS가 root로 뚫려도 키가 새지 않게** 한다.

## 두 세계와 특권 레벨(EL)
```
Normal World                        Secure World
  EL0  내 호스트앱, tee-supplicant     S-EL0  Trusted App (TA)  ← 내가 만들 것
  EL1  Linux 커널, TEE driver          S-EL1  OP-TEE OS (BL32)
                 └──────── EL3: 모니터/펌웨어(TF-A BL31) ────────┘
                           (SMC 명령으로 두 세계 전환)
```
- **SMC 명령**이 EL3(모니터)로 trap → 세계 전환. 이게 "world switch".
- normal world는 secure world 메모리를 못 본다(하드웨어 격리). 반대는 가능.

## 요청 경로 (내 앱이 TA를 부를 때)
```
호스트앱 → libteec(Client API) → /dev/tee0 → [SMC→EL3] → OP-TEE OS → 내 TA
```
비밀 키·연산은 TA(secure world) 안에서만. 결과만 normal world로 반환.

## 부팅 체인(부트로더 = TEE의 신뢰 뿌리)
```
BL1(TF-A) → BL2 → BL31(EL3 런타임) + BL32(OP-TEE OS) → BL33(U-Boot/edk2) → Linux
```
> TEE는 **자기를 로드한 부팅체인만큼만 신뢰**된다 → 그래서 02(Secure Boot)가 TEE를 완성한다.

## 위협모델 요약
- **막는다**: 장악된 normal-world OS(root 포함)로부터 secure world의 키/연산.
- **못 막는다**: 물리 공격, TA 자체의 버그, 신뢰 뿌리가 깨진 부팅체인, side-channel(대체로).

## 왜 TEE인가 (vs 대안)
- **TPM**: 별도 저비용 칩, 측정·sealing·attestation에 강함(수동적). 임의 코드 실행은 못 함.
- **HSM**: 키 관리·고성능 서명 전용(강한 격리), 범용 앱 실행은 아님.
- **TEE(TrustZone)**: SoC 안에서 **임의의 신뢰 코드(TA)** 를 격리 실행 → 모바일 결제·DRM·키스토어 등.

## 핵심 용어
`REE`(Rich Exec Env=normal world) · `TEE` · `TA`(Trusted App) · `PTA`(Pseudo-TA, OP-TEE 커널 내장) · `libteec`/`GP TEE Client API` · `tee-supplicant`(secure storage 등 REE측 도우미) · `xtest`(OP-TEE 테스트 스위트).
