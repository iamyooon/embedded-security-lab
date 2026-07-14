# embedded-security-lab

임베디드 보안(Secure Boot · TEE · HSM)을 **QEMU로 실습**하며 위협모델과 코드를 정리하는 학습 포트폴리오.
각 단계는 "동작 → 일부러 부수기(공격 데모) → 내 말로 설명(writeup)" 순으로 완성한다.

## 왜 QEMU인가
- OP-TEE(대표 오픈소스 TEE)의 **공식 레퍼런스 타깃이 QEMU**(`qemu_v8`)라 업계 표준 학습 경로.
- TF-A 서명 부팅체인, `virt,secure=on`(EL3/secure world), swtpm(가상 TPM), SoftHSM(소프트 HSM) 모두 에뮬 가능.
- 하드웨어 root of trust(eFuse/OTP)·실 secure storage·물리 공격만 리얼보드(5단계)로 남긴다.

## 로드맵
| 단계 | 주제 | 핵심 산출물 |
|------|------|-------------|
| [01](01-optee-qemu/) | **TEE — OP-TEE on QEMU** | 직접 만든 Trusted Application(TA) + 호스트앱, world-switch 이해 |
| [02](02-secure-boot/) | **Secure Boot** | U-Boot FIT verified boot → TF-A 인증체인, "변조→부팅거부" 데모 |
| [03](03-measured-boot/) | **Measured Boot** | swtpm PCR 측정·sealing·기초 attestation |
| [04](04-hsm-pkcs11/) | **HSM** | SoftHSM + PKCS#11, 키는 HSM 안·서명만 밖으로 |
| [05](05-real-board/) | **리얼보드** | 하드웨어 root of trust (NXP i.MX8 / STM32MP1) |

## 학습 방식
작업 규칙(역할 분담·설명먼저·부수기·설명백 등)은 [LEARNING.md](LEARNING.md) 참고.

## 환경
호스트가 낡아(Ubuntu 16.04) 빌드는 Docker(Ubuntu 22.04) 컨테이너에서. 대용량 빌드 산출물은 `/data`에 두고 git 제외.
