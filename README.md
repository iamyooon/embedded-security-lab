# embedded-security-lab

임베디드 보안(Secure Boot · TEE · HSM)을 **QEMU로 실습**하며 위협모델과 코드를 정리하는 학습 포트폴리오.
각 단계는 "동작 → 일부러 부수기(공격 데모) → 내 말로 설명(writeup)" 순으로 완성한다.

## 왜 QEMU인가
- OP-TEE(대표 오픈소스 TEE)의 **공식 레퍼런스 타깃이 QEMU**(`qemu_v8`)라 업계 표준 학습 경로.
- TF-A 서명 부팅체인, `virt,secure=on`(EL3/secure world), swtpm(가상 TPM), SoftHSM(소프트 HSM) 모두 에뮬 가능.
- 하드웨어 root of trust(eFuse/OTP)·실 secure storage·물리 공격만 리얼보드(5단계)로 남긴다.

## 로드맵
| 단계 | 주제 | 핵심 산출물 | 상태 |
|------|------|-------------|------|
| [01](01-optee-qemu/) | **TEE — OP-TEE on QEMU** | 직접 만든 Trusted Application(TA) + 호스트앱, world-switch 이해 | 완료 (2026-11-19) |
| [02](02-secure-boot/) | **Secure Boot** | U-Boot FIT verified boot → TF-A 인증체인, "변조→부팅거부" 데모 | 완료 (2026-11-19) |
| [03](03-measured-boot/) | **Measured Boot** | swtpm PCR 측정·sealing·기초 attestation | 계획 |
| [04](04-hsm-pkcs11/) | **HSM** | SoftHSM + PKCS#11, 키는 HSM 안·서명만 밖으로 | 계획 |
| [05](05-real-board/) | **리얼보드** | 하드웨어 root of trust (NXP i.MX8 / STM32MP1) | 계획 |

## 핵심 결과 (01, 02)
| 실험 | 결과 | 근거 |
|------|------|------|
| TA 키 반출 요청 (EXPORT_KEY) | OP-TEE 코어가 거부, TA panic -> 키 안 나감 | [01 README](01-optee-qemu/README.md) |
| 키 생명주기 + 호출자별 접근 제어 | 통합 테스트 26/26 PASS, 다른 uid 거부 / root+setuid 는 못 막음(한계 명시) | [01 README](01-optee-qemu/README.md), [그림](01-optee-qemu/notes/04-access-control.png) |
| 저장소 공격 (root 가 /var/lib/tee 조작) | 읽기·변조 막힘(변조 시 키 삭제 = 가용성 공격), 롤백 뚫림 -> RPMB 필요 | [그림](01-optee-qemu/notes/05-storage-attack.png) |
| xtest 전체 회귀 | 153 케이스 / 43582 서브테스트 실패 0 (TBB + FIT 체인 위) | [01 README](01-optee-qemu/README.md) |
| TF-A TBB [A] 이미지 / [B] 서명 / [C] 공격자 키 | 셋 다 부팅 거부, VERBOSE 원인 줄로 구분 | [02 README](02-secure-boot/README.md), [인증서 체인](02-secure-boot/notes/cert-chain.png) |
| U-Boot FIT [D] 커널 변조 | 해시 불일치로 거부 | [FIT 체인](02-secure-boot/notes/fit-chain.png) |
| [E] 검증 실패 후 셸 -> booti 우회 | 무서명 커널 부팅됨 -> 하드닝 후 셸 차단 [E'] | [02 README](02-secure-boot/README.md) |

내 말로 쓴 설명: [01 writeup](01-optee-qemu/notes/writeup.md), [02 writeup](02-secure-boot/notes/writeup.md)

## 학습 방식
작업 규칙(역할 분담·설명먼저·부수기·설명백 등)은 [LEARNING.md](LEARNING.md) 참고.

## 환경
빌드는 Docker(Ubuntu 22.04) 컨테이너에서. 대용량 빌드 산출물은 `<리포>/optee`에 두고 git 제외.
(2026-11-17 서버 이전: 호스트 16.04 -> 24.04, `/data/optee` 소멸로 `<리포>/optee` 에 재빌드.)
