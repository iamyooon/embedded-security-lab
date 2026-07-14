# 05 · 리얼보드 — 하드웨어 Root of Trust

QEMU가 못 가르치는 것(eFuse/OTP 소각, 실 secure storage, 물리 공격면, 성능)을 실물로 메운다.

## 후보 보드
- **NXP i.MX8M**(Mini/Nano/Plus/Quad) — **HAB secure boot + OP-TEE 정식 지원**(meta-imx). 회사 보드가 이거면 최적.  ← 모델 확인 예정
- STM32MP1 — secure boot + OP-TEE, 저가 개발보드.
- (RPi4는 이 목적엔 부적합 — secure world/OP-TEE 미제공)

## 목표 / 완료 기준
- [ ] 회사 NXP 보드 모델 확인 → HAB/OP-TEE 지원 여부
- [ ] 01~04 중 하나를 실물에 포팅(예: OP-TEE TA, 또는 HAB secure boot)
- [ ] writeup: QEMU와 실물의 차이(무엇이 진짜였나)

## 위협모델 (← 내가 작성)
> 물리 공격 포함으로 확장 …
