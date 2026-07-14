# 01 · TEE — OP-TEE on QEMU

ARM TrustZone 기반 TEE를 QEMU(`qemu_v8`)에서 부팅하고, **직접 Trusted Application(TA)** 을 만들어 secure/normal world 분리를 이해한다.

## 목표 / 완료 기준
- [ ] OP-TEE `qemu_v8` 스택 빌드 → secure+normal world 부팅, `xtest` 통과
- [ ] **내가 만든 TA + 호스트앱** 동작 (예: 키가 secure world 밖으로 안 나가는 서비스)
- [ ] 공격 데모: normal world(root)에서 secret을 못 꺼냄을 보인다
- [ ] writeup: world-switch(SMC→EL3→S-EL1) 흐름을 내 말로
- [ ] "왜": TEE vs TPM vs HSM — 이 문제엔 왜 TEE인가

## 위협모델 (← 내가 작성한다: 규칙 2)
> 여기에 직접 채워넣기:
> - 무엇을 지키나 (자산):
> - 공격자 능력 (예: normal-world Linux를 root로 장악):
> - TEE가 막는 것 / 못 막는 것 (물리공격·TA버그·깨진 부팅체인):
> - 무엇이 깨지면 실패로 보나:

## 배경지식
- [notes/00-trustzone-primer.md](notes/00-trustzone-primer.md) — TrustZone·OP-TEE 개념 프라이머

## 빌드
- [build/README.md](build/README.md) — OP-TEE 공식 빌드(repo + qemu_v8.xml) 절차

## 내 TA 코드
- [ta/](ta/) — Trusted Application + 호스트앱 (급소는 손으로 타이핑: 규칙 5)
