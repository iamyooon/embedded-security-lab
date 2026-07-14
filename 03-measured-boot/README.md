# 03 · Measured Boot (TPM)

가상 TPM(**swtpm**)으로 부팅 단계를 **측정(PCR)** 하고, 상태에 secret을 **sealing**, 기초 **attestation**을 해본다.

## 목표 / 완료 기준
- [ ] QEMU + swtpm(TPM 2.0) 연결, PCR 확장 관찰
- [ ] secret을 특정 PCR 상태에 seal → 상태 바뀌면 unseal 실패 데모(규칙 3)
- [ ] 기초 attestation(quote) 흐름 이해
- [ ] writeup + "왜": measured boot(TPM) vs verified boot(02)의 차이

## 위협모델 (← 내가 작성)
> …

## 연결
- 02(verified=거부) vs 03(measured=기록·증명)의 상보 관계를 명확히.
