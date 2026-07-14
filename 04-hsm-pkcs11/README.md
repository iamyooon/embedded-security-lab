# 04 · HSM (SoftHSM + PKCS#11)

키가 **HSM 밖으로 안 나가고**, 서명/복호만 HSM 안에서 일어나는 구조를 PKCS#11로 구현한다.

## 목표 / 완료 기준
- [ ] SoftHSM 토큰 생성, 키 쌍을 HSM 안에 생성(추출 불가 플래그)
- [ ] PKCS#11로 서명 — 개인키를 앱이 못 읽음을 확인(규칙 3)
- [ ] 02의 FIT 이미지를 **SoftHSM 키로 서명** → 02↔04 연결
- [ ] writeup + "왜": HSM vs TEE vs TPM 역할 분담
- [ ] (선택) YubiHSM 2 / 클라우드 HSM(AWS CloudHSM)로 실물 확장

## 위협모델 (← 내가 작성)
> …
