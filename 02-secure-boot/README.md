# 02 · Secure Boot (verified boot)

서명된 이미지만 부팅되고, **변조하면 부팅이 거부**되는 체인을 구현한다.

## 목표 / 완료 기준
- [ ] U-Boot **FIT verified boot** — 커널+dtb를 서명하고 U-Boot가 검증
- [ ] **TF-A 인증 부팅체인**(BL1→BL2 이미지 인증)
- [ ] 공격 데모: 서명 바이트 flip → "부팅 거부" 확인 (규칙 3)
- [ ] writeup + "왜": FIT verified boot vs UEFI Secure Boot

## 위협모델 (← 내가 작성)
> 자산 / 공격자(변조된 커널 주입) / 무엇이 깨지면 실패 …

## 연결
- 01의 TEE는 **이 부팅체인만큼만 신뢰**된다. 04의 HSM 키로 여기 이미지를 서명하면 02↔04 연결.
