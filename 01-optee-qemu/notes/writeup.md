# 01 TEE (OP-TEE on QEMU) -- 내 말로 설명 (규칙 4)

> 가르치듯 쓴다. 막히는 곳 = 아직 모르는 곳. 아래 질문은 뼈대일 뿐, 지우고 내 문장으로 채운다.
> 근거 자료: README.md 실행 결과 표, notes/02-ca-ta-world-switch.md, notes/03-ca-ta-code-flow.png,
> notes/04-access-control.png, notes/05-storage-attack.png

## 1. TEE 가 지키는 것과 경계
- normal world 를 root 로 장악한 공격자도 못 하는 것은? 그걸 하드웨어에서 무엇이 보장하나?
- 반대로 TEE 가 있어도 root 가 할 수 있는 것은?

root도 못하는 것은 hw적으로 메모리 접근할때마다 secure, non-secure를 검사하므로 secure world의 메모리를 보는것이고 export_key를 보내도 키를 유출시킬 수 없음. root가 할수있는 것은 키를 쓰게 만드는것(root는 setuid로 주인행세 가능),  재전송, dos, ta 버그를 이용하는 것임.

## 2. CA 에서 TA 까지 (world switch)
- CA 가 TEEC_InvokeCommand 를 부르면 TA 함수가 실행되기까지 어떤 단계(EL)를 거치나?

el0인 ca에서 teec_invokecommand를 부르면 el1인 tee 드라이버를 통해 smc 명령이 실행되면서 el3 모니터를 통해 s-el1 op-tee os를 거쳐서 s-el0인 ta가 실행되어 함수가 실행됨

- 인자(메시지, 결과 tag)는 두 world 사이에서 어떻게 오가나? TA 가 normal world 메모리를 볼 때 조심할 점은?

전달된 인자는 정수의 경우 레지스터로 복사되고 메시지나 버퍼는 공유메모리로 등록되어 ta가 들여다보고 있음. 그런데 사용하는 사이에 normal쪽에서 메모리 내용을 바꿀 수 있음. 그래서 ta에서는 메모리를 복사해서 검사하고 써야함

## 3. 키가 secure world 밖으로 안 나가는 서비스
- EXPORT_KEY 는 왜 실패했나? TA 코드가 막았나, OP-TEE 가 막았나?
- 키 값을 안 주고도 CA 가 키를 "쓸" 수 있게 하는 구조는?

키 객체를 만들 때 extractable 없음 유지를 해서 만들었고 실패하면 ta가 panic을 하고 있음. op-tee 코어가 막음. 키가 ca로 가지 않고, id만으로 키를 사용해서 원하는 요청을 수행하게 함.

## 4. 키 저장 (Persistent Object, REE FS)
- 키는 실제로 어디에 어떤 형태로 저장되나? 누가 파일 I/O 를 하나?

키는 /var/lib/tee에 암호화된 상태로 저장됨. 실제 암호화는 시큐어 월드에서 하고, 암호화된 바이트와 해시만 tee-supplicant로 넘기고, tee-supplicant는 노멀 월드의 /var/lib/tee에 적기만 함.

- [S1][S2][S3] 는 각각 왜 막혔/뚫렸나? S2 에서 예상 못 한 것은?

읽기는 암호화되어있기 때문에 막혔고 변조는 dirf.db에 적힌 해쉬와 달라지기 때문에 막혔음. 롤백은 뚫렸는데 해시가 일치하는 파일과 dirf.db 조합으로 공격했기 때문에 가능해진것임. 이 조합이 최신인지를 체크하는 로직이 어디에도 없기 때문에 가능함. 1바이트 변조만으로 optee가 파일을 삭제해버려 가용성공격이 되버렸음.

- 롤백을 막으려면 무엇이 있어야 하나?

rpmb가 있어야 하고 rpmb는 쓰기에 인증과 카운터가 붙어 있어서 normal world가 옛 값으로 되돌릴 수 없음.


## 5. 호출자별 접근 제어
- TA 는 호출자를 무엇으로 알아보고, 키 주인 정보는 어디에 두었나?

TEE_Identity로 알아보고 키 주인정보는 persistent object의 데이터섹션에 들어가 있음

- root 는 왜 못 막나 (A6)? TEE 혼자 못 막는 이유는?

TEE_Identity는 uid로 계산해서 생성되는데 root가 setuid로 특정 uid인척하면 구분할 방법이 없음. 왜냐하면 tee_identity를 계산하는 주체가 커널이기 때문임.


## 6. 면접에서 2분 안에 말한다면
첫째, TEE는 메모리 격리를 통해서 시큐어 월드의 메모리를 노멀 월드가 보지 못하게 하고 있고, 키가 시큐어 월드 밖으로 나가지 않도록 해주는 기능을 하고 있음.

둘째, 이런 기능들을 어떻게 구현을 했냐면, 실제 키를 사용하는 게 아니라 id를 통해서 키를 사용할 수 있도록 하고, extractable이라는 플래그를 빼서 OP-TEE 코어가 키 실제 반출을 막고 있음.

셋째, 직접 QEMU와 OP-TEE 조합으로 확인해 보면 롤백은 막을 수가 없음. 실제 롤백을 막으려면 NV 카운터 같은 RPMB가 있어야 함. 그리고 루트는 커널이 신원을 만들기 때문에 못 막는 것들이 있음(setuid).
