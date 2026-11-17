# CA / TA 와 world switch — 내 말로 (규칙 4 writeup 초안)

> 2026-11-17 작성. 대화 중 내가 정리한 문장 그대로.

ta는 trusted app이고 secure world에서 동작하고 ca는 client app이고 normal wolrd에서 동작하는거지. 그래서 ca와 ta가 같이 맞물려서 동작하는것 같은데 역할이 나뉘는것 같네. ta는 normal world가 깨져도 기밀성과 무결성이 지켜져야 하는 키, 판정로직, 상태를 둔다라고 할수있겠네.. 너가 식당에 빗댄것처럼 청결해야할 주방에는 요리사만 있고 요리는 주방에서만 하는거지. 요리가 필요한 손님은 주방밖에서 주문해서 받아야 하고..

대략적인 처리 흐름은  둘 사이의 통신을 위해 통로가 있는데 ca가 libteec 라이브러리의 함수를 호출하여 op-tee 드라이버가 동작하면서 smc 명령을 실행하여 el3의 tf-a 모니터가  secure world로 world switch이 시키지. 그러면 op-tee가 요청을 받아서 uuid로 해당 ta를 찾고 ta가 처리를 진행하는 식이고...

ca(el0) -> libteec(el0) -> op-tee driver(el1) -> tf-a(el3) -> op-tee(s-el1) -> ta(s-el0) 이런식으로 처리흐름이 만들어지네

```
CA(EL0) -> libteec(EL0) -> OP-TEE 드라이버(EL1, SMC 실행)
  -> TF-A 모니터(EL3, world switch) -> OP-TEE OS(S-EL1) -> TA(S-EL0)
결과는 같은 경로를 거꾸로 타고 CA 로 돌아온다.
```
