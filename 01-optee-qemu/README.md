# 01 · TEE — OP-TEE on QEMU

ARM TrustZone 기반 TEE를 QEMU(`qemu_v8`)에서 부팅하고, **직접 Trusted Application(TA)** 을 만들어 secure/normal world 분리를 이해한다.

## 목표 / 완료 기준
- [ ] OP-TEE `qemu_v8` 스택 빌드 → secure+normal world 부팅, `xtest` 통과 -- 빌드/부팅 완료, xtest 는 1001 만 PASS (전체 regression 미실행)
- [x] **내가 만든 TA + 호스트앱** 동작 (예: 키가 secure world 밖으로 안 나가는 서비스) -- secure_mac + 키 생명주기 + 호출자별 접근 제어
- [x] 공격 데모: normal world(root)에서 secret을 못 꺼냄을 보인다 -- EXPORT_KEY -> TA panic, TARGET_DEAD
- [ ] writeup: world-switch(SMC→EL3→S-EL1) 흐름을 내 말로
- [ ] "왜": TEE vs TPM vs HSM — 이 문제엔 왜 TEE인가

## 위협모델 (← 내가 작성한다: 규칙 2)
> 여기에 직접 채워넣기:
> - 무엇을 지키나 (자산): 키(기밀성), mac을 계산하는 판정로직(무결성), freshness 카운터(무결성)
> - 공격자 능력 (예: normal-world Linux를 root로 장악): normal world root이고 ta에 임의명령,입력을 보내고, normal world 메모리를 읽고 쓸수있음. ca교체 가능, 물리공격,부팅체인 변조는 가정안함
> - TEE가 막는 것 / 못 막는 것 (물리공격·TA버그·깨진 부팅체인):
>   - 막는것) 키빼내는것, 키없이 mac을 만드는 것
>   - 못막는것) 키를 쓰게 만드는것(ta가 호출자를 구분하지 않음), 재전송(카운터를 ca가 관리), dos공격(root가 ca,ta 호출자체를 막을수있음), ta버그(tee는 ta코드의 실수는 못막음)
> - 무엇이 깨지면 실패로 보나:
>   - export_key가 키를 돌려줌, 변조프레임 verify가 valid=1
>
> 키 생명주기(Persistent Object) 추가 (2026-11-18):
> - 자산: 저장되어있는 기존 키들
> - 공격자 능력: root는 /data/tee 의 암호화된 키 파일을 읽고 쓸수는 있는데 보이지는 않음.
>   - 할수없는것) 키값을 알아내는 것, 키값을 바꿔치기하는것
>   - 할수있는것) 지우기, 롤백 (REE FS 로는 못막음)
> - 실패 기준:
>   1) /data/tee 파일이나 TA API 로 키 값이 보임
>   2) 변조한 저장 파일을 TA 가 받아들여 MAC 계산에 씀
>   3) 삭제한 키 ID 로 MAC 계산이 됨
>
> 호출자별 접근 제어 추가 (2026-11-18):
> - 못막는것) 일반 앱(다른 uid)은 막음, root는 주인 uid로 바꿔 쓸 수 있어 못 막음

## 배경지식
- [notes/00-trustzone-primer.md](notes/00-trustzone-primer.md) — TrustZone·OP-TEE 개념 프라이머

## 빌드
- [build/README.md](build/README.md) — OP-TEE 공식 빌드(repo + qemu_v8.xml) 절차

## 내 TA 코드
- [ta/](ta/) — Trusted Application + 호스트앱 (급소는 손으로 타이핑: 규칙 5)

## 실행 결과

### secure_mac (transient 키, 2026-11-17)
`optee_example_secure_mac` -> [1] GEN_KEY [2] MAC [3] VERIFY 정상 valid=1 [4] VERIFY 변조 valid=0 [5] EXPORT_KEY 거부(0xFFFF3024, origin 3).
키는 세션 수명이라 실행마다 tag 가 다르다. 흐름 그림: `notes/03-ca-ta-code-flow.png`.

### 키 생명주기 -- GP Persistent Object (2026-11-18)
JD "Key 생성, 저장, 조회, 삭제"에 대응. 키는 id(uint32)로만 가리키고 값은 어떤 명령으로도 안 나간다.

| 명령 | TA 함수 (직접 구현) | 핵심 |
|---|---|---|
| KEY_CREATE | `key_create` | transient 생성 + usage=MAC 제한 -> `TEE_CreatePersistentObject` (OVERWRITE 없음 -> 중복 id 거부) |
| KEY_INFO | `key_info` | `TEE_GetObjectInfo1` -- 종류/길이/usage 만 |
| KEY_DELETE | `key_delete` | WRITE_META 로 open -> `TEE_CloseAndDeletePersistentObject1` |
| MAC_BY_ID | `mac_by_id` | open -> 기존 `mac_do` 재사용 -> close |

통합 테스트 `optee_example_secure_mac test`: **PASS 26 / FAIL 0**, TA panic 없음 (아래 접근 제어 A0-A7 포함).
- 정상 T1-T7: 생성/조회/사용, 메타데이터 HMAC-SHA256/256/usage=0x8, EXTRACTABLE 없음 유지, 세션 바꿔도 같은 tag(영속)
- 부정 N1-N7: 중복 생성 ACCESS_CONFLICT, 없는 id ITEM_NOT_FOUND, 짧은 버퍼 SHORT_BUFFER(+필요 크기 32 반환), param 타입 오류 BAD_PARAMETERS (GEN_KEY 검사 누락도 보완)
- 삭제 D1-D4: 삭제 후 MAC/INFO/재삭제 모두 ITEM_NOT_FOUND -> 실패 기준 3 통과
- 예측(규칙 3): T4 유지 / N1 거부 / T7 같음 -> 3개 모두 맞음

### 호출자별 접근 제어 (2026-11-18)
키 주인 = 만든 호출자의 `TEE_Identity`(login + uid 로 계산한 uuid, 20B). `key_create` 가 이걸 persistent object 의
데이터 영역(initialData)에 키와 같이 저장하고, `check_owner()`(직접 구현)가 INFO/MAC/DELETE 전에 현재 호출자와 비교한다.
CA 세션은 `TEEC_LOGIN_USER`, LOGIN_PUBLIC(신원 없음)은 거부. 테스트는 fork -> setuid -> OpenSession 으로 uid 를 바꿔 호출.

| # | 상황 | 결과 | 예측 |
|---|---|---|---|
| A0 | uid1001 KEY_CREATE id=2 | SUCCESS | - |
| A1 | uid1003 MAC_BY_ID (남의 키 사용) | ACCESS_DENIED | 맞음 |
| A2 | uid1003 KEY_INFO | ACCESS_DENIED | - |
| A3 | uid1003 KEY_DELETE (남의 키 삭제) | ACCESS_DENIED | 맞음 |
| A4 | root(uid0) 그대로 MAC_BY_ID | ACCESS_DENIED | 처음 "될 듯" -> 질문 이해 후 "root 허용 코드 없음" 으로 정정, 맞음 |
| A5 | LOGIN_PUBLIC KEY_CREATE | ACCESS_DENIED | - |
| A6 | root 가 setuid(1001) 후 MAC_BY_ID | **SUCCESS (한계)** | 맞음 |
| A7 | 주인 uid1001 KEY_DELETE | SUCCESS | 맞음 |

리뷰에서 잡은 것: `key_delete` 를 WRITE_META 만으로 열면 `check_owner` 의 `TEE_ReadObjectData` 가 커널에서 거부되고
(`core/tee/tee_svc_storage.c:762`) libutee 가 그 오류를 `TEE_Panic` 으로 바꾼다 -> READ | WRITE_META 로 열어야 함.
`check_owner` 의 읽은 길이 검사 누락 -> 데이터 영역이 빈 키면 초기화 안 된 스택값과 비교 -> CORRUPT_OBJECT 반환으로 보완.

리뷰에서 잡은 버그 (구현 중): objectID 길이에 `sizeof(handle)` -> 64bit TA 에선 8바이트라 id 가 달라짐(TA 는 aarch64 로 빌드됨),
Open 결과 미확인 -> 없는 id 에서 NULL 키로 진행, 실패 경로 Close 누락 -> 핸들 누수.

한계 (안 된 것):
- 저장 위치는 REE FS(`/data/tee`, `CFG_REE_FS=y`, RPMB 꺼짐). 암호화 키는 HUK 에서 유도되는데 QEMU 는 HUK 를 구현 안 해
  `core/kernel/otp_stubs.c:22` 기본값(전부 0)을 쓴다 -> QEMU 에선 이론상 오프라인 복호화 가능. 실기는 OTP HUK 필요.
- root 의 파일 삭제/롤백은 못 막는다(위협모델). 저장소 공격 데모(실패 기준 1, 2)는 아직.
- 호출자 신원은 normal world 커널이 uid 로 계산해 준다 -> 커널을 쥔 root 는 setuid 로 주인 행세 가능 (A6).
- `/data/tee` 가 initramfs 라 재부팅하면 사라진다 -> 재부팅 영속성은 미확인(세션 간 영속만 확인).
