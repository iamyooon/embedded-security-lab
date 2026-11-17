# 헤드리스로 OP-TEE 부팅 + xtest 실행

## 핵심: `make check` (xterm 불필요)
OP-TEE의 `make run`은 xterm 2개(normal/secure 콘솔)를 띄워 **헤드리스 서버에선 안 된다**.
대신 **`make check`** 가 자동화 타깃 — `build/qemu-check.exp`(expect)가 QEMU를 아래처럼 띄우고 로그인·xtest를 자동 실행:
```
QEMU_CHECK_ARGS = -serial mon:stdio -serial file:serial1.log
```
- **normal world** 콘솔 → stdio (expect가 여기로 로그인·명령)
- **secure world** 콘솔 → serial1.log 파일 (OP-TEE OS 로그)
→ 프라이머의 "두 세계 두 콘솔"이 실제로 이 두 시리얼로 나뉜다.

## 실행 (컨테이너)
빌드 컨테이너를 이미지로 커밋해두면(라이브러리 포함) 재사용:
```sh
docker commit optee-build optee-runner:latest      # 1회
docker run --rm --security-opt seccomp=unconfined \
  -v <리포>/optee:/optee -w /optee/build optee-runner:latest \
  bash -lc 'export PATH=/usr/local/bin:$PATH; make check XTEST_ARGS="1001"'
```
- `XTEST_ARGS="1001"` → 게스트에서 `xtest 1001`(regression 서브셋). 비우면 전체 regression.
- `make check`는 `all`에 의존하므로 먼저 소스 최신여부를 재확인(대개 no-op).
- 실패 로그를 보려면 `DUMP_LOGS_ON_ERROR=1`.

## 결과 (통과 캡처)
```
Running: xtest 1001...
Status: PASS (10 test cases)
Running: keyctl tests...   Status: keyctl tests successful
Test Rust example applications ... 전부 Test success
[make check exit=0]
```
→ TF-A(EL3) → OP-TEE OS(secure world) → U-Boot → Linux 부팅 후, **TEE 테스트가 secure world에서 통과**.

## 배운 것
- `make check` = CI/헤드리스용. `make run` = 대화형(xterm).
- exit code 0 자체가 xtest 통과의 증거(qemu-check.exp가 판정).
- secure world 로그는 별도 시리얼(serial1.log)로 분리 → 두 세계 격리를 로그에서도 확인.

## 다음
- [ ] 내 TA 작성 → [../ta/](../ta/) (optee_examples의 hello_world를 읽고 시작)
