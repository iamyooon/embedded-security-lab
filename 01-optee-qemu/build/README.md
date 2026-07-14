# OP-TEE `qemu_v8` 빌드 (공식 방식 A)

OP-TEE는 `repo` + 매니페스트로 전체 스택(TF-A · OP-TEE OS · U-Boot/edk2 · Linux · buildroot · **QEMU까지**)을 한 번에 받아 빌드한다.

## 왜 컨테이너인가
호스트가 Ubuntu 16.04/Python 3.5라 최신 빌드가 안 됨 → **Ubuntu 22.04 Docker 컨테이너**에서 빌드(우리 RPi4 작업과 같은 패턴). 체크아웃/산출물은 대용량(~15GB+)이라 **`/data/optee`** 에 두고 git 제외.

## 절차 (요약 — 실제 실행은 Claude가 컨테이너로)
```sh
# 컨테이너(Ubuntu 22.04) 안, /data/optee 에서
apt-get install -y android-tools-adb ... python3 repo git \
    gcc build-essential ...            # OP-TEE 문서의 prerequisites
repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml
repo sync -j$(nproc)                    # TF-A/OP-TEE/U-Boot/Linux/QEMU 소스
cd build
make toolchains -j2                     # 크로스 툴체인
make -j$(nproc)                         # 전체 빌드 (수십 분)
make run                                # QEMU 부팅: normal + secure 콘솔 2개
# normal 콘솔에서:  xtest         ← OP-TEE 테스트 스위트 통과 확인
```

## 확인 포인트 (배우는 관점)
- 부팅 로그에 `OP-TEE` secure world 초기화가 뜨는가 (BL32).
- `xtest` 가 secure storage/crypto 테스트를 통과하는가.
- 콘솔이 왜 2개인가 → normal world / secure world 로그 분리.

## 상태
- [ ] 컨테이너 빌드 환경 구성
- [ ] repo sync + 빌드
- [ ] `make run` → `xtest` 통과 캡처
- [ ] (다음) 내 TA 추가 → [../ta/](../ta/)

> 참고: 실제 빌드 산출물(`/data/optee`)은 이 repo에 포함하지 않는다. 여기엔 빌드 스크립트/절차/결과 캡처/writeup만 커밋.
