#!/bin/bash
# 내 TA(secure_mac)를 OP-TEE 트리에 넣고 빌드 -> QEMU 부팅 -> 게스트에서 CA 실행.
#   ./run-secure-mac.sh            # 빌드 + 실행
#   ./run-secure-mac.sh build      # 빌드만
#   ./run-secure-mac.sh run        # 실행만
set -e
REPO="$(cd "$(dirname "$0")/.." && pwd)"        # 01-optee-qemu
OPTEE="${OPTEE_DIR:-$REPO/../optee}"
IMG=optee-runner:latest
MODE="${1:-all}"

echo "== TA 소스 동기화: $REPO/ta/secure_mac -> $OPTEE/optee_examples/secure_mac"
rsync -a --delete "$REPO/ta/secure_mac/" "$OPTEE/optee_examples/secure_mac/"
cp "$REPO/build/lab-run.exp" "$REPO/build/lab-run.mk" "$OPTEE/build/"
chmod +x "$OPTEE/build/lab-run.exp"

drun() {  # 컨테이너에서 uid1000(빌드 유저)로 실행. buildroot 는 root 실행을 거부한다.
	docker run --rm --security-opt seccomp=unconfined \
		-u 1000:1000 -e HOME=/tmp -v "$OPTEE":/optee -w /optee/build \
		"$IMG" bash -lc "export PATH=/usr/local/bin:\$PATH; $1"
}

if [ "$MODE" = all ] || [ "$MODE" = build ]; then
	echo "== 빌드 (optee_examples + rootfs 재생성)"
	drun "make -j${JOBS:-3}"
fi

if [ "$MODE" = all ] || [ "$MODE" = run ]; then
	echo "== QEMU 부팅 후 게스트에서 CA 실행"
	drun "make -f lab-run.mk lab-run LAB_CMD='optee_example_secure_mac'" || rc=$?
	echo "== secure world 로그(OP-TEE OS / 내 TA 의 IMSG) =="
	tail -40 "$OPTEE/out/bin/serial1.log" 2>/dev/null || true
	exit "${rc:-0}"
fi
