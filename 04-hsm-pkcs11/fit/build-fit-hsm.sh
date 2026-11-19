#!/bin/bash
# 04: 02 의 FIT 를 파일 키(fitdev.key) 대신 SoftHSM 토큰 안의 키(fithsm)로 서명한다.
#   (1) SoftHSM 토큰 + 키쌍 생성 (never extractable)  -- 토큰 저장소: optee/out/fit/hsm-tokens (git 제외)
#   (2) mkimage -N pkcs11 : kernel-hsm.itb 서명 + ctrl-hsm.dtb 에 공개키(/signature/key-fithsm)
#   (3) u-boot-fit-hsm.bin = u-boot-nodtb.bin(02 에서 만든 OF_SEPARATE + 하드닝 빌드) + ctrl-hsm.dtb
#   (4) TF-A 재빌드 -> bl33 해시 재서명
# 전제: 02-secure-boot/fit/build-fit.sh 를 한 번 돌려 u-boot-nodtb.bin, kernel-fdt.dts, kernel.its 가 있다.
# 주의: PIN 을 명령줄(pkcs11 URI)에 넣는다 -> ps 로 보인다. 실습 편의. 실제로는 서명 서버 분리/승인 필요.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
LAB04="$HERE/.."
OPTEE="${OPTEE_DIR:-$HERE/../../optee}"
FIT="$OPTEE/out/fit"
PIN="${PIN:-1234}"
mkdir -p "$FIT/hsm-tokens"

hsm() {
	docker run --rm -u 1000:1000 -e HOME=/tmp \
		-e SOFTHSM2_CONF=/lab04/docker/softhsm2.conf -e OPENSSL_CONF=/lab04/docker/openssl-pkcs11.cnf \
		-v "$OPTEE":/optee -v "$LAB04":/lab04 -w /optee/out/fit hsm-lab bash -c "set -e; $1"
}
M=/usr/lib/softhsm/libsofthsm2.so

echo "== (1) 토큰/키"
hsm "pkcs11-tool --module $M -L | grep -qE 'token label +: fit$' || softhsm2-util --init-token --free --label fit --pin $PIN --so-pin 5678
     pkcs11-tool --module $M --login --pin $PIN -O --type privkey 2>/dev/null | grep -q fithsm || \
       pkcs11-tool --module $M --login --pin $PIN --keypairgen --key-type rsa:2048 --id 02 --label fithsm
     pkcs11-tool --module $M --login --pin $PIN -O --type privkey | grep -E 'label|Access'"

echo "== (2) mkimage -N pkcs11"
hsm "/optee/u-boot/scripts/dtc/dtc -q -I dts -O dtb -p 8192 -o ctrl-hsm.dtb kernel-fdt.dts
     sed 's/key-name-hint = \"fitdev\"/key-name-hint = \"fithsm\"/' kernel.its > kernel-hsm.its
     /optee/u-boot/tools/mkimage -f kernel-hsm.its -N pkcs11 -k 'pkcs11:token=fit;pin-value=$PIN' -K ctrl-hsm.dtb -r kernel-hsm.itb | grep -E 'Sign algo|written'
     /optee/u-boot/tools/fit_check_sign -f kernel-hsm.itb -k ctrl-hsm.dtb | grep -E 'Signature check'"

echo "== (3) u-boot-fit-hsm.bin"
cat "$OPTEE/u-boot/u-boot-nodtb.bin" "$FIT/ctrl-hsm.dtb" > "$FIT/u-boot-fit-hsm.bin"
ln -sf /optee/out/fit/kernel-hsm.itb "$OPTEE/out/bin/kernel.itb"

echo "== (4) TF-A 재빌드"
docker run --rm --security-opt seccomp=unconfined -u 1000:1000 -e HOME=/tmp -v "$OPTEE":/optee -w /optee/build optee-runner:latest \
	bash -lc "export PATH=/usr/local/bin:\$PATH; make arm-tf TF_A_TRUSTED_BOARD_BOOT=y TF_A_LOGLVL=\${TF_A_LOGLVL:-40} BL33_BIN=/optee/out/fit/u-boot-fit-hsm.bin BL33_DEPS= >/dev/null"
echo "부팅: (optee/build) make -f lab-run.mk lab-run TF_A_TRUSTED_BOARD_BOOT=y BL33_BIN=/optee/out/fit/u-boot-fit-hsm.bin BL33_DEPS="
