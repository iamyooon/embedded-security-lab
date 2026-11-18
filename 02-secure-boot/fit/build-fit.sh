#!/bin/bash
# FIT verified boot 빌드:
#   (1) 런타임 DTB -> kernel-fdt.dtb(FIT 안) / ctrl.dtb(U-Boot 자신의 DTB, 공개키 들어갈 곳)
#   (2) U-Boot 를 OF_SEPARATE 로 재빌드
#   (3) mkimage: kernel.itb 서명 + ctrl.dtb 에 공개키 기록(required=conf)
#   (4) u-boot-fit.bin = u-boot-nodtb.bin + ctrl.dtb
#   (5) TF-A 재빌드 -> bl33(u-boot.bin) 해시가 들어간 nt_fw_content.crt 재생성
#
# 전제: optee/out/fit/{runtime.dtb, keys/fitdev.key, keys/fitdev.crt} 가 있다.
#   runtime.dtb  : 게스트의 /sys/firmware/fdt (OP-TEE 가 psci/optee 노드를 넣은 최종본)
#   keys/        : FIT 서명 키쌍. 비밀키라 리포에 안 넣는다 (optee/ 는 .gitignore).
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
OPTEE="${OPTEE_DIR:-$HERE/../../optee}"
FIT="$OPTEE/out/fit"
IMG=optee-runner:latest

cp "$HERE/kernel.its" "$HERE/u-boot-fit.conf" "$FIT/"

drun() {
	docker run --rm --security-opt seccomp=unconfined \
		-u 1000:1000 -e HOME=/tmp -v "$OPTEE":/optee -w "$1" \
		"$IMG" bash -lc "export PATH=/usr/local/bin:\$PATH; set -e; $2"
}

DTC=/optee/u-boot/scripts/dtc/dtc
MKIMAGE=/optee/u-boot/tools/mkimage
UBOOT_FRAGS="/optee/u-boot/configs/qemu_arm64_defconfig /optee/build/kconfigs/u-boot_qemu_v8.conf /optee/out/fit/u-boot-fit.conf"

echo "== (1) DTB 준비"
drun /optee/out/fit "
	$DTC -q -I dtb -O dts runtime.dtb | grep -v 'linux,initrd-' > kernel-fdt.dts
	$DTC -q -I dts -O dtb -o kernel-fdt.dtb kernel-fdt.dts
	$DTC -q -I dts -O dtb -p 8192 -o ctrl.dtb kernel-fdt.dts
	ln -sf /optee/linux/arch/arm64/boot/Image Image
	ln -sf /optee/out-br/images/rootfs.cpio.gz rootfs.cpio.gz"

echo "== (2) U-Boot 재빌드 (OF_SEPARATE)"
rm -f "$OPTEE/u-boot/.config"
# scripts/check-of.sh 는 "앞 단계가 DTB 를 주는 보드(QEMU)는 OF_BOARD 를 켜라"는 정책 검사다.
# 공개키를 bl33 안에 넣으려고 일부러 끄는 것이라 make 변수로 그 검사만 건너뛴다(소스 수정 없음).
drun /optee/build "make u-boot UBOOT_DEFCONFIG_FILES='$UBOOT_FRAGS' UBOOT_COMMON_FLAGS='CROSS_COMPILE=\$(CROSS_COMPILE_NS_KERNEL) cmd_ofcheck=true'"
grep -E '^CONFIG_OF_(SEPARATE|BOARD)|^# CONFIG_OF_BOARD|LEGACY_IMAGE_FORMAT' "$OPTEE/u-boot/.config"

echo "== (3) mkimage: FIT 서명 + 공개키를 ctrl.dtb 에"
drun /optee/out/fit "$MKIMAGE -f kernel.its -k keys -K ctrl.dtb -r kernel.itb"

echo "== (4) u-boot-fit.bin = u-boot-nodtb.bin + ctrl.dtb  (u-boot.bin 의 make 규칙과 같은 단순 cat)"
cat "$OPTEE/u-boot/u-boot-nodtb.bin" "$FIT/ctrl.dtb" > "$FIT/u-boot-fit.bin"
ln -sf /optee/out/fit/kernel.itb "$OPTEE/out/bin/kernel.itb"

echo "== (5) TF-A 재빌드 (bl33 재서명)"
# BL33_DEPS 를 비워 u-boot 를 다시 make 하지 않게 하고, BL33 을 우리 파일로 지정
drun /optee/build "make arm-tf TF_A_TRUSTED_BOARD_BOOT=y TF_A_LOGLVL=${TF_A_LOGLVL:-50} BL33_BIN=/optee/out/fit/u-boot-fit.bin BL33_DEPS="
ls -l "$OPTEE/out/bin/bl33.bin" "$OPTEE/out/bin/nt_fw_content.crt" "$FIT/u-boot-fit.bin" "$FIT/kernel.itb"
