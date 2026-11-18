# [E] 셸 우회 실험 실행 타깃. lab-run.mk 와 같은 방식으로 공식 Makefile 의 QEMU 인자를 재사용한다.
#   make -f fit-shell.mk fit-shell TF_A_TRUSTED_BOARD_BOOT=y BL33_BIN=/optee/out/fit/u-boot-fit.bin BL33_DEPS=
include Makefile

.PHONY: fit-shell
fit-shell:
	cd $(BINARIES_PATH) && \
		export QEMU=$(QEMU_BIN) && \
		export QEMU_CHECK_ARGS="$(QEMU_CHECK_ARGS)" && \
		expect $(ROOT)/build/shell-bypass.exp
