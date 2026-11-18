# OP-TEE build 시스템에 얹는 실행 타깃.
#   make -f lab-run.mk lab-run LAB_CMD="optee_example_secure_mac"
# 공식 Makefile 을 그대로 include 해 QEMU_BIN/QEMU_CHECK_ARGS 를 재사용한다.
include Makefile

LAB_CMD ?= xtest 1001

.PHONY: lab-run
lab-run:
	ln -sf $(ROOT)/out-br/images/rootfs.cpio.gz $(BINARIES_PATH)/
	cd $(BINARIES_PATH) && \
		export QEMU=$(QEMU_BIN) && \
		export QEMU_CHECK_ARGS="$(QEMU_CHECK_ARGS)" && \
		export LAB_CMD="$(LAB_CMD)" && \
		export LAB_SCRIPT="$(LAB_SCRIPT)" && \
		expect $(ROOT)/build/lab-run.exp
