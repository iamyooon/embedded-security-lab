#!/bin/bash
# OP-TEE qemu_v8 전체 스택 빌드 (Ubuntu 22.04 컨테이너).
# root로 의존성 설치 → yoctouser(uid1000)로 재실행해 빌드(buildroot는 root 실행 거부).
# 마운트: 호스트 /data/optee ↔ 컨테이너 /optee
set -e
exec >> /optee/optee-build.log 2>&1
LOG(){ echo "[$(date +%F' '%H:%M:%S)] $*"; }

if [ "$(id -u)" = "0" ]; then
  LOG "===== root: prerequisites 설치 ====="
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq \
    acpica-tools autoconf automake bc bison build-essential ccache cpio cscope \
    curl device-tree-compiler e2fsprogs expect fastboot flex ftp-upload gdisk git \
    libattr1-dev libcap-ng-dev libfdt-dev libftdi-dev libglib2.0-dev libgmp3-dev \
    libgnutls28-dev libhidapi-dev libmpc-dev libncurses5-dev libpixman-1-dev libslirp-dev libssl-dev \
    libtool libusb-1.0-0-dev make mtools netcat ninja-build python3 python3-pip \
    python3-cryptography python3-pyelftools python3-serial python-is-python3 rsync \
    swig unzip uuid-dev wget xdg-utils xz-utils zlib1g-dev >/dev/null
  pip3 install -q --upgrade meson ninja tomli pyelftools
  # repo 툴
  curl -s https://storage.googleapis.com/git-repo-downloads/repo > /usr/local/bin/repo
  chmod a+x /usr/local/bin/repo
  # 로그/작업트리 소유권을 빌드 유저로
  touch /optee/optee-build.log
  chown -R 1000:1000 /optee
  LOG "root 완료 → yoctouser로 전환"
  exec su yoctouser -c "bash /optee/build-optee.sh"
fi

# ---- yoctouser (uid 1000) ----
LOG "===== OP-TEE BUILD (user) START ====="
export PATH=/usr/local/bin:$HOME/.local/bin:$PATH
git config --global user.email build@local || true
git config --global user.name  build || true
git config --global color.ui   false || true
cd /optee
if [ ! -d .repo ]; then
  LOG "repo init (qemu_v8)"
  repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml
fi
LOG "repo sync ..."
repo sync -j"$(nproc)" --no-clone-bundle
LOG "make toolchains ..."
cd build
make -j2 toolchains
LOG "make (full stack) ..."
make -j"$(nproc)"
LOG "===== OP-TEE BUILD DONE ====="
ls -la /optee/out 2>/dev/null || true
