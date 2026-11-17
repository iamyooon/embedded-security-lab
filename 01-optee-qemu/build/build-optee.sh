#!/bin/bash
# OP-TEE qemu_v8 전체 스택 빌드 (Ubuntu 22.04 컨테이너).
# root로 의존성 설치 → 빌드 유저(uid1000)로 재실행해 빌드(buildroot는 root 실행 거부).
# 마운트: 호스트 <리포>/optee ↔ 컨테이너 /optee
# 2026-11-17: 서버 이전(16.04 -> 24.04, /data 소멸)으로 경로 변수화, 빌드 유저를 컨테이너에서 직접 생성,
#             메모리 4GB 라 병렬도를 JOBS(기본 3)로 제한.
# 호스트에서 실행:
#   docker run --name optee-build --security-opt seccomp=unconfined \
#     -v <리포>/optee:/optee ubuntu:22.04 bash /optee/build-optee.sh
#   docker commit optee-build optee-runner:latest   # 빌드 끝난 뒤 1회
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
  LOG "root 완료 → 빌드 유저($BUILD_USER)로 전환"
  id -u 1000 >/dev/null 2>&1 || { groupadd -g 1000 builder; useradd -m -u 1000 -g 1000 -s /bin/bash builder; }
  BUILD_USER=$(id -un 1000)
  exec su "$BUILD_USER" -c "JOBS=${JOBS:-3} bash /optee/build-optee.sh"
fi

# ---- 빌드 유저 (uid 1000) ----
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
make -j"${JOBS:-3}"
LOG "===== OP-TEE BUILD DONE ====="
ls -la /optee/out 2>/dev/null || true
