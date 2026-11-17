#!/bin/bash
# vi 에서 TA/CA API 를 찾아 쓰기 위한 ctags + cscope 인덱스를 리포 루트에 만든다.
#   ./make-tags.sh        (호스트에 universal-ctags, cscope 필요)
# 범위: 내 TA/CA 코드 + GP TEE Internal API(libutee) + libutils + libteec(CA 쪽) + optee_examples(참고 구현)
# 사용: 리포 루트에서 vi 를 띄운다(~/.vimrc 가 ./tags, ./cscope.out 을 읽음).
#   vi 01-optee-qemu/ta/secure_mac/ta/secure_mac_ta.c
#   Ctrl-]  정의로 이동 / Ctrl-t 복귀 / :cs find s TEE_MACInit
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
O="$ROOT/optee"
cd "$ROOT"

find "$ROOT/01-optee-qemu/ta" \
     "$O/optee_os/lib/libutee" \
     "$O/optee_os/lib/libutils" \
     "$O/optee_client/libteec" \
     "$O/optee_examples" \
     -type f \( -name '*.[ch]' \) -not -path '*/out/*' > cscope.files

ctags -L cscope.files -f tags --c-kinds=+p --fields=+iaS --extras=+q
cscope -b -q -k -i cscope.files
echo "files: $(wc -l < cscope.files)  -> $ROOT/{tags,cscope.out}"
