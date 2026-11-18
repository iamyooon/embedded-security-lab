# 01 저장소 공격 데모 [S1][S2][S3] -- 게스트에서 root 로 한 줄씩 실행 (lab-run.exp LAB_SCRIPT).
#   make -f lab-run.mk lab-run LAB_SCRIPT=/optee/build/storage-attack.sh ...
# '#' 로 시작하는 줄은 보내지 않는다. 각 줄은 셸 한 줄이어야 한다.
# REE FS 파일 배치 (core/tee/tee_ree_fs.c get_offs_size): 블록 4096B, 헤더/노드/데이터 블록이 각각 vers 0/1 두 벌.
#   데이터 블록 0 = 오프셋 8192(vers 0) / 12288(vers 1). 어느 벌이 유효한지 모르니 두 벌 모두 같은 자리를 뒤집는다.
SM=optee_example_secure_mac; T=/var/lib/tee; flip() { [ -f "$1" ] || return; sz=$(wc -c < "$1"); for o in $2 $3; do [ $o -lt $sz ] || continue; b=$(dd if="$1" bs=1 skip=$o count=1 2>/dev/null | hexdump -e '1/1 "%02x"'); [ "$b" = "00" ] && v='\377' || v='\000'; printf "$v" | dd of="$1" bs=1 seek=$o count=1 conv=notrunc 2>/dev/null; n=$(dd if="$1" bs=1 skip=$o count=1 2>/dev/null | hexdump -e '1/1 "%02x"'); echo "    flip $1 @$o: $b -> $n"; done; }
echo "########## 준비: root 가 키 id=10 생성 -> 백업 -> 삭제해서 사라지는 파일 = 내 키 파일 -> 백업 복원"
sleep 5; $SM create 10; $SM mac 10
rm -rf /tmp/bak; cp -a $T /tmp/bak; ls $T > /tmp/with; echo "    백업 파일 수: $(ls /tmp/bak | wc -l)"
$SM delete 10 >/dev/null; ls $T > /tmp/without; OBJ=$(grep -vxF -f /tmp/without /tmp/with | grep -v dirf.db | head -1); echo "    내 키 파일: $T/$OBJ ($(wc -c < /tmp/bak/$OBJ) B)"
rm -rf $T/*; cp -a /tmp/bak/* $T/; $SM mac 10

echo "########## [S1] 읽기: 키 파일에 평문이 보이는가"
hexdump -C $T/$OBJ | head -6; echo "    ... (데이터 블록 0, 오프셋 0x2000)"; hexdump -C $T/$OBJ | grep -A3 "^00002000"
echo "    이 파일의 출력 가능 문자열(8자 이상) 수: $(strings -n 8 $T/$OBJ | wc -l)"

echo "########## [S2] 변조: 키 파일 데이터 블록 0 의 1바이트 (두 벌 모두)"
flip $T/$OBJ 8292 12388; $SM mac 10; $SM info 10; ls $T | grep -cx "$OBJ"

echo "########## [S2 복구] 백업 복원 -> 원래대로 쓰이는가"
rm -rf $T/*; cp -a /tmp/bak/* $T/; $SM mac 10

echo "########## [S3] 롤백: 삭제 -> 백업 복원 -> MAC"
$SM delete 10; $SM mac 10
rm -rf $T/*; cp -a /tmp/bak/* $T/; $SM mac 10; $SM info 10
