#!/usr/bin/env python3
"""[H2] 메모리 덤프에서 n 을 나누는 128B 조각(RSA-2048 의 소수 p, q)을 찾고, 복원한 키로 서명해 HSM 서명과 비교.
   python3 h2_recover.py core.rsa n.hex data.bin sig.bin
"""
import hashlib
import sys

core, nhex, data, sig = sys.argv[1:5]
n = int(open(nhex).read().strip(), 16)
d = open(core, 'rb').read()
found = {}
for off in range(0, len(d) - 128, 4):
    w = d[off:off + 128]
    for endian in ('big', 'little'):
        v = int.from_bytes(w, endian)
        if v.bit_length() > 1000 and n % v == 0:
            found.setdefault(v, []).append((hex(off), endian))
for v, where in found.items():
    print(f"인수 {hex(v)[:18]}... 위치 {where}")
if len(found) != 2:
    sys.exit("p, q 를 못 찾음")
p, q = found
print("p*q == n :", p * q == n)
dd = pow(65537, -1, (p - 1) * (q - 1))
di = bytes.fromhex('3031300d060960864801650304020105000420') + hashlib.sha256(open(data, 'rb').read()).digest()
em = b'\x00\x01' + b'\xff' * (256 - 3 - len(di)) + b'\x00' + di
mine = pow(int.from_bytes(em, 'big'), dd, n).to_bytes(256, 'big')
print("복원 키 서명 == HSM 서명 :", mine == open(sig, 'rb').read())
