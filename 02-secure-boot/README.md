# 02 · Secure Boot (verified boot)

서명된 이미지만 부팅되고, **변조하면 부팅이 거부**되는 체인을 구현한다.

## 목표 / 완료 기준
- [x] U-Boot **FIT verified boot** — 커널+dtb를 서명하고 U-Boot가 검증 (셸 우회 확인은 남음)
- [x] **TF-A 인증 부팅체인**(BL1→BL2 이미지 인증) -- `make arm-tf TF_A_TRUSTED_BOARD_BOOT=y`
- [x] 공격 데모: 서명 바이트 flip → "부팅 거부" 확인 (규칙 3) -- 아래 [A][B][C]
- [ ] writeup + "왜": FIT verified boot vs UEFI Secure Boot

## 위협모델 (← 내가 작성)
> - 무엇을 지키나 (자산): 이미지(무결성) -- bl2, bl31(tf-a), bl32(op-tee), bl33(u-boot), 커널이미지. 그리고 서명용 비밀키(기밀성, 개발사 보관), fit 서명용 비밀키
> - 공격자 능력:
>   - 바꿀 수 없는 것) rom(bl1), rotpk 해시(efuse/otp)
>   - 바꿀 수 있는 것) 플래시에 있는 공개키, 이미지, 서명값, 인증서. 정식 서명된 구버전 이미지로 교체(롤백)
>   - 할 수 있는 것) 시리얼 콘솔 접근
>   - 가정 안 함) qemu 라서 bl1 도 호스트의 파일(out/bin/bl1.bin)이고 rotpk 해시도 빌드에 박힌 값. 호스트 파일을 바꿀 수 있는 공격자는 범위 밖
> - 막는 것 / 못 막는 것:
>   - 막는것) 공개키 교체, 이미지 변조, 서명값/인증서 교체
>   - 못막는것) 정식 서명된 구버전 롤백(서명이 진짜), 런타임에 메모리에 로딩된 코드를 바꾸는 공격(부팅 때 한 번만 검증), 서명용 비밀키 유출
> - 무엇이 깨지면 실패로 보나:
>   1) 이미지 변조했는데 booting 찍히고 부팅이 계속됨
>   2) 공개키 교체했는데 해시 비교에서 verify 찍히고 부팅이 계속됨
>   3) 서명값 교체했는데 이미지 서명 검증에서 통과하고 부팅이 계속됨
>   4) fit 커널을 변조했는데 부팅됨

## 공격 데모 결과 (2026-11-18, QEMU + TF-A v2.14.0 TBB)

BL1 이 BL2 를 믿기까지 하는 일 (`bl_common.c` load_auth_image_recursive, `auth_mod.c`):

```
tb_fw.crt = [본문: 루트공개키 | bl2해시 | nv카운터] + [서명 = 루트비밀키로 서명(hash(본문))]

BL1 (1) hash(본문.루트공개키) == OTP 의 ROTPK 해시 ?      auth_mod.c:267
    (2) 본문.루트공개키로 서명 검증, hash(본문)과 맞나 ?  auth_mod.c:294
    (3) hash(bl2.bin) == 본문.bl2해시 ?                   id=1 auth_hash
    셋 다 통과 -> BL2 로 점프
```

부모(인증서 id=6)를 "로드 -> 검증"한 뒤에야 자식(bl2 id=1)을 로드한다. 그래서 인증서에서 실패하면 bl2 는 읽지도 않는다.

| 실험 | 공격자가 바꾼 것 | 예측 | 실패한 검사 | id=1 로드 | 실패 기준 |
|---|---|---|---|---|---|
| [A] | bl2.bin 1바이트 (0x100) | BL1 로그 뒤 정지, 주체 BL1 -- 맞음 | (3) 해시 비교 | 함 | 1 통과 |
| [B] | tb_fw.crt 서명 1바이트 (1100) | `Loading image id=6` 까지 -- `Image id=6 loaded` 한 줄 더 나옴 | (2) 서명 검증 | 안 함 | 3 통과 |
| [C] | 공격자 키쌍으로 인증서 새로 생성 + 변조 bl2 | 공개키 해시 비교에서 실패 -- 맞음 (id=1 은 모르겠음) | (1) ROTPK 해시 비교 | 안 함 | 2 통과 |

- 세 경우 모두 마지막 줄은 `ERROR: Failed to load BL2 firmware.` 로 같다. INFO 레벨에선 **직전에 어느 id 까지 로드됐나**로 구분, 원인 줄은 LOG_LEVEL=50(VERBOSE)에서만 나온다 (`[TBB] auth_signature():271 failed`).
- LOG_LEVEL=50 재실행 (2026-11-19, [A][B] 추가) -- 원인 줄로 셋이 갈린다. 예측(A: 다른 함수 + 코드 2, B: 271 과 다른 줄) 맞음.

  | 실험 | id=1 로드 | VERBOSE 원인 줄 | 에러 코드 (`crypto_mod.h`) |
  |---|---|---|---|
  | [A] | 함 | `auth_hash():122` | 2 CRYPTO_ERR_HASH |
  | [B] | 안 함 | `auth_signature():301` (서명 검증) | 3 CRYPTO_ERR_SIGNATURE |
  | [C] | 안 함 | `auth_signature():271` (ROTPK 해시 비교) | 2 CRYPTO_ERR_HASH |

  [A] 와 [C] 는 코드가 같아 함수/줄로 구분해야 한다. 양산 빌드는 VERBOSE 가 꺼져 있으니 id 로 좁히고 VERBOSE 빌드로 재현하는 순서.
- `Image id=6 loaded` 는 검증 결과가 아니라 파일을 메모리에 다 읽었다는 load_image() 로그다.
- [C] 에서 공격자 인증서는 자기 공개키로 자기 서명을 보증하는 self-signed 구조라 서명만으론 아무것도 증명 못 한다. 키를 믿는 근거는 (1) OTP 해시뿐 -- 위협모델의 "바꿀 수 없는 것"이 실제로 막은 지점.
- 검증 실패한 이미지는 메모리에서 0 으로 지운다 (`zero_normalmem`).
- 미확인: [C] 공격자 인증서의 서명 자체가 유효한지는 (2) 까지 안 가서 이번 실행으로 확인 못 함.

그림: `notes/tbb-attack-{A,B,C}.png` (생성: `notes/tbb-attack.gen.py`)

## FIT verified boot (2026-11-18)

TF-A 체인은 BL33(U-Boot)까지만 덮고, 원래 U-Boot 는 uImage 를 검증 없이 bootm 했다(커널이 체인 밖).
또 U-Boot 의 DTB 는 QEMU 가 RAM 에 주는 것(`CONFIG_OF_BOARD`)이라 bl33 해시 밖이었다
(`u-boot.bin == u-boot-nodtb.bin` 확인, `board_fdt_blob_setup()`).

구성: FIT 공개키를 U-Boot 자신의 DTB(`/signature/key-fitdev`, required=conf)에 넣고, 그 DTB 를 u-boot.bin 뒤에 붙인다
-> TF-A 의 bl33 해시(nt_fw_content.crt)가 공개키까지 덮는다 -> U-Boot 가 그 키로 kernel.itb 의 conf-1 서명 검증 -> 이미지별 해시 비교.
그림: `notes/fit-chain.png`. 빌드: `fit/build-fit.sh` (its, kconfig 조각 같은 디렉토리).

- 서명 대상 = 구성 노드의 이름 문자열(kernel-1, fdt-1..) + 각 이미지의 해시값 + 노드 속성. 데이터 자체는 해시로 간접 보호.
- FIT 키는 루트 키와 분리: 커널은 자주 서명 -> 유출돼도 펌웨어 체인은 안전, 새 공개키 넣은 U-Boot 로 교체. 단 옛 U-Boot 롤백엔 NV 카운터 필요.
- 커널용 dtb 는 QEMU dumpdtb 가 아니라 게스트 `/sys/firmware/fdt` 를 썼다. 부팅 중 OP-TEE 가 psci, /firmware/optee, reserved-memory 를 RAM 의 DTB 에 넣기 때문(둘을 비교해 확인).
- U-Boot `scripts/check-of.sh` 가 QEMU 에서 OF_BOARD 끄는 걸 막는다 -> make 변수 `cmd_ofcheck=true` 로 우회(소스 수정 없음). 부팅 시 "Unexpected devicetree source" 경고는 남는다.

| 실험 | 예측 | 결과 |
|---|---|---|
| 정상 부팅 | - | conf 서명 `sha256,rsa2048:fitdev+ OK` -> 이미지 해시 `sha256+ OK` x3 -> 커널, secure_mac [1]-[5] 동일 |
| [D] itb 안 커널 1바이트 변조 (재서명 안 함) | 커널 해시 줄에서 실패 -- 맞음 | 서명 OK, `sha256 error!` -> `Bad Data Hash` -> `can't get kernel image!`. 실패 기준 4 통과 |
| [E] 위 상태 + 시리얼 콘솔 (`fit/shell-bypass.exp`) | 셸 안 뜸, booti 안 됨 -- **둘 다 틀림** | 실패 직후 `=>` 셸. `load hostfs Image` + `booti` 로 **무서명 커널이 login 까지 부팅** |
| [E'] 하드닝 후 같은 공격 | - | 배너 직후 키 20번 연타해도 셸 없음, 검증 실패 -> `resetting ...` -> 재부팅. 정상 부팅/secure_mac 동일 |

[E] 에서 배운 것: FIT 서명 검증은 "bootm 으로 FIT 를 올릴 때"만 강제된다. U-Boot 기본값은 개발 편의라
bootcmd 실패 -> 셸, autoboot 중 키 입력 -> 셸이고, 셸의 booti 는 서명을 안 본다. 체인을 다 붙여도 마지막 단계가 명령줄을 내주면 끝.
-> 위협모델 공격자 능력에 "시리얼 콘솔 접근" 추가, 하드닝(`fit/u-boot-fit.conf`):

- bootcmd 끝에 `; reset` -- 실패하면 셸이 아니라 재부팅 (fail-secure, 대신 변조 itb 면 무한 리셋 = 가용성 손실)
- `BOOTDELAY=-2` -- autoboot 중단 검사 안 함
- `ENV_IS_NOWHERE` -- 플래시 env 의 bootcmd 를 공격자가 바꾸는 길 차단 (원래 `Loading Environment from Flash`)
- `CMD_BOOTZ/GO/BOOTEFI` 제거 (심층 방어). `booti` 는 못 뺌: arm64 bootm 이 `booti_setup()` 을 씀 (`boot/bootm.c:676`) -> 셸 차단이 유일한 방어선

## 연결
- 01의 TEE는 **이 부팅체인만큼만 신뢰**된다. 04의 HSM 키로 여기 이미지를 서명하면 02↔04 연결.
