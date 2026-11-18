#!/usr/bin/env python3
"""TF-A TBB + U-Boot FIT verified boot 전체 신뢰 체인 (지금 vs 목표). SVG + PNG.
   python3 fit-chain.gen.py <outdir>
"""
import os
import sys
from xml.sax.saxutils import escape

F = "NanumGothic, sans-serif"
M = "NanumGothicCoding, monospace"
W, H = 1900, 1130
C = {
    "rom": ("#f2f2f2", "#666666"), "tfa": ("#e8f0fb", "#3b6fb6"),
    "ub": ("#e7f5ec", "#2e8b57"), "fit": ("#fff4e0", "#c77700"),
    "bad": ("#fdecea", "#c0392b"), "key": ("#f4ecfb", "#7d4cad"),
    "txt": "#1d1d1f", "sub": "#555555",
}


def text(x, y, s, size=16, color=None, weight="normal", font=F, anchor="start"):
    return (f'<text x="{x}" y="{y}" font-family="{font}" font-size="{size}" '
            f'fill="{color or C["txt"]}" font-weight="{weight}" '
            f'text-anchor="{anchor}" xml:space="preserve">{escape(s)}</text>')


def box(o, x, y, w, h, kind, title, lines=(), dash=False, mono=False):
    bg, bd = C[kind]
    d = ' stroke-dasharray="8,5"' if dash else ""
    o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{bg}" '
             f'stroke="{bd}" stroke-width="2.5"{d}/>')
    o.append(text(x + 12, y + 26, title, 17, bd, "bold"))
    for i, s in enumerate(lines):
        o.append(text(x + 12, y + 52 + i * 23, s, 14, font=M if mono else F))


def arr(o, x1, y1, x2, y2, label="", color="#555", dash=False, ly=-40):
    d = ' stroke-dasharray="7,5"' if dash else ""
    o.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" '
             f'stroke-width="2.5" marker-end="url(#ah)"{d}/>')
    if label:
        o.append(text((x1 + x2) / 2, (y1 + y2) / 2 + ly, label, 14, color, anchor="middle"))


def chain(o, y0, target):
    """한 줄짜리 부팅 체인. target=False 면 지금 상태."""
    bh = 175
    # ROM/OTP
    box(o, 30, y0, 210, bh, "rom", "BL1 + OTP", ["Mask ROM (못 바꿈)", "OTP: ROTPK 해시", "", "[A][B][C] 로 확인"])
    # BL2
    arr(o, 240, y0 + 80, 290, y0 + 80, "검증")
    box(o, 290, y0, 250, bh, "tfa", "BL2", ["tb_fw.crt 로 검증됨", "(루트 키)"])
    # BL31/32 (side)
    arr(o, 540, y0 + 80, 600, y0 + 80, "검증")
    box(o, 600, y0, 330, bh, "tfa", "BL2 가 BL33 검증", [
        "trusted_key.crt   (루트 키 서명)",
        " -> nt_fw_key.crt  (NT world 키)",
        " -> nt_fw_content.crt",
        "     = hash(bl33.bin)",
        "(BL31/BL32 도 같은 식, 생략)"], mono=False)
    # BL33 u-boot
    arr(o, 930, y0 + 80, 990, y0 + 80, "검증")
    if target:
        box(o, 990, y0, 360, bh, "ub", "BL33 = u-boot.bin", [
            "u-boot-nodtb.bin (코드)",
            "+ u-boot.dtb  <- 빌드 때 붙임",
            "    /signature/key-fit",
            "      FIT 공개키 (mkimage -K)",
            "bl33 해시가 공개키까지 덮음"])
    else:
        box(o, 990, y0, 360, bh, "ub", "BL33 = u-boot.bin", [
            "u-boot-nodtb.bin (코드) 만",
            "u-boot.bin == u-boot-nodtb.bin",
            "(확인함, cmp 동일)",
            "DTB 는 안에 없음"])
        # QEMU DTB (outside chain)
        box(o, 990, y0 + bh + 40, 360, 100, "bad", "DTB: QEMU 가 RAM 에 만들어 줌",
            ["CONFIG_OF_BOARD=y", "board_fdt_blob_setup() 이 그대로 씀 -> 검증 안 됨"])
        arr(o, 1170, y0 + bh + 40, 1170, y0 + bh + 2, "", C["bad"][1], dash=True)
    # kernel
    arr(o, 1350, y0 + 80, 1410, y0 + 80, "검증" if target else "없음",
        "#555" if target else C["bad"][1], dash=not target)
    if target:
        box(o, 1410, y0, 460, bh, "fit", "kernel.itb (FIT)", [
            "/images/kernel-1  data + hash",
            "/images/fdt-1     data + hash",
            "/images/ramdisk-1 data + hash",
            "/configurations/conf-1 + signature",
            "bootm: 서명 -> 각 이미지 해시"], mono=True)
    else:
        box(o, 1410, y0, 460, bh, "bad", "uImage (legacy) + rootfs", [
            "load hostfs - ... uImage",
            "bootm ${kernel_addr_r} ...",
            "",
            "커널은 체인 밖 -- 바꿔도 부팅됨",
            "(위협모델 자산인데 비어 있음)"])


def main():
    out = sys.argv[1]
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
         '<defs><marker id="ah" markerWidth="10" markerHeight="10" refX="9" refY="5" '
         'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#555"/></marker></defs>',
         f'<rect width="{W}" height="{H}" fill="#fff"/>']
    o.append(text(30, 44, "Secure Boot 전체 신뢰 체인 -- TF-A TBB + U-Boot FIT verified boot", 26, weight="bold"))
    o.append(text(30, 74, "각 단계는 다음 단계를 검증하고 나서 넘겨준다. 한 칸이라도 검증 없이 넘어가면 그 뒤는 전부 못 믿는다.", 17, C["sub"]))

    o.append(text(30, 122, "지금 (2026-11-18 빌드)", 21, C["bad"][1], "bold"))
    chain(o, 140, False)

    o.append(f'<line x1="30" y1="485" x2="{W - 30}" y2="485" stroke="#ccc" stroke-width="2"/>')
    o.append(text(30, 528, "목표 (FIT verified boot 적용 후)", 21, C["ub"][1], "bold"))
    chain(o, 546, True)

    # 키 패널
    ky = 760
    box(o, 30, ky, 900, 340, "key", "키 3 종류 -- 누가 무엇을 서명/검증하나", [])
    rows = [
        ("키", "비밀키 (서명, 개발사/HSM)", "공개키를 믿는 근거"),
        ("루트 키", "tb_fw.crt, trusted_key.crt", "OTP 의 ROTPK 해시 (못 바꿈)"),
        ("NT world 키", "nt_fw_key/content.crt", "trusted_key.crt 안 (루트 키가 보증)"),
        ("FIT 키 (새로)", "kernel.itb 의 conf 서명", "u-boot.dtb 안 (bl33 해시가 보증)"),
    ]
    for i, (a, b, c) in enumerate(rows):
        yy = ky + 66 + i * 40
        wgt = "bold" if i == 0 else "normal"
        o.append(text(50, yy, a, 15, weight=wgt))
        o.append(text(220, yy, b, 15, weight=wgt))
        o.append(text(530, yy, c, 15, weight=wgt))
    o.append(text(50, ky + 250, "FIT 키를 루트 키와 나누는 이유: 커널은 자주 서명 -> 유출 기회 많음.", 15))
    o.append(text(50, ky + 276, "FIT 키가 새도 펌웨어 체인은 안전, 새 공개키를 넣은 U-Boot 로 교체하면 복구.", 15))
    o.append(text(50, ky + 302, "단 옛 U-Boot 로 롤백하면 옛 키가 살아남 -> NV 카운터 필요 (위협모델 '못 막는 것').", 15))

    # 할 일 패널
    box(o, 970, ky, 900, 340, "ub", "목표로 가려면 (해야 할 일)", [
        "(1) FIT 키쌍 생성 (openssl, RSA-2048)",
        "(2) kernel.its 작성: kernel + fdt + ramdisk, conf 에 signature",
        "(3) mkimage -f kernel.its -k <키dir> -K u-boot.dtb -r kernel.itb",
        "     -> itb 에 서명, u-boot.dtb 에 공개키 기록 (required = conf)",
        "(4) U-Boot: OF_BOARD 끄고 u-boot.dtb 를 u-boot.bin 에 붙여 빌드",
        "     -> TF-A 가 bl33 을 다시 서명 (cert 갱신)",
        "(5) BOOTCOMMAND: load hostfs kernel.itb -> bootm",
        "(6) 공격 데모: itb 안 커널 1바이트 변조 -> bootm 거부?",
        "",
        "미확인: QEMU DTB 없이 U-Boot 가 뜨는지 (메모리/장치 정보)",
    ])
    o.append("</svg>")
    svg = "\n".join(o)
    p = os.path.join(out, "fit-chain")
    with open(p + ".svg", "w") as f:
        f.write(svg)
    import cairosvg
    cairosvg.svg2png(bytestring=svg.encode(), write_to=p + ".png")
    print(p + ".png")


if __name__ == "__main__":
    main()
