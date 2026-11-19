#!/usr/bin/env python3
"""TF-A TBBR 인증서 체인 -- 어느 BL 이 어느 인증서를 검증하고, 인증서 안에 무엇이 들었나. SVG + PNG.
   python3 cert-chain.gen.py <outdir>   (PNG 는 cairosvg 필요)
   근거: drivers/auth/tbbr/tbbr_cot_common.c, tbbr_cot_bl1.c, tbbr_cot_bl2.c, drivers/auth/auth_mod.c:217-246,
         plat/qemu/common/qemu_rotpk.S, qemu_trusted_boot.c
"""
import os
import sys
from xml.sax.saxutils import escape

F = "NanumGothic, sans-serif"
M = "NanumGothicCoding, monospace"
C = {
    "rom_bg": "#f2f2f2", "rom_bd": "#666666",
    "crt_bg": "#fff6e5", "crt_bd": "#c98a00",
    "img_bg": "#e8f0fb", "img_bd": "#3b6fb6",
    "bad_bg": "#fdecea", "bad_bd": "#c0392b",
    "ok_bg": "#e7f5ec", "ok_bd": "#2e8b57",
    "txt": "#1d1d1f", "sub": "#555555", "arrow": "#777777",
}
W, H = 1640, 1000


def text(x, y, s, size=16, color=None, weight="normal", font=F, anchor="start"):
    return (f'<text x="{x}" y="{y}" font-family="{font}" font-size="{size}" '
            f'fill="{color or C["txt"]}" font-weight="{weight}" '
            f'text-anchor="{anchor}">{escape(s)}</text>')


def rect(x, y, w, h, bg, bd, dash=False, rx=8, sw=2):
    d = ' stroke-dasharray="6,4"' if dash else ""
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" '
            f'fill="{bg}" stroke="{bd}" stroke-width="{sw}"{d}/>')


def arrow(x1, y1, x2, y2, color=None, dash=False):
    c = color or C["arrow"]
    d = ' stroke-dasharray="6,4"' if dash else ""
    return (f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{c}" '
            f'stroke-width="2"{d} marker-end="url(#ah)"/>')


def box(o, x, y, w, h, kind, title, lines, tsize=17):
    bg, bd = C[kind + "_bg"], C[kind + "_bd"]
    o.append(rect(x, y, w, h, bg, bd))
    o.append(text(x + 14, y + 26, title, tsize, bd, "bold", M))
    for i, s in enumerate(lines):
        col = C["bad_bd"] if s.startswith("!") else None
        o.append(text(x + 14, y + 50 + i * 22, s.lstrip("!"), 15, col))


def build():
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
         '<defs><marker id="ah" markerWidth="10" markerHeight="10" refX="9" refY="5" '
         'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#777"/></marker></defs>',
         f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
         text(40, 50, "TF-A 인증서 체인 -- 누가 무엇을 검증하고, 인증서 안에 무엇이 들었나", 28, weight="bold"),
         text(40, 84, "인증서 = 다음 단계의 공개키 또는 이미지 해시를 담고, 부모가 준 공개키로 서명 검증된다. "
              "루트 인증서 2개만 ROTPK 와 대조.", 17, C["sub"])]

    # ROTPK
    box(o, 40, 330, 310, 200, "rom", "ROTPK 해시", [
        "= ROT 공개키의 SHA-256",
        "실기기: OTP / eFuse",
        "!QEMU: BL1 이미지에 내장",
        "  (qemu_rotpk.S)",
        "BL1, BL2 둘 다 링크",
        "plat_get_rotpk_info()"])

    # Lane 1: BL1
    o.append(rect(390, 115, 1220, 200, "#fafafa", "#bbbbbb", rx=12))
    o.append(text(410, 143, "BL1 (ROM) 이 검증", 18, weight="bold"))
    box(o, 420, 160, 400, 135, "crt", "tb_fw.crt  (루트)", [
        "서명: ROT 비밀키",
        "담은 것: ROT 공개키, hash(BL2)",
        "검증: 공개키 해시 == ROTPK ? -> 서명 ?"])
    o.append(arrow(820, 228, 890, 228))
    o.append(text(855, 218, "hash", 13, C["sub"], anchor="middle"))
    box(o, 890, 160, 260, 135, "img", "BL2", [
        "hash(bl2.bin) ==", "tb_fw.crt 의 값 ?", "-> 맞으면 실행"])
    box(o, 1180, 160, 410, 135, "bad", "[C] 여기서 막힘", [
        "공격자 키로 만든 tb_fw.crt",
        "hash(BL2) 는 맞음, 서명도 자기 키로는 맞음",
        "!공개키 해시 != ROTPK -> 거부"])

    # Lane 2: BL2
    o.append(rect(390, 340, 1220, 600, "#fafafa", "#bbbbbb", rx=12))
    o.append(text(410, 368, "BL2 가 검증 (key 인증서 -> content 인증서 -> 이미지)", 18, weight="bold"))
    box(o, 420, 470, 350, 180, "crt", "trusted_key.crt  (루트)", [
        "서명: ROT 비밀키",
        "담은 것:",
        "  trusted_world 공개키",
        "  non_trusted_world 공개키",
        "검증: 공개키 해시 == ROTPK ?"])

    rows = [
        (390, "soc_fw_key.crt", "trusted_world 키", "soc_fw_content_pk",
         "soc_fw_content.crt", "hash(BL31)", "BL31", "EL3 모니터"),
        (530, "tos_fw_key.crt", "trusted_world 키", "tos_fw_content_pk",
         "tos_fw_content.crt", "hash(BL32)", "BL32", "OP-TEE OS"),
        (670, "nt_fw_key.crt", "non_trusted 키", "nt_fw_content_pk",
         "nt_fw_content.crt", "hash(BL33)", "BL33", "U-Boot"),
    ]
    for y, k, ksig, kpk, c, chash, img, desc in rows:
        o.append(arrow(770, 560, 840, y + 50))
        box(o, 840, y, 290, 110, "crt", k, ["서명: " + ksig, "담음: " + kpk], 16)
        o.append(arrow(1130, y + 55, 1160, y + 55))
        box(o, 1160, y, 250, 110, "crt", c, ["서명: 왼쪽 content_pk", "담음: " + chash], 16)
        o.append(arrow(1410, y + 55, 1440, y + 55))
        box(o, 1440, y, 150, 110, "img", img, [desc, "hash 대조"], 16)

    # FIT
    o.append(arrow(1515, 780, 1515, 810))
    box(o, 1160, 810, 430, 110, "ok", "kernel.itb (FIT) -- U-Boot 이 검증 [D]", [
        "공개키: u-boot.dtb 안 (BL33 해시가 덮음)",
        "TF-A 인증서 체인 밖, 별도 FIT 키"], 16)

    # 규칙 박스
    box(o, 420, 790, 700, 130, "rom", "규칙", [
        "부모 인증서가 담은 공개키로 자식 인증서 서명을 검증한다.",
        "부모가 없는 루트 인증서(parent=NULL)만 ROTPK 해시와 대조한다.",
        "이미지는 서명이 없고, 바로 위 인증서의 해시와만 비교한다."], 16)

    # ROTPK -> 루트 인증서 점선
    o.append(arrow(350, 380, 420, 250, C["bad_bd"], dash=True))
    o.append(arrow(350, 480, 420, 540, C["bad_bd"], dash=True))

    o.append(text(40, 970, "근거: drivers/auth/tbbr/tbbr_cot_{common,bl1,bl2}.c (parent / pk / 담는 값), "
                  "auth_mod.c:217-246 (ROTPK 대조), plat/qemu/common/qemu_rotpk.S", 15, C["sub"]))
    o.append("</svg>")
    return "\n".join(o)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(out, "cert-chain")
    svg = build()
    with open(p + ".svg", "w") as f:
        f.write(svg)
    try:
        import cairosvg
        cairosvg.svg2png(bytestring=svg.encode(), write_to=p + ".png")
    except ImportError:
        print("cairosvg 없음: SVG 만 생성")
    print(p)


if __name__ == "__main__":
    main()
