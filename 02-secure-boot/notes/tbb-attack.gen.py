#!/usr/bin/env python3
"""TF-A TBB 공격 데모 [A][B][C] -- BL1 검증 흐름과 실패 지점. SVG + PNG.
   python3 tbb-attack.gen.py <outdir>   (PNG 는 cairosvg 필요)
"""
import os
import sys
from xml.sax.saxutils import escape

F = "NanumGothic, sans-serif"
M = "NanumGothicCoding, monospace"
C = {
    "flash_bg": "#e8f0fb", "flash_bd": "#3b6fb6",
    "rom_bg": "#f2f2f2", "rom_bd": "#666666",
    "bad_bg": "#fdecea", "bad_bd": "#c0392b",
    "ok_bg": "#e7f5ec", "ok_bd": "#2e8b57",
    "skip_bg": "#fafafa", "skip_bd": "#bbbbbb",
    "txt": "#1d1d1f", "sub": "#555555", "arrow": "#777777",
}
W, H = 1640, 1010

EXP = {
    "A": {
        "title": "[A] bl2.bin 1바이트 변조 (offset 0x100)",
        "goal": "공격자: 내 BL2 로 부팅하고 싶다 -> 이미지만 고친다",
        "bad": {"bl2"},
        "status": ["ok", "ok", "bad", "skip"],
        "why": ["인증서는 진짜라 (1)(2) 통과.",
                "인증서의 bl2 해시와 변조된 bl2.bin 의 해시가 달라 (3) 실패.",
                "-> 실패 기준 1 통과 (부팅 거부)"],
        "log": [
            ("INFO:    Loading image id=6 at address 0xe05b000", 0),
            ("INFO:    Image id=6 loaded: 0xe05b000 - 0xe05b4be", 0),
            ("INFO:    Loading image id=1 at address 0xe05b000", 0),
            ("INFO:    Image id=1 loaded: 0xe05b000 - 0xe06d5d4", 0),
            ("ERROR:   Failed to load BL2 firmware.", 1),
        ],
        "logsrc": "tamper-bl2-verbose.log (LOG_LEVEL=40)",
    },
    "B": {
        "title": "[B] tb_fw.crt 서명 1바이트 변조 (offset 1100)",
        "goal": "공격자: [A] 가 막혔으니 인증서를 건드린다",
        "bad": {"sig"},
        "status": ["ok", "bad", "skip", "skip"],
        "why": ["공개키는 진짜라 (1) 통과.",
                "서명이 hash(본문)과 안 맞아 (2) 실패 -> 본문을 못 믿으니 bl2 는 읽지도 않음.",
                "-> 실패 기준 3 통과"],
        "log": [
            ("INFO:    Loading image id=6 at address 0xe05b000", 0),
            ("INFO:    Image id=6 loaded: 0xe05b000 - 0xe05b4be", 0),
            ("ERROR:   Failed to load BL2 firmware.", 1),
            ("         (id=1 로드 줄 없음)", 2),
        ],
        "logsrc": "tamper-cert.log (LOG_LEVEL=40)",
    },
    "C": {
        "title": "[C] 공개키 교체 -- 공격자 키로 인증서를 통째로 새로 만듦",
        "goal": "공격자: 내 키쌍 + 변조 bl2 해시 + 내 비밀키 서명 (cert_create)",
        "bad": {"pk", "hash", "sig", "bl2"},
        "status": ["bad", "skip", "skip", "skip"],
        "why": ["hash(공격자 공개키) f8d17b.. != OTP 의 ROTPK 해시 -> (1) 실패.",
                "서명 검증(294줄)은 그 뒤라 가지도 않음. bl2 도 안 읽음.",
                "-> 실패 기준 2 통과. 막아 준 것 = 바꿀 수 없는 OTP 해시"],
        "log": [
            ("INFO:    Loading image id=6 at address 0xe05b000", 0),
            ("INFO:    Image id=6 loaded: 0xe05b000 - 0xe05b4be", 0),
            ("VERBOSE: [TBB] auth_signature():271 failed with error code 2.", 1),
            ("VERBOSE: [TBB] auth_mod_verify_img():526 failed with error code 2.", 1),
            ("ERROR:   Failed to load BL2 firmware.", 1),
        ],
        "logsrc": "tamper-rotpk.log (LOG_LEVEL=50)",
    },
}

STEPS = [
    ("(1) 공개키가 진짜 루트 키인가", "hash(본문.공개키) == OTP 의 ROTPK 해시 ?",
     "auth_mod.c:267  crypto_mod_verify_hash"),
    ("(2) 본문을 루트 키 주인이 썼나", "본문.공개키로 서명 검증 : hash(본문) 과 일치 ?",
     "auth_mod.c:294  crypto_mod_verify_signature"),
    ("(3) bl2.bin 이 그 본문과 맞나", "hash(bl2.bin) == 본문.bl2해시 ?",
     "id=1 auth_hash   (bl2.bin 을 읽은 뒤)"),
    ("BL2 로 점프", "셋 다 통과해야 실행", ""),
]
ST_LABEL = {"ok": "통과", "bad": "실패 -> 정지", "skip": "실행 안 됨"}


def text(x, y, s, size=17, color=None, weight="normal", font=F, anchor="start"):
    return (f'<text x="{x}" y="{y}" font-family="{font}" font-size="{size}" '
            f'fill="{color or C["txt"]}" font-weight="{weight}" '
            f'text-anchor="{anchor}" xml:space="preserve">{escape(s)}</text>')


def rect(x, y, w, h, bg, bd, dash=False, rx=8, sw=2):
    d = ' stroke-dasharray="7,5"' if dash else ""
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" '
            f'fill="{bg}" stroke="{bd}" stroke-width="{sw}"{d}/>')


def arrow(x1, y1, x2, y2, color=None):
    c = color or C["arrow"]
    return (f'<path d="M{x1},{y1} C{(x1 + x2) / 2},{y1} {(x1 + x2) / 2},{y2} {x2},{y2}" '
            f'fill="none" stroke="{c}" stroke-width="2" marker-end="url(#ah)"/>')


def field(o, x, y, w, h, key, label, val, bad):
    bg, bd = (C["bad_bg"], C["bad_bd"]) if key in bad else ("#ffffff", C["flash_bd"])
    o.append(rect(x, y, w, h, bg, bd, rx=5))
    o.append(text(x + 12, y + 24, label, 16, weight="bold"))
    o.append(text(x + 12, y + 46, val, 14, C["bad_bd"] if key in bad else C["sub"]))


def build(k):
    e = EXP[k]
    bad = e["bad"]
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
         f'viewBox="0 0 {W} {H}">',
         '<defs><marker id="ah" markerWidth="10" markerHeight="10" refX="9" refY="5" '
         'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#777"/></marker></defs>',
         f'<rect width="{W}" height="{H}" fill="#ffffff"/>']
    o.append(text(40, 46, e["title"], 26, weight="bold"))
    o.append(text(40, 78, e["goal"], 18, C["sub"]))

    # --- 왼쪽: 플래시 (공격자가 바꿀 수 있음)
    LX, LW = 40, 520
    o.append(rect(LX, 100, LW, 520, C["flash_bg"], C["flash_bd"]))
    o.append(text(LX + 16, 128, "플래시 / out/bin  (공격자가 바꿀 수 있음)", 17,
                  C["flash_bd"], "bold"))
    o.append(rect(LX + 16, 142, LW - 32, 356, "#f7faff", C["flash_bd"], rx=6))
    o.append(text(LX + 30, 168, "tb_fw.crt  (id=6, BL2 용 인증서)", 16, weight="bold"))
    o.append(text(LX + 30, 192, "본문 (TBSCertificate)", 15, C["sub"]))
    fx, fw = LX + 40, LW - 80
    pk_val = "공격자 공개키 (해시 f8d17b..)" if "pk" in bad else "루트 공개키 (해시 e3cf97..)"
    h_val = "변조된 bl2 의 해시" if "hash" in bad else "정상 bl2 의 해시"
    field(o, fx, 202, fw, 58, "pk", "루트 공개키", pk_val, bad)
    field(o, fx, 268, fw, 58, "hash", "bl2 해시", h_val, bad)
    field(o, fx, 334, fw, 58, "nv", "NV 카운터", "0", bad)
    o.append(text(LX + 30, 420, "본문에 대한 서명", 15, C["sub"]))
    sig_val = {"B": "루트 키 서명, 1바이트 뒤집음",
               "C": "공격자 비밀키로 서명"}.get(k, "루트 비밀키로 서명(hash(본문))")
    field(o, fx, 430, fw, 58, "sig", "signatureValue (RSA-PSS 2048)", sig_val, bad)
    bl2_val = "1바이트 뒤집음 (0x100)" if "bl2" in bad else "정상"
    field(o, LX + 16, 512, LW - 32, 58, "bl2", "bl2.bin  (id=1)", bl2_val, bad)
    o.append(text(LX + 16, 600, "빨간 칸 = 이번 실험에서 공격자가 바꾼 것", 14, C["bad_bd"]))

    # --- 가운데: ROM / OTP (못 바꿈)
    MX, MW = 640, 300
    o.append(rect(MX, 96, MW, 96, C["rom_bg"], C["rom_bd"]))
    o.append(text(MX + 16, 122, "OTP / eFuse  (못 바꿈)", 17, C["rom_bd"], "bold"))
    o.append(text(MX + 16, 150, "ROTPK 해시 = e3cf97..", 16))
    o.append(text(MX + 16, 176, "(QEMU 는 BL1 빌드에 박힘)", 14, C["sub"]))
    o.append(rect(MX, 540, MW, 90, C["rom_bg"], C["rom_bd"]))
    o.append(text(MX + 16, 566, "BL1 (Mask ROM, 못 바꿈)", 17, C["rom_bd"], "bold"))
    o.append(text(MX + 16, 592, "검증 없이 신뢰하는 출발점.", 15))
    o.append(text(MX + 16, 616, "오른쪽 (1)->(3) 을 수행", 15))

    # --- 오른쪽: BL1 검증 단계
    RX, RW = 1020, 580
    o.append(text(RX, 128, "BL1 의 검증 순서 (load_auth_image_recursive)", 17, weight="bold"))
    ys = [142, 262, 382, 502]
    for i, (t1, t2, t3) in enumerate(STEPS):
        st = e["status"][i]
        bg, bd = {"ok": (C["ok_bg"], C["ok_bd"]), "bad": (C["bad_bg"], C["bad_bd"]),
                  "skip": (C["skip_bg"], C["skip_bd"])}[st]
        hh = 100 if i < 3 else 70
        tc = C["txt"] if st != "skip" else "#999999"
        o.append(rect(RX, ys[i], RW, hh, bg, bd, dash=(st == "skip"), sw=3 if st == "bad" else 2))
        o.append(text(RX + 16, ys[i] + 28, t1, 17, tc, "bold"))
        o.append(text(RX + RW - 16, ys[i] + 28, ST_LABEL[st], 16, bd, "bold", anchor="end"))
        o.append(text(RX + 16, ys[i] + 54, t2, 15, tc))
        if t3:
            o.append(text(RX + 16, ys[i] + 80, t3, 14, "#999999" if st == "skip" else C["sub"], font=M))
        if i < 3:
            o.append(f'<line x1="{RX + RW / 2}" y1="{ys[i] + hh}" x2="{RX + RW / 2}" '
                     f'y2="{ys[i + 1]}" stroke="#999" stroke-width="2" marker-end="url(#ah)"/>')

    # --- 데이터 -> 단계 화살표
    o.append(arrow(fx + fw, 231, RX, 200))              # 공개키 -> (1)
    o.append(arrow(MX + MW, 150, RX, 165))              # OTP -> (1)
    o.append(arrow(fx + fw, 459, RX, 300))              # 서명 -> (2)
    o.append(arrow(fx + fw, 231, RX, 316))              # 공개키 -> (2)
    o.append(arrow(fx + fw, 297, RX, 420))              # bl2해시 -> (3)
    o.append(arrow(LX + LW - 16, 541, RX, 440))         # bl2.bin -> (3)

    # --- 아래: 왜 + 실제 로그
    o.append(rect(40, 650, W - 80, 110, "#fffdf3", "#c9a227"))
    o.append(text(56, 678, "결과", 17, "#8a6d00", "bold"))
    for j, s in enumerate(e["why"]):
        o.append(text(120, 678 + j * 26, s, 16))
    o.append(rect(40, 780, W - 80, 200, "#1e1e1e", "#1e1e1e"))
    o.append(text(56, 806, "실제 로그 (앞의 BL1 공통 6줄 생략)  -- " + e["logsrc"], 14, "#aaaaaa"))
    for j, (s, lv) in enumerate(e["log"]):
        col = {0: "#d4d4d4", 1: "#ff6b5e", 2: "#888888"}[lv]
        o.append(text(56, 840 + j * 26, s, 16, col, font=M))
    o.append("</svg>")
    return "\n".join(o)


def main():
    out = sys.argv[1]
    for k in EXP:
        svg = build(k)
        p = os.path.join(out, f"tbb-attack-{k}")
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
