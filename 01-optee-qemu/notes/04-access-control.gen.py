#!/usr/bin/env python3
"""01 호출자별 접근 제어 -- 신원이 어디서 만들어지고 어디서 비교되는가, A1/A4/A6/A7 결과. SVG + PNG.
   python3 04-access-control.gen.py <outdir>   (PNG 는 cairosvg 필요)
"""
import os
import sys
from xml.sax.saxutils import escape

F = "NanumGothic, sans-serif"
M = "NanumGothicCoding, monospace"
C = {
    "nw_bg": "#e8f0fb", "nw_bd": "#3b6fb6",
    "k_bg": "#f2f2f2", "k_bd": "#666666",
    "sw_bg": "#fff6e5", "sw_bd": "#c98a00",
    "bad_bg": "#fdecea", "bad_bd": "#c0392b",
    "ok_bg": "#e7f5ec", "ok_bd": "#2e8b57",
    "txt": "#1d1d1f", "sub": "#555555", "arrow": "#777777",
}
W, H = 1640, 1000


def text(x, y, s, size=17, color=None, weight="normal", font=F, anchor="start"):
    return (f'<text x="{x}" y="{y}" font-family="{font}" font-size="{size}" '
            f'fill="{color or C["txt"]}" font-weight="{weight}" '
            f'text-anchor="{anchor}">{escape(s)}</text>')


def rect(x, y, w, h, bg, bd, dash=False, rx=8, sw=2):
    d = ' stroke-dasharray="6,4"' if dash else ""
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" '
            f'fill="{bg}" stroke="{bd}" stroke-width="{sw}"{d}/>')


def arrow(x1, y1, x2, y2, color=None):
    c = color or C["arrow"]
    return (f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{c}" '
            f'stroke-width="2" marker-end="url(#ah)"/>')


# (호출자 라벨, 커널이 넘기는 신원, 테스트, 결과, ok?)
CALLERS = [
    ("uid 1001 앱 (주인)", "USER + uuid(1001)", "A0 생성 / A7 삭제", "SUCCESS", True),
    ("uid 1003 앱 (남)", "USER + uuid(1003)", "A1 MAC / A2 INFO / A3 삭제", "ACCESS_DENIED", False),
    ("root (uid 0) 그대로", "USER + uuid(0)", "A4 MAC", "ACCESS_DENIED", False),
    ("root -> setuid(1001)", "USER + uuid(1001)", "A6 MAC  [한계]", "SUCCESS", True),
    ("LOGIN_PUBLIC", "PUBLIC (신원 없음)", "A5 생성", "ACCESS_DENIED", False),
]


def build():
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
         '<defs><marker id="ah" markerWidth="10" markerHeight="10" refX="9" refY="5" '
         'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#777"/></marker></defs>',
         f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
         text(40, 50, "01 호출자별 접근 제어 -- 키 주인만 INFO / MAC / DELETE", 28, weight="bold"),
         text(40, 84, "주인 = 키를 만든 호출자의 TEE_Identity (login + uid 로 계산한 uuid, 20B).  "
              "결과: PASS 26 / FAIL 0  (commit e7630b5)", 17, C["sub"])]

    # 열 머리
    cols = [(40, "Normal world 앱 (EL0)"), (420, "Linux 커널 tee 드라이버"),
            (800, "TA: check_owner()"), (1300, "결과")]
    for x, t in cols:
        o.append(text(x, 135, t, 19, weight="bold"))

    # TA 와 저장소 박스 (오른쪽 가운데)
    o.append(rect(790, 150, 470, 610, C["sw_bg"], C["sw_bd"], rx=12))
    o.append(text(810, 182, "Secure world", 16, C["sub"]))

    y0, dy = 210, 105
    for i, (who, ident, test, res, ok) in enumerate(CALLERS):
        y = y0 + i * dy
        o.append(rect(40, y, 330, 70, C["nw_bg"], C["nw_bd"]))
        o.append(text(56, y + 30, who, 18, weight="bold"))
        o.append(text(56, y + 56, test, 15, C["sub"]))
        o.append(arrow(370, y + 35, 418, y + 35))
        o.append(rect(420, y, 330, 70, C["k_bg"], C["k_bd"]))
        o.append(text(436, y + 30, "프로세스 uid 로 신원 계산", 15, C["sub"]))
        o.append(text(436, y + 56, ident, 16, font=M))
        o.append(arrow(750, y + 35, 808, y + 35))
        o.append(rect(810, y + 10, 200, 50, "#ffffff", C["sw_bd"]))
        o.append(text(910, y + 42, "PUBLIC -> 바로 거부" if i == 4 else "me == owner ?",
                      16 if i != 4 else 15, font=M if i != 4 else F, anchor="middle"))
        bg, bd = (C["ok_bg"], C["ok_bd"]) if ok else (C["bad_bg"], C["bad_bd"])
        o.append(arrow(1010, y + 35, 1298, y + 35))
        o.append(rect(1300, y, 300, 70, bg, bd))
        o.append(text(1450, y + 43, res, 19, bd, "bold", M, "middle"))

    # persistent object 그림 (아래)
    py = 760
    o.append(rect(790, py + 20, 470, 190, "#ffffff", C["sw_bd"], rx=10))
    o.append(text(810, py + 52, "Persistent object id=2  (/var/lib/tee, 암호화)", 17, weight="bold"))
    o.append(rect(810, py + 70, 210, 120, C["k_bg"], C["k_bd"]))
    o.append(text(825, py + 98, "속성 (attributes)", 16, weight="bold"))
    o.append(text(825, py + 126, "HMAC 키 256bit", 15, font=M))
    o.append(text(825, py + 152, "usage = MAC", 15, font=M))
    o.append(text(825, py + 178, "(원래부터 저장)", 14, C["sub"]))
    o.append(rect(1030, py + 70, 210, 120, C["ok_bg"], C["ok_bd"]))
    o.append(text(1045, py + 98, "데이터 영역 (data)", 16, weight="bold"))
    o.append(text(1045, py + 126, "owner =", 15, font=M))
    o.append(text(1045, py + 152, "USER+uuid(1001)", 15, font=M))
    o.append(text(1045, py + 178, "(이번에 추가, 20B)", 14, C["sub"]))
    # 데이터 영역 -> check_owner 화살표
    o.append(arrow(1135, py + 70, 1135, 735))
    o.append(text(1125, 745, "TEE_ReadObjectData", 14, C["sub"], font=M, anchor="end"))

    # 왼쪽 아래: 설명
    lx, ly = 40, 760
    o.append(rect(lx, ly + 20, 710, 190, "#fafafa", "#bbbbbb", rx=10))
    lines = [
        ("어떻게", True),
        ("key_create: 호출자 신원 me 를 initialData 로 키와 같이 저장", False),
        ("key_info / mac_by_id / key_delete: Open 직후 check_owner()", False),
        ("  (delete 는 READ|WRITE_META 로 open -- READ 없으면 TA panic)", False),
        ("한계 (A6)", True),
        ("신원은 normal world 커널이 uid 로 만든다 -> 커널을 쥔 root 는", False),
        ("setuid 로 주인 행세 가능. TEE 혼자서는 못 막음.", False),
    ]
    yy = ly + 50
    for s, b in lines:
        o.append(text(lx + 20, yy, s, 16 if not b else 17,
                      C["bad_bd"] if s.startswith("한계") else None, "bold" if b else "normal"))
        yy += 24

    o.append("</svg>")
    return "\n".join(o)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(out, "04-access-control")
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
