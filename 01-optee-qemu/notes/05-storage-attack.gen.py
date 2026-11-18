#!/usr/bin/env python3
"""01 저장소 공격 데모 [S1][S2][S3] -- /var/lib/tee 구조와 공격 지점 (결과 포함). SVG + PNG.
   python3 05-storage-attack.gen.py <outdir>   (PNG 는 cairosvg 필요)
"""
import os
import sys
from xml.sax.saxutils import escape

F = "NanumGothic, sans-serif"
M = "NanumGothicCoding, monospace"
C = {
    "nw_bg": "#e8f0fb", "nw_bd": "#3b6fb6",
    "sw_bg": "#fff6e5", "sw_bd": "#c98a00",
    "bad_bg": "#fdecea", "bad_bd": "#c0392b",
    "k_bg": "#f2f2f2", "k_bd": "#666666",
    "txt": "#1d1d1f", "sub": "#555555", "arrow": "#777777",
}
W, H = 1640, 960


def text(x, y, s, size=17, color=None, weight="normal", font=F, anchor="start"):
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


def build():
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
         '<defs><marker id="ah" markerWidth="10" markerHeight="10" refX="9" refY="5" '
         'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#777"/></marker></defs>',
         f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
         text(40, 50, "01 저장소 공격 -- root 가 /var/lib/tee 파일을 직접 건드린다", 28, weight="bold"),
         text(40, 84, "설정: CFG_REE_FS=y, CFG_RPMB_FS=n, CFG_REE_FS_INTEGRITY_RPMB=n  "
              "(dirf.db 를 고정해 줄 RPMB 앵커 없음)", 17, C["sub"])]

    # Secure world (위)
    o.append(rect(40, 120, 1560, 230, C["sw_bg"], C["sw_bd"], rx=12))
    o.append(text(60, 152, "Secure world (OP-TEE OS)", 18, weight="bold"))
    o.append(rect(70, 175, 300, 150, "#ffffff", C["sw_bd"]))
    o.append(text(90, 207, "HUK (기기 고유키)", 17, weight="bold"))
    o.append(text(90, 235, "QEMU: 전부 0 (otp_stubs.c)", 15, C["bad_bd"]))
    o.append(text(90, 263, "-> TA 별 저장 키 TSK 유도", 15, C["sub"]))
    o.append(text(90, 291, "-> 파일마다 FEK 로 암호화", 15, C["sub"]))
    o.append(arrow(370, 250, 470, 250))
    o.append(rect(470, 175, 520, 150, "#ffffff", C["sw_bd"]))
    o.append(text(490, 207, "secure storage 계층", 17, weight="bold"))
    o.append(text(490, 235, "쓰기: 암호화 + 해시 -> RPC 로 파일 저장 요청", 15))
    o.append(text(490, 263, "읽기: 파일 해시 == dirf.db 에 적힌 해시 ?", 15))
    o.append(text(490, 291, "      dirf.db 자체는 무엇과 비교? -> 앵커 없음", 15, C["bad_bd"]))
    o.append(arrow(990, 250, 1090, 250))
    o.append(rect(1090, 175, 480, 150, "#ffffff", C["sw_bd"]))
    o.append(text(1110, 207, "secure_mac TA", 17, weight="bold"))
    o.append(text(1110, 235, "MAC_BY_ID / KEY_INFO / KEY_DELETE", 15, font=M))
    o.append(text(1110, 263, "Open 실패 코드가 그대로 CA 로", 15, C["sub"]))

    # 경계
    o.append(f'<line x1="40" y1="385" x2="1600" y2="385" stroke="#999" stroke-width="2" stroke-dasharray="10,6"/>')
    o.append(text(1600, 377, "SMC / RPC (tee-supplicant 가 파일 I/O 대행)", 15, C["sub"], anchor="end"))

    # Normal world /var/lib/tee
    o.append(rect(40, 410, 1560, 210, C["nw_bg"], C["nw_bd"], rx=12))
    o.append(text(60, 442, "Normal world: /var/lib/tee (root 읽기/쓰기 가능)", 18, weight="bold"))
    o.append(rect(70, 465, 420, 130, "#ffffff", C["nw_bd"]))
    o.append(text(90, 497, "dirf.db", 18, weight="bold", font=M))
    o.append(text(90, 525, "목록: (TA uuid, 객체 id) -> 파일 번호", 15))
    o.append(text(90, 553, "+ 각 파일의 해시", 15))
    o.append(text(90, 581, "(암호화 + 무결성 보호)", 14, C["sub"]))
    o.append(arrow(490, 530, 590, 530))
    o.append(rect(590, 465, 420, 130, "#ffffff", C["nw_bd"]))
    o.append(text(610, 497, "0, 1, 2 ...  (객체 파일)", 18, weight="bold", font=M))
    o.append(text(610, 525, "속성: 키 값 / usage", 15))
    o.append(text(610, 553, "데이터: owner 신원 20B", 15))
    o.append(text(610, 581, "(FEK 로 암호화, 해시 트리)", 14, C["sub"]))
    o.append(arrow(780, 465, 780, 330))
    o.append(arrow(480, 465, 480, 330))

    # 실험 3개
    ex = [
        ("[S1] 읽기", "키 파일 hexdump / strings", "결과: 무작위 바이트, 키/owner 안 보임", "실패 기준 1 통과  (예측 맞음)", True),
        ("[S2] 변조", "데이터 블록 1바이트 (두 벌 모두)", "결과: MAC 0xF0100001 CORRUPT_OBJECT", "-> OP-TEE 가 객체 삭제 (가용성 공격)", True),
        ("[S3] 롤백", "백업 -> 삭제 -> 백업 복원", "결과: MAC SUCCESS, tag 동일", "지운 키 부활 = 못 막음 (예측 맞음)", False),
    ]
    x0 = 40
    for i, (t, a, b, c, held) in enumerate(ex):
        x = x0 + i * 530
        bg, bd = ("#e7f5ec", "#2e8b57") if held else (C["bad_bg"], C["bad_bd"])
        o.append(rect(x, 660, 500, 170, bg, bd, rx=10))
        o.append(text(x + 20, 694, t + ("  -- 막힘" if held else "  -- 뚫림"), 20, bd, "bold"))
        o.append(text(x + 20, 726, a, 16))
        o.append(text(x + 20, 762, b, 16, weight="bold"))
        o.append(text(x + 20, 800, c, 15, C["sub"]))
        o.append(arrow(x + 250, 660, x + 250, 625, C["bad_bd"]))

    o.append(text(40, 880, "공격자 = normal world root. 키 파일 = 생성 후 삭제해서 사라지는 파일 (/var/lib/tee/23, 16KB). "
                  "근거: tee_svc_storage.c remove_corrupt_obj / tee_ree_fs.c:552", 16, C["sub"]))
    o.append(text(40, 908, "S2 는 무결성은 지키지만 키를 지운다. S3 를 막으려면 dirf.db 앵커(RPMB) 필요.", 16, C["sub"]))
    o.append("</svg>")
    return "\n".join(o)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(out, "05-storage-attack")
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
