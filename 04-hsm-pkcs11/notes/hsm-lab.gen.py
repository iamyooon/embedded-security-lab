#!/usr/bin/env python3
"""04 HSM 실습 요약 -- [H1][H2] 키 꺼내기, [F1][F2] FIT 서명. SVG + PNG.
   python3 hsm-lab.gen.py <outdir>   (PNG 는 cairosvg 필요)
"""
import os
import sys
from xml.sax.saxutils import escape

F = "NanumGothic, sans-serif"
M = "NanumGothicCoding, monospace"
C = {
    "app_bg": "#e8f0fb", "app_bd": "#3b6fb6",
    "hsm_bg": "#fff6e5", "hsm_bd": "#c98a00",
    "bad_bg": "#fdecea", "bad_bd": "#c0392b",
    "ok_bg": "#e7f5ec", "ok_bd": "#2e8b57",
    "rom_bg": "#f2f2f2", "rom_bd": "#666666",
    "txt": "#1d1d1f", "sub": "#555555", "arrow": "#777777",
}
W, H = 1640, 1040


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
    o.append(rect(x, y, w, h, C[kind + "_bg"], C[kind + "_bd"]))
    o.append(text(x + 14, y + 26, title, tsize, C[kind + "_bd"], "bold"))
    for i, s in enumerate(lines):
        col = C["bad_bd"] if s.startswith("!") else None
        o.append(text(x + 14, y + 52 + i * 22, s.lstrip("!"), 15, col))


def build():
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
         '<defs><marker id="ah" markerWidth="10" markerHeight="10" refX="9" refY="5" '
         'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#777"/></marker></defs>',
         f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
         text(40, 50, "04 HSM (SoftHSM + PKCS#11) -- 키는 못 꺼내게, 서명만 시킨다", 28, weight="bold"),
         text(40, 84, "공격자 = PIN 을 가진 빌드 서버 root.  HSM 이 막는 것 = 키 유출.  못 막는 것 = PIN 으로 서명 시키기(오용).",
              17, C["sub"])]

    # 상단: 빌드 서버 프로세스 구조
    o.append(rect(40, 115, 1000, 330, "#fafafa", "#bbbbbb", rx=12))
    o.append(text(60, 145, "빌드 서버 -- mkimage / pkcs11-tool 프로세스 (root 가 메모리를 볼 수 있음)", 18, weight="bold"))
    box(o, 70, 170, 290, 120, "app", "앱 (mkimage)", [
        "키 = 핸들(번호)로만 가리킴", "C_Login(PIN) -> C_Sign(핸들, 해시)"])
    o.append(arrow(360, 230, 430, 230))
    box(o, 430, 170, 580, 250, "hsm", "SoftHSM = 같은 프로세스에 로드된 .so", [
        "토큰 파일: 키를 PIN 유래 키로 암호화해 디스크 저장",
        "속성 sensitive / never extractable -> API 로는 값 안 줌",
        "!서명 순간: 키를 복호해 이 프로세스 메모리에서 연산",
        "!(OpenSSL RSA_sign 안에 p, q 가 평문으로 있음)",
        "서명 후에는 지움 -> 끝난 뒤 덤프로는 0건",
        "",
        "진짜 HSM: 연산이 별도 칩 안 -> 호스트 메모리에 키 없음"])

    # H1 / H2
    box(o, 1080, 115, 520, 150, "ok", "[H1] API 로 꺼내기 -- 막힘", [
        "C_GetAttributeValue(CKA_PRIVATE_EXPONENT)",
        "rv=0x11 CKR_ATTRIBUTE_SENSITIVE, 길이 -1",
        "막은 것: 권한이 아니라 키 속성 (SoftHSM 이 검사)",
        "= 01 의 EXPORT_KEY 를 OP-TEE 코어가 막은 구조"])
    box(o, 1080, 285, 520, 160, "bad", "[H2] root 메모리 덤프 -- 뚫림", [
        "RSA_sign 진입 시점 gcore -> n 을 나누는 128B 탐색",
        "p, q 각 2벌 (SoftHSM BE + OpenSSL BIGNUM LE)",
        "p*q == n, 복원 키 서명 == HSM 서명",
        "!SoftHSM 이라서. 진짜 HSM 은 이 경로 없음(미확인)"])
    o.append(arrow(1010, 330, 1080, 360, C["bad_bd"], dash=True))

    # 하단: FIT 체인
    o.append(rect(40, 480, 1560, 420, "#fafafa", "#bbbbbb", rx=12))
    o.append(text(60, 510, "02 FIT 와 연결 -- 서명하는 쪽만 바뀌고, 검증하는 쪽(U-Boot)은 그대로", 18, weight="bold"))
    box(o, 70, 535, 330, 150, "rom", "02 (이전)", [
        "keys/fitdev.key 평문 파일",
        "mkimage -k keys",
        "!파일 복사 = 키 유출"])
    box(o, 70, 705, 330, 170, "hsm", "04 (지금)", [
        "토큰 fit / 키 fithsm",
        "mkimage -N pkcs11",
        "  -k pkcs11:token=fit;pin-value=..",
        "개인키 파일 없음",
        "!PIN 이 명령줄 -> ps 로 보임"])
    o.append(arrow(400, 790, 470, 700))
    box(o, 470, 600, 340, 200, "app", "산출물", [
        "kernel-hsm.itb",
        "  conf-1 서명 sha256,rsa2048:fithsm",
        "ctrl-hsm.dtb",
        "  /signature/key-fithsm (required)",
        "u-boot-nodtb.bin + ctrl-hsm.dtb",
        "  = BL33 -> TF-A 가 해시로 덮음"])
    o.append(arrow(810, 650, 880, 600))
    o.append(arrow(810, 750, 880, 770))
    box(o, 880, 535, 690, 150, "ok", "[F1] 새 U-Boot(key-fithsm) + HSM 서명 itb -- 예측: 동작, 맞음", [
        "sha256,rsa2048:fithsm+ OK  ->  이미지 해시 sha256+ OK",
        "-> 커널 -> login, uname 출력",
        "오프라인 fit_check_sign -k ctrl-hsm.dtb : Signature check OK"], 16)
    box(o, 880, 705, 690, 170, "bad", "[F2] 02 U-Boot(key-fitdev) + HSM 서명 itb -- 예측: 안 됨, 맞음", [
        "sha256,rsa2048:fithsm-  error!",
        "Failed to verify required signature 'key-fitdev'",
        "-> resetting ... 반복 (02 하드닝: 실패 시 셸 대신 리셋)",
        "U-Boot 는 서명이 파일로 됐는지 HSM 으로 됐는지 모름 -> 공개키만 맞으면 됨"], 16)

    o.append(text(40, 945, "결론: HSM 은 검증 체인과 별개로, 체인이 기대는 전제(개인키 비밀성)를 지킨다. "
                  "키 유출은 HSM 이, 키 오용은 PIN 관리 / 승인 절차 / 로그가 막는다.", 17, weight="bold"))
    o.append(text(40, 980, "근거: 04-hsm-pkcs11/src/{read_priv.c, h2_dump.sh, h2_recover.py}, fit/build-fit-hsm.sh, "
                  "u-boot lib/rsa/rsa-sign.c (pkcs11 URI), README 실험 표", 15, C["sub"]))
    o.append("</svg>")
    return "\n".join(o)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(out, "hsm-lab")
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
