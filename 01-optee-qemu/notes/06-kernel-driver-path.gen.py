#!/usr/bin/env python3
"""01 CA 호출 하나가 커널 TEE 드라이버 -> EL3 -> OP-TEE -> TA 까지 가는 경로. SVG + PNG.
   python3 06-kernel-driver-path.gen.py <outdir>   (PNG 는 cairosvg 필요)
   근거: optee_client/libteec/src/tee_client_api.c, linux/drivers/tee/{tee_core.c,tee_shm.c,optee/call.c,optee/smc_abi.c},
         trusted-firmware-a/services/spd/opteed/opteed_main.c, optee_os/core/arch/arm/kernel/thread_optee_smc.c,
         optee_os/core/tee/entry_std.c
"""
import os
import sys
from xml.sax.saxutils import escape

F = "NanumGothic, sans-serif"
M = "NanumGothicCoding, monospace"
C = {
    "u_bg": "#e8f0fb", "u_bd": "#3b6fb6",
    "k_bg": "#eef3fb", "k_bd": "#24508f",
    "m_bg": "#f2f2f2", "m_bd": "#666666",
    "s_bg": "#fff6e5", "s_bd": "#c98a00",
    "bad_bg": "#fdecea", "bad_bd": "#c0392b",
    "ok_bg": "#e7f5ec", "ok_bd": "#2e8b57",
    "txt": "#1d1d1f", "sub": "#555555", "arrow": "#777777",
}
W, H = 1640, 1200


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


def box(o, x, y, w, h, kind, title, lines, tsize=16, mono=True):
    o.append(rect(x, y, w, h, C[kind + "_bg"], C[kind + "_bd"]))
    o.append(text(x + 12, y + 24, title, tsize, C[kind + "_bd"], "bold"))
    for i, s in enumerate(lines):
        col = C["bad_bd"] if s.startswith("!") else (C["sub"] if s.startswith("~") else None)
        o.append(text(x + 12, y + 48 + i * 21, s.lstrip("!~"), 14, col, font=M if mono else F))


def lane(o, y, h, label, sub, bg):
    o.append(rect(30, y, 1580, h, bg, "#cccccc", rx=10, sw=1))
    o.append(text(48, y + 28, label, 18, weight="bold"))
    o.append(text(48, y + 50, sub, 14, C["sub"]))


def build():
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
         '<defs><marker id="ah" markerWidth="10" markerHeight="10" refX="9" refY="5" '
         'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#777"/></marker></defs>',
         f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
         text(40, 46, "CA 호출 하나가 secure world 까지 -- Linux TEE 드라이버 경로 (01 secure_mac)", 27, weight="bold"),
         text(40, 78, "01 writeup 의 EL0 -> EL1 -> EL3 -> S-EL1 -> S-EL0 를 함수 단위로. 소스 추적만 함 (런타임 관측 안 함).",
              16, C["sub"])]

    lane(o, 100, 180, "EL0  normal 사용자", "CA + libteec", "#f7faff")
    lane(o, 295, 395, "EL1  normal 커널", "/dev/tee0 -> TEE 코어 -> OP-TEE 드라이버", "#f3f6fb")
    lane(o, 705, 130, "EL3  TF-A BL31", "secure monitor", "#f6f6f6")
    lane(o, 850, 245, "S-EL1 / S-EL0", "OP-TEE OS -> TA", "#fffaf0")

    # EL0
    box(o, 220, 115, 420, 150, "u", "secure_mac CA (host/main.c)", [
        "TEEC_OpenSession(.., TEEC_LOGIN_USER)",
        "TEEC_InvokeCommand(MAC_BY_ID,",
        "   MEMREF_TEMP_INPUT msg,",
        "   MEMREF_TEMP_OUTPUT tag)"])
    box(o, 700, 115, 560, 150, "u", "libteec (tee_client_api.c)", [
        "OpenSession -> ioctl(TEE_IOC_OPEN_SESSION)   :641",
        "tmpref -> teec_pre_process_tmpref()          :192",
        "   -> ioctl(TEE_IOC_SHM_REGISTER) (CA 버퍼 등록)",
        "Invoke -> ioctl(TEE_IOC_INVOKE)               :728"])
    o.append(arrow(640, 190, 700, 190))

    # EL1
    box(o, 220, 360, 400, 130, "k", "tee_core.c  tee_ioctl()", [
        "case TEE_IOC_OPEN_SESSION   :980",
        "case TEE_IOC_SHM_REGISTER   :976",
        "case TEE_IOC_INVOKE -> tee_ioctl_invoke  :982"])
    o.append(arrow(900, 265, 520, 360))
    box(o, 220, 510, 400, 165, "bad", "(a) 신원 = 커널이 정함", [
        "optee_open_session (call.c:362)",
        " -> tee_session_calc_client_uuid",
        "    (tee_core.c:167)",
        '!"uid=%x", current_euid() -> uuid_v5',
        "~= TA 의 TEE_Identity. root setuid -> A6"])
    o.append(arrow(420, 490, 420, 510))
    box(o, 660, 360, 420, 150, "k", "(b) 버퍼 등록 tee_shm.c", [
        "tee_shm_register",
        " -> iov_iter_extract_pages()   :451",
        "~   페이지 pin: 이동/해제 금지",
        " -> optee_shm_register (smc_abi.c:453)",
        "~   물리 페이지 목록 -> OP-TEE"])
    o.append(arrow(620, 425, 660, 425))
    box(o, 1120, 360, 470, 205, "k", "(c) SMC 루프  smc_abi.c", [
        "optee_invoke_func (call.c:512)",
        " -> optee_smc_do_call_with_arg   :886",
        "    a0 = OPTEE_SMC_CALL_WITH_(REGD_)ARG",
        "    while: invoke_fn = arm_smccc_smc :1474",
        "      RPC 반환 -> optee_handle_rpc  :951",
        "~     (tee-supplicant 파일 I/O 등) 다시 SMC",
        "      아니면 결과 반환"])
    o.append('<polyline points="560,360 560,342 1300,342" fill="none" stroke="#777" stroke-width="2"/>')
    o.append(arrow(1300, 342, 1300, 360))
    o.append(text(930, 336, "TEE_IOC_INVOKE", 13, C["sub"], anchor="middle"))

    # EL3
    box(o, 1120, 720, 470, 100, "m", "opteed_smc_handler (opteed_main.c:608)", [
        "normal EL1 컨텍스트 저장 cm_el1_sysregs_context_save",
        "-> secure 컨텍스트로 ERET (반환 땐 반대)"])
    o.append(arrow(1355, 565, 1355, 720))
    o.append(text(1365, 650, "SMC", 14, C["sub"]))

    # S-EL1 / S-EL0
    box(o, 1120, 870, 470, 170, "s", "OP-TEE OS", [
        "thread_handle_std_smc",
        "   (thread_optee_smc.c:52)",
        " -> entry_invoke_command (entry_std.c:429)",
        " -> TA 세션 찾아 S-EL0 로 진입",
        "~memref = (b) 에서 받은 물리 페이지를 매핑"])
    o.append(arrow(1355, 820, 1355, 870))
    box(o, 560, 870, 500, 170, "s", "secure_mac TA (S-EL0)", [
        "TA_InvokeCommandEntryPoint",
        " -> check_owner(TEE_Identity == 주인?)",
        " -> mac_do(키 id, msg) -> tag",
        "!msg 는 normal 메모리: 검사 중 CA 가 바꿀 수 있음",
        "~-> 복사한 뒤 검사하고 사용 (TOCTOU)"])
    o.append(arrow(1120, 955, 1060, 955))

    box(o, 40, 915, 480, 170, "ok", "이 경로에서 나온 01 결론", [
        "A6: 신원의 원천이 normal 커널의 euid",
        "    -> TEE 혼자 root 를 못 막음",
        "공유 메모리: pin 은 위치만 고정,",
        "    내용 변경은 못 막음 -> TA 가 복사",
        "S1-S3: 저장 I/O 는 (c) RPC 로",
        "    tee-supplicant 가 대행"], mono=False)

    o.append(text(40, 1130, "근거: libteec tee_client_api.c, linux drivers/tee/{tee_core.c, tee_shm.c, optee/call.c, optee/smc_abi.c}, "
                  "TF-A services/spd/opteed/opteed_main.c,", 14, C["sub"]))
    o.append(text(40, 1152, "      optee_os core/arch/arm/kernel/thread_optee_smc.c, core/tee/entry_std.c "
                  "(줄 번호는 이 리포 optee/ 트리 기준, 2026-11-19)", 14, C["sub"]))
    o.append("</svg>")
    return "\n".join(o)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(out, "06-kernel-driver-path")
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
