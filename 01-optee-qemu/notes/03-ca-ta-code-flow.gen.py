#!/usr/bin/env python3
"""CA <-> TA code flow diagram (secure_mac). SVG + PNG."""
import sys
from xml.sax.saxutils import escape

OUT = sys.argv[1]

W = 1920
CA_X, CA_W = 40, 560
OS_X, OS_W = 720, 380
TA_X, TA_W = 1240, 640
LH = 23          # line height
PAD = 14
GAP = 26

F = "NanumGothic, sans-serif"
M = "NanumGothicCoding, monospace"

C = {
    "nw_bg": "#e8f0fb", "nw_bd": "#3b6fb6",
    "sw_bg": "#e7f5ec", "sw_bd": "#2e8b57",
    "os_bg": "#f2f2f2", "os_bd": "#888888",
    "bad_bg": "#fdecea", "bad_bd": "#c0392b",
    "txt": "#1d1d1f", "sub": "#555555",
    "req": "#3b6fb6", "resp": "#2e8b57", "dead": "#c0392b",
}

# (title, ca_lines, os_lines, ta_lines, req_label, resp_label, kind)
# kind: normal / local(no SMC) / bad
STEPS = [
    ("준비", ["TEEC_InitializeContext(NULL, &ctx)",
              "  /dev/tee0 open -> ctx.fd 채움"],
     ["SMC 없음", "(드라이버와 연결만)"], [], None, None, "local"),
    ("세션 열기", ["TEEC_OpenSession(&ctx, &sess, &uuid,",
                   "                 TEEC_LOGIN_PUBLIC, ...)",
                   "  uuid = 82a856b1-...-318d1360ffad",
                   "  LOGIN_PUBLIC: 호출자 신원 없음"],
     ["tee-supplicant 로", "/lib/optee_armtz/<uuid>.ta 로드",
      "서명 검증 + 헤더 uuid 대조"],
     ["TA_CreateEntryPoint()",
      "TA_OpenSessionEntryPoint()",
      "  mac_ctx 할당, ctx->key = NULL"],
     "open(uuid)", "sess.session_id", "normal"),
    ("[1] GEN_KEY (cmd 0)", ["paramTypes = NONE, NONE, NONE, NONE",
                             "TEEC_InvokeCommand(&sess, GEN_KEY, &op)"],
     ["TA_InvokeCommandEntryPoint", "switch(cmd) -> gen_key"],
     ["gen_key(ctx)",
      "  TEE_AllocateTransientObject(HMAC_SHA256, 256)",
      "  TEE_GenerateKey  -> 난수 256bit (매번 다름)",
      "  TEE_RestrictObjectUsage(USAGE_MAC 만)",
      "  ctx->key = obj   (옛 키는 Free)"],
     "cmd=0", "res = 0x00000000", "normal"),
    ("[2] MAC (cmd 1)", ["build_frame(frame, 0x123, 42, payload)",
                         "  frame 14B = 0123 0000002a 0064000000000001",
                         "paramTypes = MEMREF_TEMP_INPUT,",
                         "             MEMREF_TEMP_OUTPUT, NONE, NONE",
                         "params[0] = frame(14B)  params[1] = tag(32B)",
                         "TEEC_InvokeCommand(&sess, MAC, &op)"],
     ["frame / tag 버퍼를", "secure world 와 공유(매핑)"],
     ["cmd_mac(ptypes, params)",
      "  ptypes == exp ?   아니면 BAD_PARAMETERS",
      "  key 있나? tag 버퍼 >= 32B ?",
      "  mac_do(compare=false)",
      "    TEE_AllocateOperation(HMAC_SHA256, MAC)",
      "    TEE_SetOperationKey(op, ctx->key)",
      "    TEE_MACInit / TEE_MACUpdate(frame)",
      "    TEE_MACComputeFinal -> tag 32B",
      "  params[1].size = 32"],
     "cmd=1, frame", "res = 0x0, tag 32B", "normal"),
    ("[3] VERIFY 정상 / [4] VERIFY 변조 (cmd 2)",
     ["paramTypes = MEMREF_TEMP_INPUT(frame),",
      "             MEMREF_TEMP_INPUT(tag),",
      "             VALUE_OUTPUT, NONE",
      "[4] 는 그 전에 frame[7] ^= 0x01",
      "    (8번째 바이트 최하위 비트: 0x64 -> 0x65)",
      "TEEC_InvokeCommand(&sess, VERIFY, &op)"],
     ["값(value.a)은 복사로", "CA 에 돌려줌"],
     ["cmd_verify(ptypes, params)",
      "  mac_do(compare=true)",
      "    TEE_MACCompareFinal(tag)",
      "  SUCCESS      -> value.a = 1",
      "  MAC_INVALID  -> value.a = 0, res = SUCCESS",
      "  (res = 작업 성공 여부, valid = 진짜 여부)"],
     "cmd=2, frame, tag", "[3] 0x0 valid=1 / [4] 0x0 valid=0", "normal"),
    ("[5] EXPORT_KEY 공격 데모 (cmd 3)",
     ["paramTypes = MEMREF_TEMP_OUTPUT, NONE x3",
      "params[0] = stolen(32B, 0 으로 채움)",
      "TEEC_InvokeCommand(&sess, EXPORT_KEY, &op)",
      "",
      "결과: 0xffff3024 TARGET_DEAD, origin 3(TEE)",
      "      stolen 은 전부 00 -> 키 안 샘"],
     ["코어(tee_svc_cryp.c):", "EXTRACTABLE 없음",
      "-> BAD_PARAMETERS(0xffff0006)",
      "TA 가 죽었으므로", "OP-TEE OS 가 대신 응답"],
     ["cmd_export_key(ptypes, params)",
      "  TEE_GetObjectBufferAttribute(SECRET_VALUE)",
      "    -> 코어가 BAD_PARAMETERS 리턴",
      "    -> libutee: 허용 목록 밖 -> TEE_Panic",
      "  [TA 사망. return 에 도달 못함]"],
     "cmd=3", "0xffff3024 TARGET_DEAD", "bad"),
    ("정리", ["TEEC_CloseSession(&sess)",
              "TEEC_FinalizeContext(&ctx)"],
     ["세션 / 컨텍스트 해제"],
     ["transient 키는 메모리에만 있다가 사라짐",
      "-> 다음 실행은 새 키 -> tag 도 달라짐"],
     "close", None, "normal"),
]


def text(x, y, s, size=16, fam=F, color=C["txt"], weight="normal", anchor="start"):
    return (f'<text x="{x}" y="{y}" font-family="{fam}" font-size="{size}" '
            f'fill="{color}" font-weight="{weight}" text-anchor="{anchor}" xml:space="preserve">'
            f'{escape(s)}</text>')


def box(x, y, w, h, bg, bd, r=10, dash=False):
    d = ' stroke-dasharray="6 4"' if dash else ""
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" '
            f'fill="{bg}" stroke="{bd}" stroke-width="2"{d}/>')


def arrow(x1, x2, y, color, label, above=True):
    out = [f'<line x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" stroke="{color}" '
           f'stroke-width="2.5" marker-end="url(#a-{color[1:]})"/>']
    if label:
        ly = y - 7 if above else y + 19
        out.append(text((x1 + x2) / 2, ly, label, 14, F, color, "bold", "middle"))
    return out


els = []
y = 30
els.append(text(W / 2, y + 12, "secure_mac: CA <-> TA 코드 흐름", 28, F, C["txt"], "bold", "middle"))
els.append(text(W / 2, y + 42, "01-optee-qemu/ta/secure_mac  |  host/main.c  <->  ta/secure_mac_ta.c  |  2026-11-17 실행 결과 기준",
                15, F, C["sub"], "normal", "middle"))
y += 70

# column headers
HH = 64
els.append(box(CA_X, y, CA_W, HH, C["nw_bd"], C["nw_bd"]))
els.append(text(CA_X + CA_W / 2, y + 28, "CA  (normal world, EL0)", 20, F, "#fff", "bold", "middle"))
els.append(text(CA_X + CA_W / 2, y + 50, "host/main.c  ->  libteec", 15, F, "#fff", "normal", "middle"))
els.append(box(OS_X, y, OS_W, HH, C["os_bd"], C["os_bd"]))
els.append(text(OS_X + OS_W / 2, y + 28, "통로 (world switch)", 20, F, "#fff", "bold", "middle"))
els.append(text(OS_X + OS_W / 2, y + 50, "드라이버(EL1) -> TF-A(EL3) -> OP-TEE OS(S-EL1)", 12, F, "#fff", "normal", "middle"))
els.append(box(TA_X, y, TA_W, HH, C["sw_bd"], C["sw_bd"]))
els.append(text(TA_X + TA_W / 2, y + 28, "TA  (secure world, S-EL0)", 20, F, "#fff", "bold", "middle"))
els.append(text(TA_X + TA_W / 2, y + 50, "ta/secure_mac_ta.c  ->  libutee", 15, F, "#fff", "normal", "middle"))
y += HH + 20
lane_top = y

rows = []
for title, ca, os_, ta, req, resp, kind in STEPS:
    n = max(len(ca), len(os_), len(ta), 2)
    h = 40 + n * LH + PAD * 2
    rows.append((y, h, title, ca, os_, ta, req, resp, kind))
    y += h + GAP
H = y + 70

# lanes background
els.insert(0, f'<rect x="{OS_X}" y="{lane_top - 6}" width="{OS_W}" height="{y - lane_top}" fill="#fafafa"/>')

for (ry, h, title, ca, os_, ta, req, resp, kind) in rows:
    bad = kind == "bad"
    # step title band
    els.append(text(CA_X, ry + 22, title, 18, F, C["dead"] if bad else C["txt"], "bold"))
    by = ry + 34
    bh = h - 34
    els.append(box(CA_X, by, CA_W, bh, C["nw_bg"], C["nw_bd"]))
    for i, ln in enumerate(ca):
        col = C["dead"] if (bad and ln.startswith(("결과", "      stolen"))) else C["txt"]
        els.append(text(CA_X + 16, by + PAD + 16 + i * LH, ln, 15, M, col))
    if os_:
        els.append(box(OS_X + 20, by, OS_W - 40, bh, C["os_bg"], C["os_bd"], dash=(kind == "local")))
        for i, ln in enumerate(os_):
            els.append(text(OS_X + OS_W / 2, by + PAD + 16 + i * LH, ln, 14, F, C["sub"], "normal", "middle"))
    if ta:
        els.append(box(TA_X, by, TA_W, bh, C["bad_bg"] if bad else C["sw_bg"],
                       C["bad_bd"] if bad else C["sw_bd"]))
        for i, ln in enumerate(ta):
            col = C["dead"] if (bad and ("Panic" in ln or "사망" in ln)) else C["txt"]
            els.append(text(TA_X + 16, by + PAD + 16 + i * LH, ln, 15, M, col))
    # arrows
    if req:
        ay = by + 26
        els += arrow(CA_X + CA_W, OS_X + 20, ay, C["req"], "")
        els += arrow(OS_X + OS_W - 20, TA_X, ay, C["req"], req)
        els.append(text((CA_X + CA_W + OS_X + 20) / 2, ay - 7, "SMC", 13, F, C["req"], "bold", "middle"))
    if resp:
        ay = by + bh - 20
        if bad:
            els += arrow(OS_X + 20, CA_X + CA_W, ay, C["dead"], "")
            els.append(text(OS_X + OS_W / 2, ay - 8, resp, 14, F, C["dead"], "bold", "middle"))
            # TA dies: X mark between TA and OS
            cx, cy = (OS_X + OS_W - 20 + TA_X) / 2, ay
            els.append(f'<line x1="{cx-10}" y1="{cy-10}" x2="{cx+10}" y2="{cy+10}" stroke="{C["dead"]}" stroke-width="4"/>')
            els.append(f'<line x1="{cx-10}" y1="{cy+10}" x2="{cx+10}" y2="{cy-10}" stroke="{C["dead"]}" stroke-width="4"/>')
            els.append(text(cx, cy + 30, "panic", 13, F, C["dead"], "bold", "middle"))
        else:
            els += arrow(TA_X, OS_X + OS_W - 20, ay, C["resp"], "")
            els += arrow(OS_X + 20, CA_X + CA_W, ay, C["resp"], "")
            els.append(text(OS_X + OS_W / 2, ay - 8, resp, 14, F, C["resp"], "bold", "middle"))

# legend
ly = H - 40
els += arrow(CA_X, CA_X + 60, ly, C["req"], "")
els.append(text(CA_X + 70, ly + 5, "요청 (InvokeCommand -> SMC -> TA)", 14, F, C["sub"]))
els += arrow(CA_X + 420, CA_X + 480, ly, C["resp"], "")
els.append(text(CA_X + 490, ly + 5, "응답 (res, OUTPUT 버퍼/값)", 14, F, C["sub"]))
els += arrow(CA_X + 800, CA_X + 860, ly, C["dead"], "")
els.append(text(CA_X + 870, ly + 5, "TA 가 죽어 OP-TEE OS 가 대신 응답", 14, F, C["sub"]))
els.append(text(W - 40, ly + 5, "점선 = SMC 없이 normal world 안에서 끝남", 14, F, C["sub"], "normal", "end"))

markers = "".join(
    f'<marker id="a-{c[1:]}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
    f'<path d="M0,0 L10,5 L0,10 z" fill="{c}"/></marker>'
    for c in {C["req"], C["resp"], C["dead"]})

svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">'
       f'<defs>{markers}</defs><rect width="{W}" height="{H}" fill="#ffffff"/>'
       + "".join(els) + "</svg>")
open(OUT + ".svg", "w").write(svg)

import cairosvg
cairosvg.svg2png(bytestring=svg.encode(), write_to=OUT + ".png", scale=1.5)
print(OUT + ".svg", OUT + ".png", W, H)
