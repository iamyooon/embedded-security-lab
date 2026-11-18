/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Secure MAC Service - normal world 클라이언트(CA)
 *   SecOC 흉내: CAN id + freshness counter + payload 를 TA 에 보내 MAC 을 받는다.
 *   키는 절대 이쪽으로 오지 않는다 -- 마지막에 일부러 요구해보고 거부를 확인한다.
 */
#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>
#include <secure_mac_ta.h>

static void hexdump(const char *label, const uint8_t *buf, size_t len)
{
	size_t i;

	printf("%s (%zu B): ", label, len);
	for (i = 0; i < len; i++)
		printf("%02x", buf[i]);
	printf("\n");
}

/* SecOC 스타일 인증 대상: [CAN id (2B)][freshness (4B)][payload (8B)] */
static size_t build_frame(uint8_t *out, uint16_t can_id, uint32_t freshness,
			  const uint8_t *payload, size_t payload_len)
{
	size_t n = 0;

	out[n++] = can_id >> 8;
	out[n++] = can_id & 0xff;
	out[n++] = freshness >> 24;
	out[n++] = (freshness >> 16) & 0xff;
	out[n++] = (freshness >> 8) & 0xff;
	out[n++] = freshness & 0xff;
	memcpy(out + n, payload, payload_len);
	return n + payload_len;
}

/* ===================== 키 생명주기 통합 테스트 (argv[1] == "test") ===================== */
/*
 * 정상 + 부정 케이스. 각 줄: 기대 결과와 실제 결과를 비교해 PASS/FAIL.
 * 실패 기준(01 README 위협모델): 키 값이 API 로 보임 / 삭제한 id 로 MAC 됨.
 */
static int n_pass, n_fail;

static void check(const char *name, TEEC_Result got, TEEC_Result want)
{
	int ok = (got == want);

	printf("  %-4s %-46s got 0x%08x want 0x%08x\n", ok ? "PASS" : "FAIL",
	       name, got, want);
	ok ? n_pass++ : n_fail++;
}

static void check_true(const char *name, int cond, const char *detail)
{
	printf("  %-4s %-46s %s\n", cond ? "PASS" : "FAIL", name, detail);
	cond ? n_pass++ : n_fail++;
}

static TEEC_Result t_id_only(TEEC_Session *s, uint32_t cmd, uint32_t id)
{
	TEEC_Operation op;
	uint32_t eo;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = id;
	return TEEC_InvokeCommand(s, cmd, &op, &eo);
}

static TEEC_Result t_info(TEEC_Session *s, uint32_t id, uint32_t *type,
			  uint32_t *bits, uint32_t *usage)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t eo;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
					 TEEC_VALUE_OUTPUT, TEEC_NONE);
	op.params[0].value.a = id;
	res = TEEC_InvokeCommand(s, TA_SECURE_MAC_CMD_KEY_INFO, &op, &eo);
	*type = op.params[1].value.a;
	*bits = op.params[1].value.b;
	*usage = op.params[2].value.a;
	return res;
}

static TEEC_Result t_mac(TEEC_Session *s, uint32_t id, const uint8_t *msg,
			 size_t len, uint8_t *tag, size_t *tag_len)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t eo;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
	op.params[0].value.a = id;
	op.params[1].tmpref.buffer = (void *)msg;
	op.params[1].tmpref.size = len;
	op.params[2].tmpref.buffer = tag;
	op.params[2].tmpref.size = *tag_len;
	res = TEEC_InvokeCommand(s, TA_SECURE_MAC_CMD_MAC_BY_ID, &op, &eo);
	*tag_len = op.params[2].tmpref.size;
	return res;
}

static int run_tests(TEEC_Context *ctx, TEEC_UUID *uuid)
{
	TEEC_Session s1, s2;
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t eo, type = 0, bits = 0, usage = 0;
	const uint32_t ID = 1, NOID = 99;
	uint8_t frame[14], t1[SECURE_MAC_TAG_SIZE], t2[SECURE_MAC_TAG_SIZE];
	size_t flen, l1, l2;
	char buf[96];
	const uint8_t payload[8] = { 0x00, 0x64, 0, 0, 0, 0, 0, 0x01 };

	flen = build_frame(frame, 0x123, 42, payload, sizeof(payload));

	if (TEEC_OpenSession(ctx, &s1, uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &eo))
		errx(1, "open session 1 failed");
	t_id_only(&s1, TA_SECURE_MAC_CMD_KEY_DELETE, ID);	/* 이전 실행 잔여물 정리(결과 무시) */

	printf("== 정상 케이스\n");
	check("T1  KEY_CREATE id=1", t_id_only(&s1, TA_SECURE_MAC_CMD_KEY_CREATE, ID),
	      TEEC_SUCCESS);
	res = t_info(&s1, ID, &type, &bits, &usage);
	check("T2  KEY_INFO id=1", res, TEEC_SUCCESS);
	snprintf(buf, sizeof(buf), "type=0x%08x bits=%u usage=0x%08x", type, bits, usage);
	check_true("T3  메타데이터 = HMAC-SHA256/256bit/MAC 전용",
		   type == SECURE_MAC_GP_TYPE_HMAC_SHA256 && bits == 256 &&
		   usage == SECURE_MAC_GP_USAGE_MAC, buf);
	check_true("T4  EXTRACTABLE 없음 (반출 불가 속성 유지)",
		   !(usage & SECURE_MAC_GP_USAGE_EXTRACTABLE), buf);
	l1 = sizeof(t1);
	check("T5  MAC_BY_ID id=1", t_mac(&s1, ID, frame, flen, t1, &l1), TEEC_SUCCESS);
	TEEC_CloseSession(&s1);

	/* 세션을 닫았다 새로 열어도 같은 키 -> 같은 tag (영속성) */
	if (TEEC_OpenSession(ctx, &s2, uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &eo))
		errx(1, "open session 2 failed");
	l2 = sizeof(t2);
	res = t_mac(&s2, ID, frame, flen, t2, &l2);
	check("T6  새 세션에서 MAC_BY_ID id=1", res, TEEC_SUCCESS);
	check_true("T7  새 세션 tag == 이전 세션 tag (키가 남아 있음)",
		   res == TEEC_SUCCESS && l1 == l2 && !memcmp(t1, t2, l1),
		   "");

	printf("== 부정 케이스\n");
	check("N1  KEY_CREATE id=1 중복", t_id_only(&s2, TA_SECURE_MAC_CMD_KEY_CREATE, ID),
	      TEEC_ERROR_ACCESS_CONFLICT);
	check("N2  KEY_INFO 없는 id=99", t_info(&s2, NOID, &type, &bits, &usage),
	      TEEC_ERROR_ITEM_NOT_FOUND);
	l2 = sizeof(t2);
	check("N3  MAC_BY_ID 없는 id=99", t_mac(&s2, NOID, frame, flen, t2, &l2),
	      TEEC_ERROR_ITEM_NOT_FOUND);
	l2 = 16;
	check("N4  MAC_BY_ID tag 버퍼 16B (짧음)", t_mac(&s2, ID, frame, flen, t2, &l2),
	      TEEC_ERROR_SHORT_BUFFER);
	check_true("N5  SHORT_BUFFER 때 필요한 크기 32 를 알려줌", l2 == SECURE_MAC_TAG_SIZE, "");

	memset(&op, 0, sizeof(op));		/* id 를 VALUE 가 아니라 MEMREF 로 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = frame;
	op.params[0].tmpref.size = 4;
	check("N6  KEY_CREATE param 타입 틀림",
	      TEEC_InvokeCommand(&s2, TA_SECURE_MAC_CMD_KEY_CREATE, &op, &eo),
	      TEEC_ERROR_BAD_PARAMETERS);

	memset(&op, 0, sizeof(op));		/* GEN_KEY 에 쓸데없는 파라미터 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	check("N7  GEN_KEY param 타입 틀림 (보완한 검사)",
	      TEEC_InvokeCommand(&s2, TA_SECURE_MAC_CMD_GEN_KEY, &op, &eo),
	      TEEC_ERROR_BAD_PARAMETERS);

	printf("== 삭제\n");
	check("D1  KEY_DELETE id=1", t_id_only(&s2, TA_SECURE_MAC_CMD_KEY_DELETE, ID),
	      TEEC_SUCCESS);
	l2 = sizeof(t2);
	check("D2  삭제한 id=1 로 MAC_BY_ID (실패 기준 3)",
	      t_mac(&s2, ID, frame, flen, t2, &l2), TEEC_ERROR_ITEM_NOT_FOUND);
	check("D3  KEY_INFO 삭제한 id=1", t_info(&s2, ID, &type, &bits, &usage),
	      TEEC_ERROR_ITEM_NOT_FOUND);
	check("D4  KEY_DELETE 두 번", t_id_only(&s2, TA_SECURE_MAC_CMD_KEY_DELETE, ID),
	      TEEC_ERROR_ITEM_NOT_FOUND);
	TEEC_CloseSession(&s2);

	printf("== 결과: PASS %d / FAIL %d\n", n_pass, n_fail);
	return n_fail ? 1 : 0;
}

int main(int argc, char *argv[])
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SECURE_MAC_UUID;
	TEEC_Result res;
	uint32_t err_origin = 0;

	uint8_t frame[14];
	size_t frame_len;
	uint8_t tag[SECURE_MAC_TAG_SIZE];
	uint8_t stolen[SECURE_MAC_KEY_BITS / 8];
	const uint8_t payload[8] = { 0x00, 0x64, 0x00, 0x00,
				     0x00, 0x00, 0x00, 0x01 }; /* 속도=100 등 */

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed 0x%x", res);

	if (argc > 1 && !strcmp(argv[1], "test")) {
		int rc = run_tests(&ctx, &uuid);

		TEEC_FinalizeContext(&ctx);
		return rc;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC,
			       NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession failed 0x%x origin 0x%x",
		     res, err_origin);

	/* 1) secure world 안에서 키 생성 */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	res = TEEC_InvokeCommand(&sess, TA_SECURE_MAC_CMD_GEN_KEY, &op,
				 &err_origin);
	printf("[1] GEN_KEY      -> 0x%08x %s\n", res,
	       res == TEEC_SUCCESS ? "(키는 secure world 안)" : "(실패)");
	if (res != TEEC_SUCCESS)
		goto out;

	/* 2) 프레임에 MAC 붙이기 */
	frame_len = build_frame(frame, 0x123, 42, payload, sizeof(payload));
	hexdump("    frame", frame, frame_len);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = frame;
	op.params[0].tmpref.size = frame_len;
	op.params[1].tmpref.buffer = tag;
	op.params[1].tmpref.size = sizeof(tag);
	res = TEEC_InvokeCommand(&sess, TA_SECURE_MAC_CMD_MAC, &op,
				 &err_origin);
	printf("[2] MAC          -> 0x%08x\n", res);
	if (res != TEEC_SUCCESS)
		goto out;
	hexdump("    tag", tag, op.params[1].tmpref.size);

	/* 3) 정상 프레임 검증 -> valid=1 이어야 한다 */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_OUTPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = frame;
	op.params[0].tmpref.size = frame_len;
	op.params[1].tmpref.buffer = tag;
	op.params[1].tmpref.size = sizeof(tag);
	res = TEEC_InvokeCommand(&sess, TA_SECURE_MAC_CMD_VERIFY, &op,
				 &err_origin);
	printf("[3] VERIFY(정상) -> 0x%08x valid=%u\n", res, op.params[2].value.a);

	/* 4) 페이로드 1바이트 변조 -> valid=0 이어야 한다 (변조 공격. 재전송은 별개) */
	frame[7] ^= 0x01;
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_OUTPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = frame;
	op.params[0].tmpref.size = frame_len;
	op.params[1].tmpref.buffer = tag;
	op.params[1].tmpref.size = sizeof(tag);
	res = TEEC_InvokeCommand(&sess, TA_SECURE_MAC_CMD_VERIFY, &op,
				 &err_origin);
	printf("[4] VERIFY(변조) -> 0x%08x valid=%u\n", res, op.params[2].value.a);
	frame[7] ^= 0x01;

	/* 5) 공격 데모: root 인 normal world 가 키 자체를 요구한다 */
	memset(stolen, 0, sizeof(stolen));
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = stolen;
	op.params[0].tmpref.size = sizeof(stolen);
	res = TEEC_InvokeCommand(&sess, TA_SECURE_MAC_CMD_EXPORT_KEY, &op,
				 &err_origin);
	printf("[5] EXPORT_KEY   -> 0x%08x origin 0x%x %s\n", res, err_origin,
	       res == TEEC_SUCCESS ? "!!! 키가 샜다 !!!" : "(거부됨)");
	hexdump("    stolen buf", stolen, sizeof(stolen));

out:
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
