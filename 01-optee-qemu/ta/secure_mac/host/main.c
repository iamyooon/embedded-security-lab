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

int main(void)
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
