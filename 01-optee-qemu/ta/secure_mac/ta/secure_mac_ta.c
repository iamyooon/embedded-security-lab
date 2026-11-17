/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Secure MAC Service — SecOC 스타일 TA
 *   키는 secure world 안에서 생성되고 밖으로 나가지 않는다.
 *   normal world 는 "메시지 -> MAC" 결과만 받는다.
 *
 * 규칙 5(핵심 코드는 손으로): 아래 TODO 두 곳은 직접 타이핑한다.
 */
#include <secure_mac_ta.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

/* 세션마다 하나. 키는 '핸들'로만 들고 있어 raw 바이트가 TA 메모리에 굴러다니지 않는다. */
struct mac_ctx {
	TEE_ObjectHandle key;	/* TEE_TYPE_HMAC_SHA256, non-extractable */
};

/*
 * TODO(나) 1 — 키 생성
 *
 *   1) TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, SECURE_MAC_KEY_BITS, &obj)
 *   2) TEE_GenerateKey(obj, SECURE_MAC_KEY_BITS, NULL, 0)   <- secure world RNG
 *   3) TEE_RestrictObjectUsage(obj, TEE_USAGE_MAC)          <- EXTRACTABLE 제거 = 반출 금지
 *   4) 기존 ctx->key 가 있으면 TEE_FreeTransientObject 로 정리 후 교체
 *   실패하면 할당한 obj 를 반드시 해제하고 res 반환.
 */
static TEE_Result gen_key(struct mac_ctx *ctx)
{
	TEE_Result rst = TEE_ERROR_GENERIC;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;

	rst = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, SECURE_MAC_KEY_BITS, &obj);
	if (rst != TEE_SUCCESS) {
		return rst;
	}

	rst = TEE_GenerateKey(obj, SECURE_MAC_KEY_BITS, NULL, 0);
	if (rst != TEE_SUCCESS) {
		TEE_FreeTransientObject(obj);
		return rst;
	}

	TEE_RestrictObjectUsage(obj, TEE_USAGE_MAC);
	if (ctx->key != TEE_HANDLE_NULL){
		TEE_FreeTransientObject(ctx->key);
	}

	ctx->key = obj;
	return rst;
}

/*
 * TODO(나) 2 — MAC 계산 (mode: TEE_MODE_MAC)
 *
 *   1) TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC,
 *                            SECURE_MAC_KEY_BITS)
 *   2) TEE_SetOperationKey(op, ctx->key)
 *   3) TEE_MACInit(op, NULL, 0);  TEE_MACUpdate(op, msg, msg_len);
 *   4) 계산이면  TEE_MACComputeFinal(op, NULL, 0, tag, tag_len)
 *      검증이면  TEE_MACCompareFinal(op, NULL, 0, tag, *tag_len)
 *                -> 불일치는 TEE_ERROR_MAC_INVALID 로 돌아온다
 *   5) TEE_FreeOperation(op)
 *
 * (길이 인자가 size_t 가 아니라 uint32_t 인 이유: ta/Makefile 의
 *  CFG_TA_OPTEE_CORE_API_COMPAT_1_1=y -> GP 1.1 시그니처를 쓴다.)
 *
 * compare == false : tag 에 결과를 쓴다(*tag_len 은 in/out)
 * compare == true  : tag 를 정답과 비교만 한다
 */
static TEE_Result mac_do(struct mac_ctx *ctx, const void *msg, size_t msg_len,
			 void *tag, uint32_t *tag_len, bool compare)
{
	TEE_Result rst = TEE_ERROR_GENERIC;
	TEE_OperationHandle op = TEE_HANDLE_NULL;

	rst = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC,
				SECURE_MAC_KEY_BITS);
	if (rst != TEE_SUCCESS) {
		return rst;
	}

	rst = TEE_SetOperationKey(op, ctx->key);
	if (rst != TEE_SUCCESS) {
		TEE_FreeOperation(op);
		return rst;
	}

	TEE_MACInit(op, NULL, 0);

	TEE_MACUpdate(op, msg, msg_len);
	if (compare == false) {
		rst = TEE_MACComputeFinal(op, NULL, 0, tag, tag_len);
	} else {
		rst = TEE_MACCompareFinal(op, NULL, 0, tag, *tag_len);
	}

	TEE_FreeOperation(op);
	return rst;
}

/* ---- 여기서부터는 배관(Claude): 파라미터 검사와 디스패치 ---- */

static TEE_Result cmd_mac(struct mac_ctx *ctx, uint32_t ptypes,
			  TEE_Param params[4])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				       TEE_PARAM_TYPE_MEMREF_OUTPUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);
	uint32_t tag_len = 0;

	if (ptypes != exp)
		return TEE_ERROR_BAD_PARAMETERS;
	if (ctx->key == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_STATE;	/* GEN_KEY 먼저 */
	if (params[1].memref.size < SECURE_MAC_TAG_SIZE) {
		params[1].memref.size = SECURE_MAC_TAG_SIZE;
		return TEE_ERROR_SHORT_BUFFER;
	}

	tag_len = params[1].memref.size;
	return mac_do(ctx, params[0].memref.buffer, params[0].memref.size,
		      params[1].memref.buffer, &tag_len, false);
}

static TEE_Result cmd_verify(struct mac_ctx *ctx, uint32_t ptypes,
			     TEE_Param params[4])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				       TEE_PARAM_TYPE_MEMREF_INPUT,
				       TEE_PARAM_TYPE_VALUE_OUTPUT,
				       TEE_PARAM_TYPE_NONE);
	uint32_t tag_len = 0;
	TEE_Result res = TEE_SUCCESS;

	if (ptypes != exp)
		return TEE_ERROR_BAD_PARAMETERS;
	if (ctx->key == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_STATE;

	tag_len = params[1].memref.size;
	res = mac_do(ctx, params[0].memref.buffer, params[0].memref.size,
		     params[1].memref.buffer, &tag_len, true);

	if (res == TEE_SUCCESS) {
		params[2].value.a = 1;
	} else if (res == TEE_ERROR_MAC_INVALID) {
		params[2].value.a = 0;
		res = TEE_SUCCESS;	/* "위조였다"는 정상 응답 */
	}
	return res;
}

/*
 * 공격 데모(규칙 3): normal world 가 키 자체를 달라고 한다.
 * 키 오브젝트는 TEE_USAGE_EXTRACTABLE 이 제거돼 있으므로 반출은 불가능하다.
 * -> ACCESS_DENIED. (GP 규격상 이 오류는 TA panic 으로 이어질 수 있고,
 *    그것도 "새는 것보다 죽는다"는 정상 동작이다. 결과를 예측한 뒤 실행해보기.)
 */
static TEE_Result cmd_export_key(struct mac_ctx *ctx, uint32_t ptypes,
				 TEE_Param params[4])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);
	uint32_t sz = 0;

	if (ptypes != exp)
		return TEE_ERROR_BAD_PARAMETERS;
	if (ctx->key == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_STATE;

	sz = params[0].memref.size;
	IMSG("normal world asked for the raw key -- trying to extract it");
	return TEE_GetObjectBufferAttribute(ctx->key, TEE_ATTR_SECRET_VALUE,
					    params[0].memref.buffer, &sz);
}

/* ---- 필수 엔트리 포인트 ---- */

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t ptypes, TEE_Param params[4],
				    void **sess_ctx)
{
	struct mac_ctx *ctx = NULL;

	(void)ptypes;
	(void)params;

	ctx = TEE_Malloc(sizeof(*ctx), TEE_MALLOC_FILL_ZERO);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	ctx->key = TEE_HANDLE_NULL;
	*sess_ctx = ctx;
	IMSG("secure_mac: session opened");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct mac_ctx *ctx = sess_ctx;

	if (!ctx)
		return;
	if (ctx->key != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(ctx->key);
	TEE_Free(ctx);
	IMSG("secure_mac: session closed");
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t ptypes, TEE_Param params[4])
{
	struct mac_ctx *ctx = sess_ctx;

	switch (cmd_id) {
	case TA_SECURE_MAC_CMD_GEN_KEY:
		return gen_key(ctx);
	case TA_SECURE_MAC_CMD_MAC:
		return cmd_mac(ctx, ptypes, params);
	case TA_SECURE_MAC_CMD_VERIFY:
		return cmd_verify(ctx, ptypes, params);
	case TA_SECURE_MAC_CMD_EXPORT_KEY:
		return cmd_export_key(ctx, ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
