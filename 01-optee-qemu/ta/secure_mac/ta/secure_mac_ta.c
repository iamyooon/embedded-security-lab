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

/* ===================== 키 생명주기 (Persistent Object) ===================== */
/*
 * objectID = key id 4바이트. 저장소는 TA UUID 별로 분리돼 다른 TA 는 같은 id 로도 못 연다.
 * 공통 규칙: 연 핸들은 반드시 닫는다 (TEE_CloseObject). 실패 경로도.
 */

/* 접근 제어 함수 (아래 "호출자별 접근 제어" 절에 정의) */
static TEE_Result get_client_identity(TEE_Identity *who);
static TEE_Result check_owner(TEE_ObjectHandle obj);

/*
 * TODO(나) 3 — 키 생성 후 영구 저장
 *
 *   1) gen_key() 와 같은 방법으로 transient 키를 만든다
 *      (Allocate -> GenerateKey -> RestrictObjectUsage(TEE_USAGE_MAC))
 *   2) TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &id, sizeof(id),
 *                                 TEE_DATA_FLAG_ACCESS_READ,   <- 덮어쓰기 플래그 없음 = 같은 id 면 ACCESS_CONFLICT
 *                                 tobj, NULL, 0, &pobj)
 *      -> tobj 의 속성(키 값)과 usage 가 그대로 복사된다
 *   3) TEE_CloseObject(pobj)
 *   4) TEE_FreeTransientObject(tobj)   <- 메모리의 키 사본 정리. 성공/실패 모두
 *   res 반환.
 */
static TEE_Result key_create(uint32_t id)
{
	TEE_Result rst = TEE_ERROR_GENERIC;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_ObjectHandle pobj = TEE_HANDLE_NULL;
	TEE_Identity me;

	rst = get_client_identity(&me);
	if (rst != TEE_SUCCESS) {
		return rst;
	}

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

	rst = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &id, sizeof(id),
					TEE_DATA_FLAG_ACCESS_READ, obj, &me, sizeof(me), &pobj);

	TEE_CloseObject(pobj);
	TEE_FreeTransientObject(obj);

	return rst;

}

/*
 * TODO(나) 4 — 메타데이터 조회 (키 값은 절대 안 읽는다)
 *
 *   1) TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &id, sizeof(id),
 *                               TEE_DATA_FLAG_ACCESS_READ, &obj)
 *      -> 없으면 TEE_ERROR_ITEM_NOT_FOUND 가 그대로 돌아오게 둔다
 *   2) TEE_GetObjectInfo1(obj, info)
 *   3) TEE_CloseObject(obj)
 */
static TEE_Result key_info(uint32_t id, TEE_ObjectInfo *info)
{
	TEE_Result rst = TEE_ERROR_GENERIC;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;

	rst = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &id, sizeof(id),
					TEE_DATA_FLAG_ACCESS_READ, &obj);

	if (rst != TEE_SUCCESS) {
		return rst;
	}

	rst = check_owner(obj);
	if (rst != TEE_SUCCESS) {
		TEE_CloseObject(obj);
		return rst;
	}

	rst = TEE_GetObjectInfo1(obj, info);
	TEE_CloseObject(obj);

	return rst;
}

/*
 * TODO(나) 5 — 삭제
 *
 *   1) TEE_OpenPersistentObject(..., TEE_DATA_FLAG_ACCESS_WRITE_META, &obj)
 *      <- 삭제/이름변경 권한은 WRITE_META 로 연 핸들에만 있다
 *   2) TEE_CloseAndDeletePersistentObject1(obj)   <- 닫기까지 한다 (따로 Close 하지 않음)
 */
static TEE_Result key_delete(uint32_t id)
{
	TEE_Result rst = TEE_ERROR_GENERIC;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;

	rst = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &id, sizeof(id),
					TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_ACCESS_READ,
					&obj);
	if (rst != TEE_SUCCESS) {
		return rst;
	}

	rst = check_owner(obj);
	if (rst != TEE_SUCCESS) {
		TEE_CloseObject(obj);
		return rst;
	}

	rst = TEE_CloseAndDeletePersistentObject1(obj);
	if (rst != TEE_SUCCESS) {
		return rst;
	}

	return rst;
}

/*
 * TODO(나) 6 — 저장된 키로 MAC
 *
 *   1) TEE_OpenPersistentObject(..., TEE_DATA_FLAG_ACCESS_READ, &obj)
 *   2) struct mac_ctx tmp = { .key = obj };
 *      mac_do(&tmp, msg, msg_len, tag, tag_len, false)   <- TODO 2 를 그대로 재사용
 *   3) TEE_CloseObject(obj)
 */
static TEE_Result mac_by_id(uint32_t id, const void *msg, size_t msg_len,
			    void *tag, uint32_t *tag_len)
{
	TEE_Result rst = TEE_ERROR_GENERIC;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;

	rst = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &id, sizeof(id),
					TEE_DATA_FLAG_ACCESS_READ, &obj);
	if (rst != TEE_SUCCESS) {
		return rst;
	}

	rst = check_owner(obj);
	if (rst != TEE_SUCCESS) {
		TEE_CloseObject(obj);
		return rst;
	}

	struct mac_ctx tmp = {
		.key = obj
	};

	rst = mac_do(&tmp, msg, msg_len, tag, tag_len, false);
	if (rst != TEE_SUCCESS) {
		TEE_CloseObject(obj);
		return rst;
	}

	TEE_CloseObject(obj);
	return rst;
}

/* ===================== 호출자별 접근 제어 (2026-11-18) ===================== */
/*
 * 키 주인 = 키를 만든 호출자의 신원(TEE_Identity: login 종류 + uuid, 20바이트).
 * 신원은 normal world 커널(OP-TEE 드라이버)이 uid 로 계산해 넣는다
 *   -> 다른 uid 의 앱은 막지만, root 는 setuid 로 주인 행세 가능 (위협모델 "못 막는 것").
 * 주인 신원은 persistent object 의 데이터 영역(initialData)에 키와 같이 저장한다.
 */

/* 배관(Claude): 현재 호출자 신원. LOGIN_PUBLIC(신원 없음)은 키 기능을 못 쓴다. */
static TEE_Result get_client_identity(TEE_Identity *who)
{
	TEE_Result res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT,
						   "gpd.client.identity", who);

	if (res != TEE_SUCCESS)
		return res;
	if (who->login == TEE_LOGIN_PUBLIC)
		return TEE_ERROR_ACCESS_DENIED;
	return TEE_SUCCESS;
}

/*
 * TODO(나) 7 — 주인 확인
 *
 *   obj 는 TEE_DATA_FLAG_ACCESS_READ 를 포함해 연 핸들이어야 한다 (데이터를 읽으니까).
 *   1) TEE_Identity me, owner;  uint32_t n = 0;
 *   2) get_client_identity(&me) -- 실패면 그대로 반환
 *   3) TEE_ReadObjectData(obj, &owner, sizeof(owner), &n)
 *      -> n != sizeof(owner) 면 TEE_ERROR_CORRUPT_OBJECT
 *   4) memcmp(&me, &owner, sizeof(me)) != 0 이면 TEE_ERROR_ACCESS_DENIED
 *   5) 같으면 TEE_SUCCESS
 *
 * TODO(나) 8 — 이걸 쓰도록 위 함수들 수정
 *   key_create : get_client_identity(&me) 로 신원을 얻어
 *                TEE_CreatePersistentObject(..., obj, &me, sizeof(me), &pobj)  <- NULL, 0 대신
 *   key_info / mac_by_id : Open 성공 직후 check_owner(obj), 실패면 Close 하고 반환
 *   key_delete : Open 플래그를 ACCESS_READ | ACCESS_WRITE_META 로 (읽어야 하니까),
 *                check_owner 실패면 Close 하고 반환 (삭제하면 안 됨)
 */
static TEE_Result check_owner(TEE_ObjectHandle obj)
{
	TEE_Result rst = TEE_ERROR_GENERIC;
	TEE_Identity me, owner;
	uint32_t n = 0;

	rst = get_client_identity(&me);
	if (rst != TEE_SUCCESS) {
		return rst;
	}

	rst = TEE_ReadObjectData(obj, &owner, sizeof(owner), &n);
	if (rst != TEE_SUCCESS) {
		return rst;
	} else if (n != sizeof(owner)) {
		return TEE_ERROR_CORRUPT_OBJECT;
	}

	if (memcmp(&me, &owner, sizeof(me)) != 0) {
		return TEE_ERROR_ACCESS_DENIED;
	} else {
		return TEE_SUCCESS;
	}
}

/* ---- 여기서부터는 배관(Claude): 파라미터 검사와 디스패치 ---- */

static TEE_Result cmd_gen_key(struct mac_ctx *ctx, uint32_t ptypes)
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (ptypes != exp)
		return TEE_ERROR_BAD_PARAMETERS;	/* 2026-11-18 추가: 원래 검사 없었음 */
	return gen_key(ctx);
}

static TEE_Result cmd_key_create(uint32_t ptypes, TEE_Param params[4])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);

	if (ptypes != exp)
		return TEE_ERROR_BAD_PARAMETERS;
	return key_create(params[0].value.a);
}

static TEE_Result cmd_key_info(uint32_t ptypes, TEE_Param params[4])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				       TEE_PARAM_TYPE_VALUE_OUTPUT,
				       TEE_PARAM_TYPE_VALUE_OUTPUT,
				       TEE_PARAM_TYPE_NONE);
	TEE_ObjectInfo info = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	if (ptypes != exp)
		return TEE_ERROR_BAD_PARAMETERS;
	res = key_info(params[0].value.a, &info);
	if (res != TEE_SUCCESS)
		return res;
	params[1].value.a = info.objectType;
	params[1].value.b = info.keySize;
	params[2].value.a = info.objectUsage;
	return TEE_SUCCESS;
}

static TEE_Result cmd_key_delete(uint32_t ptypes, TEE_Param params[4])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);

	if (ptypes != exp)
		return TEE_ERROR_BAD_PARAMETERS;
	return key_delete(params[0].value.a);
}

static TEE_Result cmd_mac_by_id(uint32_t ptypes, TEE_Param params[4])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				       TEE_PARAM_TYPE_MEMREF_INPUT,
				       TEE_PARAM_TYPE_MEMREF_OUTPUT,
				       TEE_PARAM_TYPE_NONE);
	uint32_t tag_len = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (ptypes != exp)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[2].memref.size < SECURE_MAC_TAG_SIZE) {
		params[2].memref.size = SECURE_MAC_TAG_SIZE;
		return TEE_ERROR_SHORT_BUFFER;
	}

	tag_len = params[2].memref.size;
	res = mac_by_id(params[0].value.a, params[1].memref.buffer,
			params[1].memref.size, params[2].memref.buffer, &tag_len);
	if (res == TEE_SUCCESS)
		params[2].memref.size = tag_len;
	return res;
}

static TEE_Result cmd_mac(struct mac_ctx *ctx, uint32_t ptypes,
			  TEE_Param params[4])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				       TEE_PARAM_TYPE_MEMREF_OUTPUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);
	uint32_t tag_len = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (ptypes != exp)
		return TEE_ERROR_BAD_PARAMETERS;
	if (ctx->key == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_STATE;	/* GEN_KEY 먼저 */
	if (params[1].memref.size < SECURE_MAC_TAG_SIZE) {
		params[1].memref.size = SECURE_MAC_TAG_SIZE;
		return TEE_ERROR_SHORT_BUFFER;
	}

	tag_len = params[1].memref.size;
	res = mac_do(ctx, params[0].memref.buffer, params[0].memref.size,
		     params[1].memref.buffer, &tag_len, false);
	if (res == TEE_SUCCESS)
		params[1].memref.size = tag_len;	/* 실제로 쓴 길이를 CA 에 알림 */
	return res;
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
 * -> 코어가 BAD_PARAMETERS(tee_svc_cryp.c) -> libutee 가 TA panic -> CA 는 TARGET_DEAD.
 * panic 은 "새는 것보다 죽는다"는 정상 동작이다. (2026-11-17 실행으로 확인)
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
		return cmd_gen_key(ctx, ptypes);
	case TA_SECURE_MAC_CMD_MAC:
		return cmd_mac(ctx, ptypes, params);
	case TA_SECURE_MAC_CMD_VERIFY:
		return cmd_verify(ctx, ptypes, params);
	case TA_SECURE_MAC_CMD_EXPORT_KEY:
		return cmd_export_key(ctx, ptypes, params);
	case TA_SECURE_MAC_CMD_KEY_CREATE:
		return cmd_key_create(ptypes, params);
	case TA_SECURE_MAC_CMD_KEY_INFO:
		return cmd_key_info(ptypes, params);
	case TA_SECURE_MAC_CMD_KEY_DELETE:
		return cmd_key_delete(ptypes, params);
	case TA_SECURE_MAC_CMD_MAC_BY_ID:
		return cmd_mac_by_id(ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
