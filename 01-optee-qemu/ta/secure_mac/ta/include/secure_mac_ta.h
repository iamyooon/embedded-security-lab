/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef TA_SECURE_MAC_H
#define TA_SECURE_MAC_H

/* uuidgen: 82a856b1-5b26-4746-8fec-318d1360ffad */
#define TA_SECURE_MAC_UUID \
	{ 0x82a856b1, 0x5b26, 0x4746, \
		{ 0x8f, 0xec, 0x31, 0x8d, 0x13, 0x60, 0xff, 0xad } }

/* HMAC-SHA256: 256-bit key, 32-byte tag */
#define SECURE_MAC_KEY_BITS	256
#define SECURE_MAC_TAG_SIZE	32

/*
 * TA_SECURE_MAC_CMD_GEN_KEY
 *   params: none
 *   secure world generates the MAC key; it never crosses the world boundary.
 *
 * TA_SECURE_MAC_CMD_MAC
 *   params[0] MEMREF_INPUT   : message (e.g. CAN id + freshness + payload)
 *   params[1] MEMREF_OUTPUT  : MAC tag (SECURE_MAC_TAG_SIZE bytes)
 *
 * TA_SECURE_MAC_CMD_VERIFY
 *   params[0] MEMREF_INPUT   : message
 *   params[1] MEMREF_INPUT   : MAC tag to check
 *   params[2] VALUE_OUTPUT   : a = 1 valid, 0 invalid
 *
 * TA_SECURE_MAC_CMD_EXPORT_KEY  (attack demo: must NOT work)
 *   params[0] MEMREF_OUTPUT  : where a normal-world attacker wants the key
 */
#define TA_SECURE_MAC_CMD_GEN_KEY	0
#define TA_SECURE_MAC_CMD_MAC		1
#define TA_SECURE_MAC_CMD_VERIFY	2
#define TA_SECURE_MAC_CMD_EXPORT_KEY	3

/*
 * ---- 키 생명주기 (GP Persistent Object, TEE_STORAGE_PRIVATE = QEMU 에선 REE FS /var/lib/tee) ----
 * 키 ID = CA 가 정하는 uint32. TA 안에서 objectID(4바이트)로 쓴다. 키 값은 어떤 명령으로도 안 나간다.
 *
 * TA_SECURE_MAC_CMD_KEY_CREATE
 *   params[0] VALUE_INPUT    : a = key id
 *   같은 id 가 이미 있으면 TEE_ERROR_ACCESS_CONFLICT (덮어쓰기 안 함)
 *
 * TA_SECURE_MAC_CMD_KEY_INFO   (메타데이터만)
 *   params[0] VALUE_INPUT    : a = key id
 *   params[1] VALUE_OUTPUT   : a = objectType, b = keySize(bit)
 *   params[2] VALUE_OUTPUT   : a = objectUsage
 *   없는 id -> TEE_ERROR_ITEM_NOT_FOUND
 *
 * TA_SECURE_MAC_CMD_KEY_DELETE
 *   params[0] VALUE_INPUT    : a = key id
 *
 * TA_SECURE_MAC_CMD_MAC_BY_ID
 *   params[0] VALUE_INPUT    : a = key id
 *   params[1] MEMREF_INPUT   : message
 *   params[2] MEMREF_OUTPUT  : MAC tag (SECURE_MAC_TAG_SIZE bytes)
 */
#define TA_SECURE_MAC_CMD_KEY_CREATE	4
#define TA_SECURE_MAC_CMD_KEY_INFO	5
#define TA_SECURE_MAC_CMD_KEY_DELETE	6
#define TA_SECURE_MAC_CMD_MAC_BY_ID	7

/* KEY_INFO 기대값 (GP tee_api_defines.h 값, CA 가 검사용으로 씀) */
#define SECURE_MAC_GP_TYPE_HMAC_SHA256	0xA0000004
#define SECURE_MAC_GP_USAGE_EXTRACTABLE	0x00000001
#define SECURE_MAC_GP_USAGE_MAC		0x00000008

#endif /* TA_SECURE_MAC_H */
