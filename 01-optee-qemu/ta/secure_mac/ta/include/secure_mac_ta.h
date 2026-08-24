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

#endif /* TA_SECURE_MAC_H */
