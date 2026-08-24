/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The name of this file must not be modified
 */
#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <secure_mac_ta.h>

#define TA_UUID				TA_SECURE_MAC_UUID

/* single instance, one session context per client */
#define TA_FLAGS			(TA_FLAG_SINGLE_INSTANCE | \
					 TA_FLAG_MULTI_SESSION)

#define TA_STACK_SIZE			(4 * 1024)
#define TA_DATA_SIZE			(32 * 1024)

#define TA_VERSION			"0.1"
#define TA_DESCRIPTION			"Secure MAC service (SecOC-style HMAC, key stays in secure world)"

#endif /* USER_TA_HEADER_DEFINES_H */
