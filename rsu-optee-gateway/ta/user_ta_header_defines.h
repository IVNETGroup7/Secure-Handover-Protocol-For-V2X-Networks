#ifndef TA_USER_TA_HEADER_DEFINES_H_
#define TA_USER_TA_HEADER_DEFINES_H_

// OP-TEE Trusted Application properties for the RSU Gateway TA (Arm TrustZone)

#include <gateway_ta.h>

#define TA_UUID                 TA_GATEWAY_UUID

// Single-instance TA with multi-session support: each RSU opens its own TEEC_Session
// with isolated sessionContext state and its own Secure Storage object ID.
#define TA_FLAGS                (TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)

// 128 KB stack and 1 MB heap for 64 KB SmartData marshaling and active vehicle sessions
#define TA_STACK_SIZE           (128 * 1024)
#define TA_DATA_SIZE            (1024 * 1024)

#define TA_VERSION              "1.0"
#define TA_DESCRIPTION          "V2X RSU Gateway Trusted Application (Bootstrap, Secrecy Forwarding, Secure Marshaling)"

#endif /* TA_USER_TA_HEADER_DEFINES_H_ */

