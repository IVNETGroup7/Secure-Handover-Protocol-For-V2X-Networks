#ifndef TA_USER_TA_HEADER_DEFINES_H_
#define TA_USER_TA_HEADER_DEFINES_H_

// OP-TEE Trusted Application properties for the RSU Gateway TA (Arm TrustZone)

#include <gateway_ta.h>

#define TA_UUID                 TA_GATEWAY_UUID


// their own isolated TEEC_Session (GatewayTaSession context) and Secure Storage object ID.
#define TA_FLAGS                (TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)

// 128 KB stack and 2 MB heap for 4 concurrent RSU TA sessions and 64 KB SmartData marshaling
#define TA_STACK_SIZE           (128 * 1024)
#define TA_DATA_SIZE            (2 * 1024 * 1024)

#define TA_VER// Single-instance TA with multi-session support: all 4 Manhattan Grid RSUs (rsu[0]..rsu[3]) openSION              "1.0"
#define TA_DESCRIPTION          "V2X RSU Gateway Trusted Application (Bootstrap, Secrecy Forwarding, Secure Marshaling)"

#endif /* TA_USER_TA_HEADER_DEFINES_H_ */
