#ifndef TA_USER_TA_HEADER_DEFINES_H_
#define TA_USER_TA_HEADER_DEFINES_H_

// OP-TEE Trusted Application properties for the RSU Gateway TA (Arm TrustZone)

#include <gateway_ta.h>

#define TA_UUID                 TA_GATEWAY_UUID


// Multi-instance TA (no TA_FLAG_SINGLE_INSTANCE): each RSU (rsu[0]..rsu[3]) gets its own isolated
// OP-TEE TA instance with dedicated MMU address space, heap, and lock — eliminating cross-RSU
// serialization so all 4 RSUs execute concurrently across the 4 RPi3 Cortex-A53 cores without
// blocking sibling RSUs during handover ECDH or Secure Storage sealing.
#define TA_FLAGS                (TA_FLAG_EXEC_DDR)

// 64 KB stack and 512 KB heap per isolated RSU TA instance (~2.25 MB total for 4 concurrent RSUs)
#define TA_STACK_SIZE           (64 * 1024)
#define TA_DATA_SIZE            (512 * 1024)

#define TA_VERSION              "1.0"
#define TA_DESCRIPTION          "V2X RSU Gateway Trusted Application (Bootstrap, Secrecy Forwarding, Secure Marshaling)"

#endif /* TA_USER_TA_HEADER_DEFINES_H_ */
