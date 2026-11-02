#ifndef GATEWAY_TA_H_
#define GATEWAY_TA_H_

// Shared interface between the Normal World (host/ Client Application via libteec)
// and the Secure World (ta/ Trusted Application running in Arm TrustZone under OP-TEE).

#include <stdint.h>

// UUID of the RSU Gateway Trusted Application: 9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718
#define TA_GATEWAY_UUID \
    { 0x9a4c5e10, 0x6b2f, 0x4d8e, \
        { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18 } }

// TA Command IDs (invoked via TEEC_InvokeCommand)
enum TaGatewayCommand
{
    // Configure the OP-TEE Secure Storage object ID for this RSU session (e.g., "gateway.sealed.rsu0")
    // params[0] = MEMREF_TEMP_INPUT: storage object ID string (or path in host simulation mode)
    // params[1] = VALUE_INPUT:       a = purge existing object if non-zero
    TA_GATEWAY_CMD_SET_STORAGE_ID           = 0,

    // Initialize the RSU gateway inside the Secure World
    // params[0] = MEMREF_TEMP_INPUT: packed { gw_cert, esa_pub_key, group_key }
    // params[1] = VALUE_OUTPUT:      a = gateway status (GW_OK, ...)
    // params[2] = MEMREF_TEMP_OUTPUT: Secure World trace log lines
    TA_GATEWAY_CMD_INIT_GATEWAY             = 1,

    // Pin the Cloud X.509 certificate (CY_e) and derive ephemeral K_eg = SHA256(ECDH(X_s, Y_e))
    // params[0] = MEMREF_TEMP_INPUT: packed { cloud_cert_pem, host, gateway }
    // params[1] = VALUE_OUTPUT:      a = gateway status (GW_OK, ...)
    // params[2] = MEMREF_TEMP_OUTPUT: Secure World trace log lines
    TA_GATEWAY_CMD_INIT_CLOUD_SESSION       = 2,

    // Register an ESA-authorized Activation_Token { t_0, t_f, Auth_d, Auth_eg }
    // params[0] = MEMREF_TEMP_INPUT: packed { session, t0, tf, auth_d, auth_eg }
    // params[1] = VALUE_OUTPUT:      a = gateway status (GW_OK, ...)
    // params[2] = MEMREF_TEMP_OUTPUT: Secure World trace log lines
    TA_GATEWAY_CMD_ADD_ACTIVATION_TOKEN     = 3,

    // Handle a bootstrap or handover message in Secure World (ECDH_Request, Auth_Request, Active_01, Forwarding_Request)
    // params[0] = MEMREF_TEMP_INPUT:  packed { msg_type, current_ptp_time, session, in_pkt }
    // params[1] = MEMREF_TEMP_OUTPUT: out_pkt
    // params[2] = VALUE_OUTPUT:       a = gateway status (GW_OK, ...), b = out_type
    // params[3] = MEMREF_TEMP_OUTPUT: Secure World trace log lines
    TA_GATEWAY_CMD_HANDLE_BOOTSTRAP         = 4,

    // Secure Marshaling (OT -> IT): verify vehicle OTP_dt, decrypt SmartData with K_G, re-encrypt JSON with K_eg
    // params[0] = MEMREF_TEMP_INPUT:  packed { current_ptp_time, ot_pkt }
    // params[1] = MEMREF_TEMP_OUTPUT: it_https_pkt (HTTP POST header | AES-256-GCM(K_eg, JSON))
    // params[2] = VALUE_OUTPUT:       a = gateway status (GW_OK, ...)
    // params[3] = MEMREF_TEMP_OUTPUT: Secure World trace log lines
    TA_GATEWAY_CMD_SECURE_MARSHAL_OT_TO_IT  = 5,

    // Secrecy Forwarding (source RSU G_{i+1}): compute tau_{i+2} = Poly1305(K_dg, t_i, m) and output { Y_V, tau, Auth_d }
    // params[0] = MEMREF_TEMP_INPUT:  packed { t_i, session }
    // params[1] = MEMREF_TEMP_OUTPUT: packed { tau (16B), yv, auth_d }
    // params[2] = VALUE_OUTPUT:       a = gateway status (GW_OK, ...)
    // params[3] = MEMREF_TEMP_OUTPUT: Secure World trace log lines
    TA_GATEWAY_CMD_TRIGGER_HANDOVER         = 6,

    // Secrecy Forwarding (target RSU G_{i+2}): pre-compute K_dh_i, KT_i, auth_{i+2} and output fresh Y_{G_{i+2}}
    // params[0] = MEMREF_TEMP_INPUT:  packed { session, tau (16B), yv, auth_d }
    // params[1] = MEMREF_TEMP_OUTPUT: out_yg (DER SubjectPublicKeyInfo)
    // params[2] = VALUE_OUTPUT:       a = gateway status (GW_OK, ...)
    // params[3] = MEMREF_TEMP_OUTPUT: Secure World trace log lines
    TA_GATEWAY_CMD_RECEIVE_FORWARDING_NOTICE = 7
};

// Gateway status codes returned in VALUE_OUTPUT.a
constexpr int GW_OK         = 0;    // Success (output buffers populated)
constexpr int GW_IGNORED    = 1;    // Cryptographic or window validation failed: packet ignored
constexpr int GW_ERR_ARGS   = -1;   // Bad arguments (null pointer, empty field, unknown message type)
constexpr int GW_ERR_BUFFER = -2;   // Output buffer too small
constexpr int GW_ERR_CRYPTO = -3;   // Cryptographic failure (invalid key/certificate or TEE crypto error)
constexpr int GW_ERR_STATE  = -4;   // Gateway or Cloud session not initialized

// Trace prefixes emitted by the TA in the log buffer:
// Lines starting with these prefixes are rendered as trace::check(ok/failed); others as trace::detail
constexpr const char* kCheckOk     = "check:ok:";
constexpr const char* kCheckFailed = "check:failed:";

#endif /* GATEWAY_TA_H_ */

