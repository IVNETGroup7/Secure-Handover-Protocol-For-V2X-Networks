#ifndef GATEWAY_H_
#define GATEWAY_H_

// Shared by App/ and Enclave/: what the ECALLs of Enclave.edl return

constexpr int GW_OK = 0;                    // done (out buffers filled)
constexpr int GW_IGNORED = 1;               // a validation failed: nothing to send
constexpr int GW_ERR_ARGS = -1;             // bad arguments (null pointer, empty field, unknown type)
constexpr int GW_ERR_BUFFER = -2;           // out buffer too small
constexpr int GW_ERR_CRYPTO = -3;           // crypto failure (bad key, OpenSSL error)
constexpr int GW_ERR_STATE = -4;            // gateway not initialized (ecall_init_gateway first)
constexpr int GW_ERR_NOT_IMPLEMENTED = -5;  // skeleton: not written yet

// ocall_print lines that start with these are validations (ok / failed), the rest is plain output
constexpr const char* kCheckOk = "check:ok:";
constexpr const char* kCheckFailed = "check:failed:";

#endif /* GATEWAY_H_ */
