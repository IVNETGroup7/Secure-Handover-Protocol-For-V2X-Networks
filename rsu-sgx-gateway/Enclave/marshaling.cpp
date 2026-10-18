// Secure Marshaling (Secure World): data path after the bootstrap, ECALL 4 of Enclave.edl (tee.pdf step 4).
//
// Skeleton: the entry point and the steps it will run.

#include "Enclave_t.h"
#include "gateway.h"

int ecall_secure_marshal_ot_to_it(const uint8_t* ot_pkt, size_t ot_pkt_len, uint64_t current_ptp_time,
    uint8_t* it_https_pkt, size_t it_buf_max, size_t* it_pkt_len)
{
    if (!it_pkt_len) {
        return GW_ERR_ARGS;
    }
    *it_pkt_len = 0;
    if (!ot_pkt || ot_pkt_len == 0 || !it_https_pkt || it_buf_max == 0) {
        return GW_ERR_ARGS;
    }
    (void) current_ptp_time;

    // 1. split Message(AES(K_G, Data), Auth_d, OTP_dt)
    // 2. Auth_d -> K_dg, K_G of that vehicle (kept by the control component)
    // 3. OTP_dt == Poly1305(K_dg, Auth_d xor t, m), t = current_ptp_time +- 1 slot; else GW_IGNORED
    // 4. Data = AES(K_G)^-1: SmartData (location, timing, metadata, value, Auth_d)
    // 5. JSON
    // 6. encrypted for the cloud (TLS session / K_eg) into it_https_pkt
    return GW_ERR_NOT_IMPLEMENTED;
}
