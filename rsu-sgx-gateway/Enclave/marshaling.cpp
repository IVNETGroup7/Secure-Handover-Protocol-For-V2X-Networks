// Secure Marshaling (Secure World): data path after the bootstrap, ECALL 4 of Enclave.edl (tee.pdf step 4).

#include "Enclave_t.h"
#include "gateway.h"
#include "gateway_internal.h"
#include "SmartData.h"
#include "Traits.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <openssl/crypto.h>

static std::string bytesToHex(const uint8_t* data, size_t size)
{
    static const char hexChars[] = "0123456789abcdef";
    std::string s;
    s.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
        s.push_back(hexChars[(data[i] >> 4) & 0x0f]);
        s.push_back(hexChars[data[i] & 0x0f]);
    }
    return s;
}

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
    if (!gatewayIsReady()) {
        return GW_ERR_STATE;
    }

    try {
        // 1. split Message(AES(K_G, Data), Auth_d, OTP_dt): unpackDataMessage (common/SmartData.h)
        const Bytes otBytes(ot_pkt, ot_pkt + ot_pkt_len);
        const DataMessage message = unpackDataMessage(otBytes);

        // 2. Auth_d -> K_dg, K_G of that vehicle (queried from control component via gateway_internal.h)
        Bytes kDg, kG;
        if (!gatewayFindVehicleKeys(message.authD, kDg, kG)) {
            return GW_IGNORED;
        }

        // 3. OTP_dt == dataOtp(K_dg, Auth_d, t, AES(K_G, Data)), t = dataOtpSlot(current_ptp_time) +- kOtpWindow
        const uint64_t tNow = dataOtpSlot(static_cast<int64_t>(current_ptp_time));
        const uint64_t tMin = tNow >= kOtpWindow ? tNow - kOtpWindow : 0;
        bool otpOk = false;
        for (uint64_t t = tMin; t <= tNow + kOtpWindow; ++t) {
            const Block candidate = dataOtp(kDg, message.authD, t, message.sealedData);
            if (CRYPTO_memcmp(candidate.data(), message.otp.data(), candidate.size()) == 0) {
                otpOk = true;
                break;
            }
        }
        if (!otpOk) {
            return GW_IGNORED;
        }

        // 4. Data = aesGcmDecrypt(K_G, AES(K_G, Data)) -> unpackSmartData
        const auto plain = aesGcmDecrypt(kG, message.sealedData);
        if (!plain) {
            return GW_IGNORED;
        }
        const SmartData data = unpackSmartData(*plain);

        // 5. Marshal to JSON (as specified in tee.pdf step 4.5)
        const std::string authHex = bytesToHex(data.authD.data(), data.authD.size());
        const std::string valHex = bytesToHex(data.value.data(), data.value.size());

        const std::string json = "{\"Location\":" + std::to_string(data.location)
            + ",\"Timing\":" + std::to_string(static_cast<unsigned long long>(data.timing))
            + ",\"Metadata\":" + std::to_string(data.metadata)
            + ",\"ValueBytes\":" + std::to_string(data.value.size())
            + ",\"ValueHex\":\"" + valHex + "\""
            + ",\"Trust\":\"" + authHex + "\"}";

        if (json.size() >= it_buf_max) {
            return GW_ERR_BUFFER;
        }

        std::memcpy(it_https_pkt, json.data(), json.size());
        *it_pkt_len = json.size();
        return GW_OK;
    } catch (const std::exception&) {
        return GW_ERR_CRYPTO;
    }
}
