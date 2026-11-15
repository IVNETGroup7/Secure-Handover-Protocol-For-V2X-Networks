#ifndef BOOTSTRAP_SMARTDATA_H_
#define BOOTSTRAP_SMARTDATA_H_

#include "Crypto.h"
#include <cstdint>

struct SmartData
{
    uint32_t location = 0;
    uint64_t timing = 0;
    uint32_t metadata = 0;
    Bytes value;
    Bytes authD;
};

struct DataMessage
{
    Bytes sealedData;           // AES(K_G, Data)
    Bytes authD;                // Auth_d
    Block otp{};                // OTP_dt
};

constexpr size_t kMaxSmartDataValue = 64 * 1024 - 1; 

constexpr const char* kCloudAddress = "127.0.0.1";
constexpr const char* kSmartDataPath = "/smartdata";        // the cloud's resource for the marshaled SmartData
constexpr const char* kSessionKeyHeader = "X-Session-Key";  // Y_s (DER, base64) of the session of K_eg
constexpr int kMessagesPerSession = 100;                    // then a new K_eg

#ifndef __OPTEE_TA__
// Cloud P-256 key pair and self-signed certificate; pinned by each RSU's OP-TEE TA via initCloudSession
struct CloudIdentity
{
    std::shared_ptr<EVP_PKEY> key;      // X_e (and Y_e)
    Bytes certificateDer;               // CY_e: Y_e, self-signed X.509 DER
    std::string pem() const;            // certificate in PEM format
};
CloudIdentity newCloudIdentity(const std::string& commonName = "cloud");
#endif

Bytes packSmartData(const SmartData&);
SmartData unpackSmartData(const Bytes&);
Bytes packDataMessage(const DataMessage&);
DataMessage unpackDataMessage(const Bytes&);

// t of OTP_dt: slot of kOtpTimeStep s of a time in ns (the same arithmetic as the bootstrap's OTP)
uint64_t dataOtpSlot(int64_t ns);
// OTP_dt = Poly1305(K_dg, Auth_d xor t, m)
Block dataOtp(const Bytes& kDg, const Bytes& authD, uint64_t slot, const Bytes& m);

// vehicle: the OT packet of "data", at time "nowNs" (its PTP-synchronized clock)
DataMessage sealSmartData(const SmartData& data, const Bytes& kG, const Bytes& kDg, int64_t nowNs);

#ifndef __OPTEE_TA__
// K_eg = SHA256(ECDH(own private key, peer public key)): the OP-TEE TA with (X_s, Y_e), the cloud with (X_e, Y_s)
Bytes computeKEg(EVP_PKEY* privateKey, EVP_PKEY* peerPublicKey);
#endif

#endif /* BOOTSTRAP_SMARTDATA_H_ */
