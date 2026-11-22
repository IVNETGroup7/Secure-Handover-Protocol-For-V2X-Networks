#ifndef COMMON_SMARTDATA_H_
#define COMMON_SMARTDATA_H_

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
// Cloud P-256 key pair and CA-signed X.509 certificate; verified against pinned Root CA inside each RSU's OP-TEE TA
struct CloudIdentity
{
    std::shared_ptr<EVP_PKEY> key;      // X_cloud (and Y_cloud)
    Bytes certificateDer;               // CA-signed X.509 DER certificate for the Cloud
    std::string pem() const;            // certificate in PEM format
};
CloudIdentity newCloudIdentity(const CertificateAuthority& ca, const std::string& commonName = kCloudAddress);
CloudIdentity newSelfSignedCloudIdentity(const std::string& commonName = kCloudAddress);
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

// M = { Secure_Data, AES(K_G, Data), Auth_d, OTP_dt }
struct SecureDataPayload
{
    uint8_t type;
    Bytes cipherData;           // AES(K_G, Data): AES-128-GCM of packSmartData(Data)
    Bytes authD;                // Auth_d
    Block otp{};                // OTP_dt = Poly1305(K_dg, Auth_d xor t, AES(K_G, Data))
};

Bytes pack(const SecureDataPayload&);

#ifndef __OPTEE_TA__
// K_eg = SHA256(ECDH(own private key, peer public key)): the OP-TEE TA with (X_s, Y_e), the cloud with (X_e, Y_s)
Bytes computeKEg(EVP_PKEY* privateKey, EVP_PKEY* peerPublicKey);
#endif

#endif /* COMMON_SMARTDATA_H_ */
