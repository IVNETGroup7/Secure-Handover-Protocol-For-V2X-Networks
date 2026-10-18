#ifndef BOOTSTRAP_SMARTDATA_H_
#define BOOTSTRAP_SMARTDATA_H_

// Data path after the bootstrap (Fig. 5 of the paper, tee.pdf steps 4 and 6): what a vehicle sends to its RSU
//   Data       SmartData { location, timing, metadata, value, Auth_d }         (the paper's SmartData)
//   OT packet  Message(AES(K_G, Data), Auth_d, OTP_dt)
//              AES(K_G, Data): AES-128-GCM with the group key K_g (Crypto.h aesGcmEncrypt)
//              OTP_dt = Poly1305(K_dg, Auth_d xor t, m), with m = AES(K_G, Data): binds the data to the K_dg of
//              this vehicle (K_g is shared by every vehicle of the group); t as in the bootstrap (slots of
//              kOtpTimeStep s of the PTP-synchronized clock)
//   IT packet  HTTPS Header | AES(K_eg, JSON)   (Fig. 5): built in the enclave, for the cloud
//              K_eg = SHA256(ECDH(X_s, Y_e)): the key of the HTTPS session of Fig. 5, between the enclave and the
//              cloud; X_s / Y_s: the enclave's key pair of that session (Y_s goes in the header, kSessionKeyHeader),
//              Y_e: the public key of the cloud's certificate CY_e (Fig. 5 names the HTTPS Session { CY_e, K_eg };
//              here its other end is the cloud), pinned in the enclave. The cloud derives the same
//              K_eg = SHA256(ECDH(X_e, Y_s)); the body is AES-256-GCM(K_eg, JSON)
// No I/O: compiled into the vehicle, the App, the cloud and the enclave (the Secure Marshaling unpacks with it).
//
// encoding: integers big endian; variable fields with a 4-byte length (value goes up to 64 KB - 1)
//   SmartData   location (4) | timing (8) | metadata (4) | len | value | len | Auth_d
//   OT packet   len | AES(K_G, Data) | len | Auth_d | OTP_dt (16)

#include "Crypto.h"
#include <cstdint>

struct SmartData
{
    uint32_t location = 0;      // where it was measured (e.g. a road segment id)
    uint64_t timing = 0;        // when (ns since the epoch, PTP-synchronized clock)
    uint32_t metadata = 0;      // what it is (e.g. a sensor type / unit code)
    Bytes value;                // the measurement
    Bytes authD;                // Auth_d of the vehicle that measured it
};

struct DataMessage
{
    Bytes sealedData;           // AES(K_G, Data)
    Bytes authD;                // Auth_d
    Block otp{};                // OTP_dt
};

constexpr size_t kMaxSmartDataValue = 64 * 1024 - 1;   // the largest Data of the paper (TSTP's limit)

constexpr const char* kSmartDataPath = "/smartdata";        // the cloud's resource for the marshaled SmartData
constexpr const char* kSessionKeyHeader = "X-Session-Key";  // Y_s (DER, base64) of the session of K_eg
constexpr int kMessagesPerSession = 100;                    // then a new K_eg (the paper's evaluation, Section 6.1)

Bytes packSmartData(const SmartData&);
SmartData unpackSmartData(const Bytes&);        // throws std::runtime_error on a malformed buffer

Bytes packDataMessage(const DataMessage&);
DataMessage unpackDataMessage(const Bytes&);    // throws std::runtime_error on a malformed buffer

// t of OTP_dt: slot of kOtpTimeStep s of a time in ns (the same arithmetic as the bootstrap's OTP)
uint64_t dataOtpSlot(int64_t ns);
// OTP_dt = Poly1305(K_dg, Auth_d xor t, m)
Block dataOtp(const Bytes& kDg, const Bytes& authD, uint64_t slot, const Bytes& m);

// vehicle: the OT packet of "data", at time "nowNs" (its PTP-synchronized clock)
DataMessage sealSmartData(const SmartData& data, const Bytes& kG, const Bytes& kDg, int64_t nowNs);

// K_eg = SHA256(ECDH(own private key, peer public key)): the enclave with (X_s, Y_e), the cloud with (X_e, Y_s)
Bytes computeKEg(EVP_PKEY* privateKey, EVP_PKEY* peerPublicKey);

#endif /* BOOTSTRAP_SMARTDATA_H_ */
