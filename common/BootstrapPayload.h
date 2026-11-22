#ifndef COMMON_BOOTSTRAPPAYLOAD_H_
#define COMMON_BOOTSTRAPPAYLOAD_H_

// Wire payloads of the initial secure bootstrap messages (Vehicle <-> first RSU <-> ESA).

#include "SimTime.h"
#include "Traits.h"

// M = { Activation_Request, CY_g, t_0, t_f, UUID, SHA256(f_w) }
struct ActivationRequestPayload
{
    uint8_t type;
    Bytes gatewayPublicKey;     // CY_g: public key (DER) of the target gateway's (RSU's) certificate
    simtime_t t0;               // t_0
    simtime_t tf;               // t_f
    Uuid uuid;                  // UUID
    Sha256 firmwareHash;        // SHA256(f_w)
};

Bytes pack(const ActivationRequestPayload&);
ActivationRequestPayload unpackActivationRequest(const Bytes&);
std::vector<std::string> describe(const ActivationRequestPayload&);

// M = { Activation_Token, t_0, t_f, Auth_d, Auth_eg }
struct ActivationTokenPayload
{
    uint8_t type;
    simtime_t t0;      // t_0
    simtime_t tf;      // t_f
    Bytes authD;       // Auth_d = AES(Id_d, Id_d)
    Bytes authEg;      // Auth_eg = AES(Id_d, CY_e)
};

Bytes pack(const ActivationTokenPayload&);
ActivationTokenPayload unpackActivationToken(const Bytes&);
std::vector<std::string> describe(const ActivationTokenPayload&);

// M = { PTP } | { PTP_Sync, t_1 } | { PTP_Delay_Request } | { PTP_Delay_Response, t_4 }
struct PtpPayload
{
    uint8_t type;
    simtime_t timestamp;   // t_1 (PTP_Sync) or t_4 (PTP_Delay_Response)
};

Bytes pack(const PtpPayload&);
PtpPayload unpackPtp(const Bytes&);
std::vector<std::string> describe(const PtpPayload&);

// M = { ECDH_Request, Y_d } | { ECDH_Response, Y_g }
struct EcdhPayload
{
    uint8_t type;
    Bytes publicKey;            // Y_d (ECDH_Request) or Y_g (ECDH_Response)
};

Bytes pack(const EcdhPayload&);
EcdhPayload unpackEcdh(const Bytes&);
std::vector<std::string> describe(const EcdhPayload&);

// M = { Auth_Request, OTP_dt }
struct AuthRequestPayload
{
    uint8_t type;
    Block otp;                  // OTP_dt = Ascon(K_dg, Auth_d xor t, m) (BootstrapOtp.h)
};

Bytes pack(const AuthRequestPayload&);
std::vector<std::string> describe(const AuthRequestPayload&);

// M = { Auth_Granted, OTP_dt, K_g, CY_e, Auth_eg, nextRsus }
struct AuthGrantedPayload
{
    uint8_t type;
    Block otp;                              // OTP_dt: fresh Ascon MAC over { Auth_Granted, K_g, CY_e, Auth_eg, nextRsus }
    Bytes kG;                               // K_g: group key (AES-128-GCM, vehicle <-> vehicle)
    Bytes esaPublicKey;                     // CY_e: ESA public key (DER SubjectPublicKeyInfo)
    Bytes authEg;                           // Auth_eg = AES(Id_d, CY_e), from the Activation_Token
    std::vector<NeighborRsuKey> nextRsus;   // CA-verified neighbor RSUs (Y_{G_{i+1}}) for pre-computed handover
};

AuthGrantedPayload unpackAuthGranted(const Bytes&);
Bytes authGrantedOtpData(const AuthGrantedPayload&);
std::vector<std::string> describe(const AuthGrantedPayload&);

// M = { Active_01, Auth_d, OTP_dt, Auth_de } | { Active_02, Auth_d, OTP_dt, Auth_de }
struct Active01Payload
{
    uint8_t type;
    Bytes authD;                // Auth_d
    Block otp;                  // OTP_dt: fresh Ascon MAC over { Active_01, Auth_d, Auth_de } (binds K_de)
    Bytes authDe;               // Auth_de = AES(Id_d, SHA256(UUID + SHA256(f_w) + CY_e))
};

Bytes pack(const Active01Payload&);
Active01Payload unpackActive01(const Bytes&);
Bytes activeOtpData(const Bytes& authD, const Bytes& authDe);
std::vector<std::string> describe(const Active01Payload&);

// M = { Active_03, UUID, SHA256(f_w) }
struct Active03Payload
{
    uint8_t type;
    Uuid uuid;                  // UUID
    Sha256 firmwareHash;        // SHA256(f_w)
};

Bytes pack(const Active03Payload&);
Active03Payload unpackActive03(const Bytes&);
std::vector<std::string> describe(const Active03Payload&);

#endif /* COMMON_BOOTSTRAPPAYLOAD_H_ */
