#ifndef BOOTSTRAP_BOOTSTRAPPAYLOAD_H_
#define BOOTSTRAP_BOOTSTRAPPAYLOAD_H_

// Byte layout of the bootstrap messages (BootstrapMsg.payload)

#include "SimTime.h"
#include "Traits.h"

class BootstrapMsg;

// M = { Activation_Request, CY_g, t_0, t_f, UUID, SHA256(f_w) }
//   type (1) | len(CY_g) (2) | CY_g | t_0 (8, ns) | t_f (8, ns) | UUID (16) | SHA256(f_w) (32)
//   integers in big endian
struct ActivationRequestPayload
{
    uint8_t type;
    Bytes gatewayPublicKey;     // CY_g
    simtime_t t0;      // t_0
    simtime_t tf;      // t_f
    Uuid uuid;                  // UUID
    Sha256 firmwareHash;        // SHA256(f_w)
};

Bytes pack(const ActivationRequestPayload&);
ActivationRequestPayload unpackActivationRequest(const Bytes&);
std::vector<std::string> describe(const ActivationRequestPayload&); // one line per field, for printing

// M = { Activation_Token, t_0, t_f, Auth_d, Auth_eg }
//   type (1) | t_0 (8, ns) | t_f (8, ns) | len(Auth_d) (2) | Auth_d | len(Auth_eg) (2) | Auth_eg
struct ActivationTokenPayload
{
    uint8_t type;
    simtime_t t0;      // t_0
    simtime_t tf;      // t_f
    Bytes authD;                // Auth_d = AES(Id_d, Id_d)
    Bytes authEg;               // Auth_eg = AES(Id_d, CY_e)
};

Bytes pack(const ActivationTokenPayload&);
ActivationTokenPayload unpackActivationToken(const Bytes&);
std::vector<std::string> describe(const ActivationTokenPayload&);

// M = { PTP_Sync, t_1 } | { PTP_Delay_Request } | { PTP_Delay_Response, t_4 }
//   type (1) [| timestamp (8, ns)]  -- PTP_Delay_Request carries no timestamp
struct PtpPayload
{
    uint8_t type;
    simtime_t timestamp;   // t_1 (PTP_Sync) or t_4 (PTP_Delay_Response)
};

Bytes pack(const PtpPayload&);
PtpPayload unpackPtp(const Bytes&);
std::vector<std::string> describe(const PtpPayload&);

// M = { ECDH_Request, Y_d } | { ECDH_Response, Y_g }
//   type (1) | len(Y) (2) | Y   -- Y: ECDH public key (DER SubjectPublicKeyInfo, curve kEcdhCurve)
struct EcdhPayload
{
    uint8_t type;
    Bytes publicKey;            // Y_d (ECDH_Request) or Y_g (ECDH_Response)
};

Bytes pack(const EcdhPayload&);
EcdhPayload unpackEcdh(const Bytes&);
std::vector<std::string> describe(const EcdhPayload&);

// M = { Auth_Request, OTP_dt }
//   type (1) | OTP_dt (16)
struct AuthRequestPayload
{
    uint8_t type;
    Block otp;                  // OTP_dt = Poly1305(K_dg, Auth_d xor t, m)
};

Bytes pack(const AuthRequestPayload&);
AuthRequestPayload unpackAuthRequest(const Bytes&);
std::vector<std::string> describe(const AuthRequestPayload&);

// M = { Auth_Granted, OTP_dt, K_dg, K_g, CY_e, Auth_eg }
//   type (1) | OTP_dt (16) | len(K_dg) (2) | K_dg | len(K_g) (2) | K_g | len(CY_e) (2) | CY_e
//   | len(Auth_eg) (2) | Auth_eg
//   on air only as E_K_dg(M) = aesGcmEncrypt(K_dg, pack(M)) (Crypto.h)
struct AuthGrantedPayload
{
    uint8_t type;
    Block otp;                  // OTP_dt: the one the RSU matched
    Bytes kDg;                  // K_dg
    Bytes kG;                   // K_g: group key (AES-128-GCM, vehicle <-> vehicle)
    Bytes esaPublicKey;         // CY_e: ESA public key (DER SubjectPublicKeyInfo)
    Bytes authEg;               // Auth_eg = AES(Id_d, CY_e), from the Activation_Token: the vehicle checks CY_e with it
};

Bytes pack(const AuthGrantedPayload&);
AuthGrantedPayload unpackAuthGranted(const Bytes&);
std::vector<std::string> describe(const AuthGrantedPayload&);

// M = { Active_01, Auth_d, OTP_dt, Auth_de } | { Active_02, Auth_d, OTP_dt, Auth_de }
//   type (1) | len(Auth_d) (2) | Auth_d | OTP_dt (16) | len(Auth_de) (2) | Auth_de
//   Active_01 (vehicle -> RSU): on air only as E_K_dg(M) = aesGcmEncrypt(K_dg, pack(M)) (Crypto.h)
//   Active_02 (RSU -> ESA): the same M, in clear inside the HTTPS session
struct Active01Payload
{
    uint8_t type;
    Bytes authD;                // Auth_d
    Block otp;                  // OTP_dt: the one sent in Auth_Request
    Bytes authDe;               // Auth_de = AES(Id_d, SHA256(UUID + SHA256(f_w) + CY_e))
};

Bytes pack(const Active01Payload&);
Active01Payload unpackActive01(const Bytes&);
std::vector<std::string> describe(const Active01Payload&);

// M = { Active_03, UUID, SHA256(f_w) }   (ESA -> user, in clear inside the user's HTTPS connection)
//   type (1) | UUID (16) | SHA256(f_w) (32)
struct Active03Payload
{
    uint8_t type;
    Uuid uuid;                  // UUID
    Sha256 firmwareHash;        // SHA256(f_w)
};

Bytes pack(const Active03Payload&);
Active03Payload unpackActive03(const Bytes&);
std::vector<std::string> describe(const Active03Payload&);

// BootstrapMsg.payload <-> Bytes
void setPayload(BootstrapMsg&, const Bytes&);
Bytes getPayload(const BootstrapMsg&);

// M = { Forwarding_Notice, Y_V, tau } (RSU -> RSU over HTTPS)
struct ForwardingNoticePayload
{
    uint8_t type;
    Bytes vehiclePublicKey; // Y_V
    Block tau;              // tau_{i+2}
};

Bytes pack(const ForwardingNoticePayload&);
ForwardingNoticePayload unpackForwardingNotice(const Bytes&);
std::vector<std::string> describe(const ForwardingNoticePayload&);

// M = { Handover_Command, Y_G } (RSU -> Vehicle)
struct HandoverCommandPayload
{
    uint8_t type;
    Bytes targetRsuPublicKey; // Y_G_{i+2}
};

Bytes pack(const HandoverCommandPayload&);
HandoverCommandPayload unpackHandoverCommand(const Bytes&);
std::vector<std::string> describe(const HandoverCommandPayload&);

// M = { Forwarding_Request, auth, OTP } (Vehicle -> Target RSU)
struct ForwardingRequestPayload
{
    uint8_t type;
    Sha256 auth;            // auth_{i+2} = SHA256(tau)
    Block otp;              // OTP = Poly1305(KT_i, auth ^ t_c, m)
};

Bytes pack(const ForwardingRequestPayload&);
ForwardingRequestPayload unpackForwardingRequest(const Bytes&);
std::vector<std::string> describe(const ForwardingRequestPayload&);

// M = { Forwarding_Granted, Y_G_next, auth', K_G, OTP' } (Target RSU -> Vehicle)
// Encrypted on air as E_KT_i(M)
struct ForwardingGrantedPayload
{
    uint8_t type;
    Bytes nextRsuPublicKey; // Y_{G_{i+3}} (optional pre-load)
    Sha256 authPrime;       // auth'_{i+2}
    Bytes kG;               // K_{G_{i+2}}
    Block otp;              // Fresh OTP'
};

Bytes pack(const ForwardingGrantedPayload&);
ForwardingGrantedPayload unpackForwardingGranted(const Bytes&);
std::vector<std::string> describe(const ForwardingGrantedPayload&);

#endif /* BOOTSTRAP_BOOTSTRAPPAYLOAD_H_ */
