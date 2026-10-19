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
    Bytes gatewayPublicKey;     // CY_g: public key (DER) of the target gateway's (RSU's) certificate
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

// M = { Auth_Granted, OTP_dt, K_g, CY_e, Auth_eg }     (the paper's (10): Auth_Granted(Auth_eg, OTP_dt, K_G, CY_e))
//   type (1) | OTP_dt (16) | len(K_g) (2) | K_g | len(CY_e) (2) | CY_e | len(Auth_eg) (2) | Auth_eg
//   on air only as E_K_dg(M) = aesGcmEncrypt(K_dg, pack(M)) (Crypto.h)
struct AuthGrantedPayload
{
    uint8_t type;
    Block otp;                  // OTP_dt: the one the RSU matched
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
std::vector<std::string> describe(const Active03Payload&);

// BootstrapMsg.payload <-> Bytes
void setPayload(BootstrapMsg&, const Bytes&);
Bytes getPayload(const BootstrapMsg&);

// Secrecy Forwarding (common/Handover.h): handover of an activated vehicle from RSU G_{i+1} to RSU G_{i+2}

// M = { Forwarding_Notice, Y_V, tau_{i+2}, Auth_d }   (G_{i+1} -> G_{i+2}, in clear inside the HTTPS backhaul)
//   type (1) | len(Y_V) (2) | Y_V | tau_{i+2} (16) | len(Auth_d) (2) | Auth_d
struct ForwardingNoticePayload
{
    uint8_t type;
    Bytes vehiclePublicKey;     // Y_V: the vehicle's ECDH public key of its bootstrap (DER, curve kEcdhCurve)
    Block tau;                  // tau_{i+2} = Poly1305(K_dg, t_i, m)
    Bytes authD;                // Auth_d: lets G_{i+2} marshal the vehicle's SmartData afterwards
};

Bytes pack(const ForwardingNoticePayload&);
ForwardingNoticePayload unpackForwardingNotice(const Bytes&);
std::vector<std::string> describe(const ForwardingNoticePayload&);

// M = { Handover_Command, G_{i+2}, Y_G_{i+2} }   (RSU -> vehicle, in clear: Y_G_{i+2} is public)
//   type (1) | len(G_{i+2}) (2) | G_{i+2} | len(Y_G_{i+2}) (2) | Y_G_{i+2}
struct HandoverCommandPayload
{
    uint8_t type;
    std::string targetRsu;      // G_{i+2}: where the Forwarding_Request goes (e.g. "rsu[1]")
    Bytes targetRsuPublicKey;   // Y_G_{i+2}: G_{i+2}'s ECDH public key for this handover (DER)
};

Bytes pack(const HandoverCommandPayload&);
HandoverCommandPayload unpackHandoverCommand(const Bytes&);
std::vector<std::string> describe(const HandoverCommandPayload&);

// M = { Forwarding_Request, auth_{i+2}, OTP }   (vehicle -> G_{i+2})
//   type (1) | auth_{i+2} (32) | OTP (16)
struct ForwardingRequestPayload
{
    uint8_t type;
    Sha256 auth;                // auth_{i+2} = SHA256(tau_{i+2})
    Block otp;                  // OTP = Poly1305(KT_i^32, auth_{i+2} xor t_c, m)
};

Bytes pack(const ForwardingRequestPayload&);
ForwardingRequestPayload unpackForwardingRequest(const Bytes&);
std::vector<std::string> describe(const ForwardingRequestPayload&);

// M = { Forwarding_Granted, Y_G_{i+3}, auth'_{i+2}, K_G_{i+2}, OTP }   (G_{i+2} -> vehicle)
//   type (1) | len(Y_G_{i+3}) (2) | Y_G_{i+3} | auth'_{i+2} (32) | len(K_G) (2) | K_G | OTP (16)
//   on air only as E_KT_i(M) = aesGcmEncrypt(KT_i, pack(M)): AES-128-GCM (Crypto.h)
struct ForwardingGrantedPayload
{
    uint8_t type;
    Bytes nextRsuPublicKey;     // Y_G_{i+3}: the next RSU's key, pre-loaded (empty: none yet)
    Sha256 authPrime;           // auth'_{i+2} = SHA256(auth_{i+2})
    Bytes kG;                   // K_G_{i+2}: G_{i+2}'s group key
    Block otp;                  // OTP: the one of the Forwarding_Request, echoed (freshness)
};

Bytes pack(const ForwardingGrantedPayload&);
ForwardingGrantedPayload unpackForwardingGranted(const Bytes&);
std::vector<std::string> describe(const ForwardingGrantedPayload&);

// M = { Secure_Data, AES(K_G, Data), Auth_d, OTP_dt }   (vehicle -> RSU: the OT packet of common/SmartData.h)
//   type (1) | OT packet (packDataMessage: len (4) | AES(K_G, Data) | len (4) | Auth_d | OTP_dt (16))
struct SecureDataPayload
{
    uint8_t type;
    Bytes cipherData;           // AES(K_G, Data): AES-128-GCM of packSmartData(Data)
    Bytes authD;                // Auth_d
    Block otp;                  // OTP_dt = Poly1305(K_dg, Auth_d xor t, AES(K_G, Data))
};

Bytes pack(const SecureDataPayload&);
SecureDataPayload unpackSecureData(const Bytes&);
std::vector<std::string> describe(const SecureDataPayload&);

#endif /* BOOTSTRAP_BOOTSTRAPPAYLOAD_H_ */
