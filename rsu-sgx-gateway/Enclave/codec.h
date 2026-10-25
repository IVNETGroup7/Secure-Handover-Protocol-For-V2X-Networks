#ifndef GATEWAY_CODEC_H_
#define GATEWAY_CODEC_H_

// Byte layout of the bootstrap payloads the enclave reads and writes: the same layouts as
// common/BootstrapPayload.h (that file needs BootstrapService and the system clock, which the enclave has not).
// Integers in big endian; unpack throws std::runtime_error on a truncated payload.

#include "ByteWire.h"
#include "Crypto.h"

namespace wire
{

// { ECDH_Request, Y_d } | { ECDH_Response, Y_g }:  type (1) | len(Y) (2) | Y
struct Ecdh
{
    uint8_t type;
    Bytes publicKey;
};

// { Auth_Request, OTP_dt }:  type (1) | OTP_dt (16)
struct AuthRequest
{
    uint8_t type;
    Block otp;
};

// { Auth_Granted, OTP_dt, K_dg, K_g, CY_e, Auth_eg }:
//   type (1) | OTP_dt (16) | len(K_dg) (2) | K_dg | len(K_g) (2) | K_g | len(CY_e) (2) | CY_e | len(Auth_eg) (2) | Auth_eg
struct AuthGranted
{
    uint8_t type;
    Block otp;
    Bytes kDg;
    Bytes kG;
    Bytes esaPublicKey;
    Bytes authEg;
};

// { Active_01 | Active_02, Auth_d, OTP_dt, Auth_de }:
//   type (1) | len(Auth_d) (2) | Auth_d | OTP_dt (16) | len(Auth_de) (2) | Auth_de
struct Active
{
    uint8_t type;
    Bytes authD;
    Block otp;
    Bytes authDe;
};

// { Forwarding_Request, auth, OTP }: type (1) | auth (32) | OTP (16)
struct ForwardingRequest
{
    uint8_t type;
    Sha256 auth;
    Block otp;
};

// { Forwarding_Granted, Y_G_next, auth', K_G, OTP' }:
//   type (1) | len(Y_G_next) (2) | Y_G_next | auth' (32) | len(K_G) (2) | K_G | OTP' (16)
struct ForwardingGranted
{
    uint8_t type;
    Bytes nextRsuPublicKey;
    Sha256 authPrime;
    Bytes kG;
    Block otp;
};

Bytes pack(const Ecdh&);
Bytes pack(const AuthGranted&);
Bytes pack(const Active&);
Bytes pack(const ForwardingGranted&);

Ecdh unpackEcdh(const Bytes&);
AuthRequest unpackAuthRequest(const Bytes&);
Active unpackActive(const Bytes&);
ForwardingRequest unpackForwardingRequest(const Bytes&);

} // namespace wire

#endif /* GATEWAY_CODEC_H_ */
