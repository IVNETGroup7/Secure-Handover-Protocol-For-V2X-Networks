#ifndef GATEWAY_CODEC_H_
#define GATEWAY_CODEC_H_

// Byte layout of the bootstrap payloads the enclave reads and writes: the same layouts as
// common/BootstrapPayload.h (that file needs BootstrapService and the system clock, which the enclave has not);
// SecureData wraps the OT packet of common/SmartData.h (compiled into the enclave too).
// Integers in big endian; unpack throws std::runtime_error on a truncated payload.

#include "Crypto.h"

namespace wire
{

// building blocks of every layout: integers (big endian) and fields with a 2-byte length
void putUint(Bytes& out, uint64_t value, int size);
void putField(Bytes& out, const Bytes& field);

class Reader
{
    public:
        explicit Reader(const Bytes& in) : mIn(in) {}
        uint64_t uint(int size);
        Block block();
        Bytes field();
        bool done() const { return mPos == mIn.size(); }
        template <size_t N>
        std::array<uint8_t, N> array()
        {
            need(N);
            std::array<uint8_t, N> out;
            std::copy_n(mIn.begin() + static_cast<long>(mPos), N, out.begin());
            mPos += N;
            return out;
        }

    private:
        void need(size_t size) const;

        const Bytes& mIn;
        size_t mPos = 0;
};

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

// { Auth_Granted, OTP_dt, K_g, CY_e, Auth_eg }:
//   type (1) | OTP_dt (16) | len(K_g) (2) | K_g | len(CY_e) (2) | CY_e | len(Auth_eg) (2) | Auth_eg
struct AuthGranted
{
    uint8_t type;
    Block otp;
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

// { Forwarding_Request, auth_{i+2}, OTP }:  type (1) | auth_{i+2} (32) | OTP (16)
struct ForwardingRequest
{
    uint8_t type;
    Sha256 auth;
    Block otp;
};

// { Forwarding_Granted, Y_G_{i+3}, auth'_{i+2}, K_G_{i+2}, OTP }:
//   type (1) | len(Y_G_{i+3}) (2) | Y_G_{i+3} | auth'_{i+2} (32) | len(K_G) (2) | K_G | OTP (16)
struct ForwardingGranted
{
    uint8_t type;
    Bytes nextRsuPublicKey;
    Sha256 authPrime;
    Bytes kG;
    Block otp;
};

// { Secure_Data, AES(K_G, Data), Auth_d, OTP_dt }:  type (1) | the OT packet of common/SmartData.h
//   (packDataMessage: len (4) | AES(K_G, Data) | len (4) | Auth_d | OTP_dt (16))
struct SecureData
{
    uint8_t type;
    Bytes cipherData;
    Bytes authD;
    Block otp;
};

Bytes pack(const Ecdh&);
Bytes pack(const AuthGranted&);
Bytes pack(const Active&);
Bytes pack(const ForwardingRequest&);
Bytes pack(const ForwardingGranted&);
Bytes pack(const SecureData&);

Ecdh unpackEcdh(const Bytes&);
AuthRequest unpackAuthRequest(const Bytes&);
Active unpackActive(const Bytes&);
ForwardingRequest unpackForwardingRequest(const Bytes&);
ForwardingGranted unpackForwardingGranted(const Bytes&);
SecureData unpackSecureData(const Bytes&);

} // namespace wire

#endif /* GATEWAY_CODEC_H_ */
