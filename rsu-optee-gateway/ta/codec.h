#ifndef TA_CODEC_H_
#define TA_CODEC_H_

// Wire format of protocol and Secure_Data payloads inside the Trusted Application.

#include "Crypto.h"

namespace wire
{

// Big-endian integer of "size" bytes (1, 2, 4, or 8)
void putUint(Bytes& out, uint64_t value, int size);
// 2-byte big-endian length prefix followed by the field bytes
void putField(Bytes& out, const Bytes& field);

class Reader
{
    public:
        explicit Reader(const Bytes& in) : mIn(in) {}
        uint64_t uint(int size);
        Block block();
        Bytes field();

        template<size_t N>
        std::array<uint8_t, N> array()
        {
            need(N);
            std::array<uint8_t, N> out;
            for (size_t i = 0; i < N; ++i) {
                out[i] = mIn[mPos++];
            }
            return out;
        }

    private:
        void need(size_t size) const;
        const Bytes& mIn;
        size_t mPos = 0;
};

struct ActivationToken
{
    uint8_t type;
    uint64_t t0 = 0;
    uint64_t tf = 0;
    Bytes authD;
    Bytes authEg;
};

struct Ecdh
{
    uint8_t type;
    Bytes publicKey;
};

struct AuthRequest
{
    uint8_t type;
    Block otp;
};

struct AuthGranted
{
    uint8_t type;
    Block otp;
    Bytes kG;
    Bytes esaPublicKey;
    Bytes authEg;
};

struct Active
{
    uint8_t type;
    Bytes authD;
    Block otp;
    Bytes authDe;
};

struct ForwardingRequest
{
    uint8_t type;
    Sha256 auth{};
    Block otp{};
};

struct ForwardingGranted
{
    uint8_t type;
    Bytes nextRsuPublicKey;
    Sha256 authPrime{};
    Bytes kG;
    Block otp{};
};

struct SecureData
{
    uint8_t type;
    Bytes cipherData;
    Bytes authD;
    Block otp{};
};

Bytes pack(const Ecdh&);
Bytes pack(const AuthGranted&);
Bytes pack(const Active&);
Bytes pack(const ForwardingGranted&);
Bytes authGrantedOtpData(const AuthGranted&);
Bytes activeOtpData(const Bytes& authD, const Bytes& authDe);
ActivationToken unpackActivationToken(const Bytes&);
Ecdh unpackEcdh(const Bytes&);
AuthRequest unpackAuthRequest(const Bytes&);
Active unpackActive(const Bytes&);
ForwardingRequest unpackForwardingRequest(const Bytes&);
SecureData unpackSecureData(const Bytes&);

} // namespace wire

#endif /* TA_CODEC_H_ */

