#include "crypto_tee.h"
#include "Traits.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>

#ifdef __OPTEE_TA__
extern "C" {
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
}
#else
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <cstdio>
#endif

namespace ta_crypto
{

namespace
{

constexpr size_t kGcmNonceSize = 12;
constexpr size_t kGcmTagSize   = 16;

// Fixed 26-byte ASN.1 DER SubjectPublicKeyInfo prefix for an uncompressed P-256 point (0x04 || X(32) || Y(32)):
// SEQUENCE (89 B) {
//   SEQUENCE (19 B) { OID ecPublicKey (1.2.840.10045.2.1), OID prime256v1 (1.2.840.10045.3.1.7) }
//   BIT STRING (66 B) { 0x00 unused bits, 0x04 (uncompressed), X (32 B), Y (32 B) }
// }
constexpr uint8_t kP256SpkiPrefix[27] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04
};
constexpr size_t kP256SpkiLen = 91; // 27 + 32 (X) + 32 (Y)

#ifdef __OPTEE_TA__

// Portable 32-bit little-endian load/store for RFC 8439 Poly1305
uint32_t load32Le(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0])
        | (static_cast<uint32_t>(p[1]) << 8)
        | (static_cast<uint32_t>(p[2]) << 16)
        | (static_cast<uint32_t>(p[3]) << 24);
}

void store32Le(uint8_t* p, uint32_t v)
{
    p[0] = static_cast<uint8_t>(v & 0xff);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xff);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xff);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xff);
}

// RFC 8439 Poly1305 one-time authenticator using 5 x 26-bit limbs (64-bit accumulators)
// key32 = r (16 bytes, clamped here) || s (16 bytes, pre-computed AES_k(nonce))
Block poly1305OneTimeAuth(const uint8_t rBytes[16], const uint8_t sBytes[16], const uint8_t* msg, size_t len)
{
    // Clamp r according to RFC 8439 Section 2.5
    uint8_t rClamped[16];
    std::memcpy(rClamped, rBytes, 16);
    rClamped[3] &= 15;
    rClamped[7] &= 15;
    rClamped[11] &= 15;
    rClamped[15] &= 15;
    rClamped[4] &= 252;
    rClamped[8] &= 252;
    rClamped[12] &= 252;

    const uint32_t r0 = load32Le(rClamped + 0) & 0x3ffffff;
    const uint32_t r1 = (load32Le(rClamped + 3) >> 2) & 0x3ffff03;
    const uint32_t r2 = (load32Le(rClamped + 6) >> 4) & 0x3ffc0ff;
    const uint32_t r3 = (load32Le(rClamped + 9) >> 6) & 0x3f03fff;
    const uint32_t r4 = (load32Le(rClamped + 12) >> 8) & 0x00fffff;

    const uint32_t s1 = r1 * 5;
    const uint32_t s2 = r2 * 5;
    const uint32_t s3 = r3 * 5;
    const uint32_t s4 = r4 * 5;

    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

    size_t offset = 0;
    while (offset < len) {
        uint8_t block[17] = {};
        const size_t chunk = std::min<size_t>(16, len - offset);
        std::memcpy(block, msg + offset, chunk);
        block[chunk] = 1;
        offset += chunk;

        h0 += load32Le(block + 0) & 0x3ffffff;
        h1 += (load32Le(block + 3) >> 2) & 0x3ffffff;
        h2 += (load32Le(block + 6) >> 4) & 0x3ffffff;
        h3 += (load32Le(block + 9) >> 6) & 0x3ffffff;
        h4 += (load32Le(block + 12) >> 8) | (static_cast<uint32_t>(block[16]) << 24);

        const uint64_t d0 = static_cast<uint64_t>(h0) * r0 + static_cast<uint64_t>(h1) * s4
            + static_cast<uint64_t>(h2) * s3 + static_cast<uint64_t>(h3) * s2 + static_cast<uint64_t>(h4) * s1;
        uint64_t d1 = static_cast<uint64_t>(h0) * r1 + static_cast<uint64_t>(h1) * r0
            + static_cast<uint64_t>(h2) * s4 + static_cast<uint64_t>(h3) * s3 + static_cast<uint64_t>(h4) * s2;
        uint64_t d2 = static_cast<uint64_t>(h0) * r2 + static_cast<uint64_t>(h1) * r1
            + static_cast<uint64_t>(h2) * r0 + static_cast<uint64_t>(h3) * s4 + static_cast<uint64_t>(h4) * s3;
        uint64_t d3 = static_cast<uint64_t>(h0) * r3 + static_cast<uint64_t>(h1) * r2
            + static_cast<uint64_t>(h2) * r1 + static_cast<uint64_t>(h3) * r0 + static_cast<uint64_t>(h4) * s4;
        uint64_t d4 = static_cast<uint64_t>(h0) * r4 + static_cast<uint64_t>(h1) * r3
            + static_cast<uint64_t>(h2) * r2 + static_cast<uint64_t>(h3) * r1 + static_cast<uint64_t>(h4) * r0;

        uint32_t c = static_cast<uint32_t>(d0 >> 26); h0 = static_cast<uint32_t>(d0) & 0x3ffffff; d1 += c;
        c = static_cast<uint32_t>(d1 >> 26);          h1 = static_cast<uint32_t>(d1) & 0x3ffffff; d2 += c;
        c = static_cast<uint32_t>(d2 >> 26);          h2 = static_cast<uint32_t>(d2) & 0x3ffffff; d3 += c;
        c = static_cast<uint32_t>(d3 >> 26);          h3 = static_cast<uint32_t>(d3) & 0x3ffffff; d4 += c;
        c = static_cast<uint32_t>(d4 >> 26);          h4 = static_cast<uint32_t>(d4) & 0x3ffffff; h0 += c * 5;
        c = h0 >> 26;                                 h0 &= 0x3ffffff;                            h1 += c;
    }

    // Final modular reduction mod 2^130 - 5
    uint32_t c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26;          h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26;          h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26;          h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26;          h0 &= 0x3ffffff; h1 += c;

    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1u << 26);

    const uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    const uint32_t nmask = ~mask;
    h0 = (h0 & nmask) | g0;
    h1 = (h1 & nmask) | g1;
    h2 = (h2 & nmask) | g2;
    h3 = (h3 & nmask) | g3;
    h4 = (h4 & nmask) | g4;

    const uint64_t f0 = ((h0) | (h1 << 26)) + static_cast<uint64_t>(load32Le(sBytes + 0));
    const uint64_t f1 = ((h1 >> 6) | (h2 << 20)) + static_cast<uint64_t>(load32Le(sBytes + 4)) + (f0 >> 32);
    const uint64_t f2 = ((h2 >> 12) | (h3 << 14)) + static_cast<uint64_t>(load32Le(sBytes + 8)) + (f1 >> 32);
    const uint64_t f3 = ((h3 >> 18) | (h4 << 8)) + static_cast<uint64_t>(load32Le(sBytes + 12)) + (f2 >> 32);

    Block tag{};
    store32Le(tag.data() + 0, static_cast<uint32_t>(f0));
    store32Le(tag.data() + 4, static_cast<uint32_t>(f1));
    store32Le(tag.data() + 8, static_cast<uint32_t>(f2));
    store32Le(tag.data() + 12, static_cast<uint32_t>(f3));
    return tag;
}

// Encrypt a single 16-byte block with AES-128-ECB via OP-TEE Internal Core API
Block aes128EcbBlock(const uint8_t key16[16], const Block& inBlock)
{
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_ObjectHandle keyObj = TEE_HANDLE_NULL;

    if (TEE_AllocateOperation(&op, TEE_ALG_AES_ECB_NOPAD, TEE_MODE_ENCRYPT, 128) != TEE_SUCCESS) {
        throw std::runtime_error("TEE_AllocateOperation(AES_ECB) failed");
    }
    if (TEE_AllocateTransientObject(TEE_TYPE_AES, 128, &keyObj) != TEE_SUCCESS) {
        TEE_FreeOperation(op);
        throw std::runtime_error("TEE_AllocateTransientObject(AES) failed");
    }
    TEE_Attribute attr{};
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key16, 16);
    if (TEE_PopulateTransientObject(keyObj, &attr, 1) != TEE_SUCCESS
        || TEE_SetOperationKey(op, keyObj) != TEE_SUCCESS) {
        TEE_FreeTransientObject(keyObj);
        TEE_FreeOperation(op);
        throw std::runtime_error("TEE_SetOperationKey(AES_ECB) failed");
    }
    TEE_CipherInit(op, nullptr, 0);
    Block out{};
    uint32_t outLen = static_cast<uint32_t>(out.size());
    const TEE_Result res = TEE_CipherDoFinal(op, inBlock.data(), static_cast<uint32_t>(inBlock.size()),
        out.data(), &outLen);
    TEE_FreeTransientObject(keyObj);
    TEE_FreeOperation(op);
    if (res != TEE_SUCCESS || outLen != 16) {
        throw std::runtime_error("TEE_CipherDoFinal(AES_ECB) failed");
    }
    return out;
}

// Base64 decode helper for PEM X.509 certificate parsing inside the TA
std::optional<Bytes> base64DecodeLocal(const std::string& text)
{
    auto val = [](unsigned char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    Bytes out;
    uint32_t buf = 0;
    int bits = 0;
    for (char ch : text) {
        if (ch == '\r' || ch == '\n' || ch == ' ' || ch == '\t') continue;
        if (ch == '=') break;
        const int v = val(static_cast<unsigned char>(ch));
        if (v < 0) return std::nullopt;
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xff));
        }
    }
    return out;
}

// Minimal ASN.1 DER TLV parser for X.509 Certificate verification inside the TA
bool readDerTlv(const uint8_t* buf, size_t len, size_t& pos, uint8_t& tag, const uint8_t*& val, size_t& valLen,
    size_t& tlvStart, size_t& tlvTotalLen)
{
    if (pos + 2 > len) return false;
    tlvStart = pos;
    tag = buf[pos++];
    const uint8_t lenByte = buf[pos++];
    if ((lenByte & 0x80) == 0) {
        valLen = lenByte;
    } else {
        const size_t numBytes = lenByte & 0x7f;
        if (numBytes == 0 || numBytes > 4 || pos + numBytes > len) return false;
        valLen = 0;
        for (size_t i = 0; i < numBytes; ++i) {
            valLen = (valLen << 8) | buf[pos++];
        }
    }
    if (pos + valLen > len) return false;
    val = buf + pos;
    pos += valLen;
    tlvTotalLen = pos - tlvStart;
    return true;
}

// Parse ASN.1 DER ECDSA-Sig-Value (SEQUENCE { INTEGER r, INTEGER s }) into 64-byte raw (r || s) for GP TEE API
bool derEcdsaSigToRaw64(const uint8_t* der, size_t derLen, uint8_t rawSig[64])
{
    size_t pos = 0, seqLen = 0, start = 0, total = 0;
    uint8_t tag = 0;
    const uint8_t* seqVal = nullptr;
    if (!readDerTlv(der, derLen, pos, tag, seqVal, seqLen, start, total) || tag != 0x30 || pos != derLen) {
        return false;
    }
    size_t sPos = 0;
    std::memset(rawSig, 0, 64);
    for (int idx = 0; idx < 2; ++idx) {
        const uint8_t* intVal = nullptr;
        size_t intLen = 0;
        if (!readDerTlv(seqVal, seqLen, sPos, tag, intVal, intLen, start, total) || tag != 0x02 || intLen == 0) {
            return false;
        }
        while (intLen > 0 && *intVal == 0x00) {
            ++intVal;
            --intLen;
        }
        if (intLen > 32) return false;
        std::memcpy(rawSig + idx * 32 + (32 - intLen), intVal, intLen);
    }
    return sPos == seqLen;
}

#endif // __OPTEE_TA__

} // namespace

void cleanse(void* ptr, size_t len)
{
    if (!ptr || len == 0) return;
#ifdef __OPTEE_TA__
    TEE_MemFill(ptr, 0, static_cast<uint32_t>(len));
#else
    OPENSSL_cleanse(ptr, len);
#endif
}

int constTimeCmp(const void* a, const void* b, size_t len)
{
#ifdef __OPTEE_TA__
    const auto* pa = static_cast<const volatile uint8_t*>(a);
    const auto* pb = static_cast<const volatile uint8_t*>(b);
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= pa[i] ^ pb[i];
    }
    return diff;
#else
    return CRYPTO_memcmp(a, b, len);
#endif
}

Bytes randomBytes(size_t size)
{
#ifdef __OPTEE_TA__
    Bytes out(size);
    if (size > 0) {
        TEE_GenerateRandom(out.data(), static_cast<uint32_t>(size));
    }
    return out;
#else
    return ::randomBytes(size);
#endif
}

Sha256 sha256(const Bytes& data)
{
#ifdef __OPTEE_TA__
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    if (TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0) != TEE_SUCCESS) {
        throw std::runtime_error("TEE_AllocateOperation(SHA256) failed");
    }
    Sha256 digest{};
    uint32_t hashLen = static_cast<uint32_t>(digest.size());
    const TEE_Result res = TEE_DigestDoFinal(op, data.data(), static_cast<uint32_t>(data.size()),
        digest.data(), &hashLen);
    TEE_FreeOperation(op);
    if (res != TEE_SUCCESS || hashLen != 32) {
        throw std::runtime_error("TEE_DigestDoFinal(SHA256) failed");
    }
    return digest;
#else
    return ::sha256(data);
#endif
}

Bytes aesGcmEncrypt(const Bytes& key, const Bytes& plaintext)
{
#ifdef __OPTEE_TA__
    if (key.size() != 16 && key.size() != 32) {
        throw std::runtime_error("AES-GCM: invalid key size");
    }
    const uint32_t keyBits = static_cast<uint32_t>(key.size() * 8);
    const Bytes nonce = randomBytes(kGcmNonceSize);

    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_ObjectHandle keyObj = TEE_HANDLE_NULL;
    if (TEE_AllocateOperation(&op, TEE_ALG_AES_GCM, TEE_MODE_ENCRYPT, keyBits) != TEE_SUCCESS) {
        throw std::runtime_error("TEE_AllocateOperation(AES_GCM) failed");
    }
    if (TEE_AllocateTransientObject(TEE_TYPE_AES, keyBits, &keyObj) != TEE_SUCCESS) {
        TEE_FreeOperation(op);
        throw std::runtime_error("TEE_AllocateTransientObject(AES) failed");
    }
    TEE_Attribute attr{};
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key.data(), static_cast<uint32_t>(key.size()));
    if (TEE_PopulateTransientObject(keyObj, &attr, 1) != TEE_SUCCESS
        || TEE_SetOperationKey(op, keyObj) != TEE_SUCCESS) {
        TEE_FreeTransientObject(keyObj);
        TEE_FreeOperation(op);
        throw std::runtime_error("TEE_SetOperationKey(AES_GCM) failed");
    }

    if (TEE_AEInit(op, nonce.data(), kGcmNonceSize, kGcmTagSize * 8, 0,
            static_cast<uint32_t>(plaintext.size())) != TEE_SUCCESS) {
        TEE_FreeTransientObject(keyObj);
        TEE_FreeOperation(op);
        throw std::runtime_error("TEE_AEInit(AES_GCM) failed");
    }

    Bytes out(kGcmNonceSize + plaintext.size() + kGcmTagSize);
    std::memcpy(out.data(), nonce.data(), kGcmNonceSize);
    uint32_t cipherLen = static_cast<uint32_t>(plaintext.size());
    uint32_t tagLen = kGcmTagSize;
    const TEE_Result res = TEE_AEEncryptFinal(op, plaintext.data(), static_cast<uint32_t>(plaintext.size()),
        out.data() + kGcmNonceSize, &cipherLen, out.data() + kGcmNonceSize + plaintext.size(), &tagLen);
    TEE_FreeTransientObject(keyObj);
    TEE_FreeOperation(op);
    if (res != TEE_SUCCESS || cipherLen != plaintext.size() || tagLen != kGcmTagSize) {
        throw std::runtime_error("TEE_AEEncryptFinal(AES_GCM) failed");
    }
    return out;
#else
    return ::aesGcmEncrypt(key, plaintext);
#endif
}

std::optional<Bytes> aesGcmDecrypt(const Bytes& key, const Bytes& sealed)
{
#ifdef __OPTEE_TA__
    if ((key.size() != 16 && key.size() != 32) || sealed.size() < kGcmNonceSize + kGcmTagSize) {
        return std::nullopt;
    }
    const uint32_t keyBits = static_cast<uint32_t>(key.size() * 8);
    const size_t cipherSize = sealed.size() - kGcmNonceSize - kGcmTagSize;
    const uint8_t* nonce = sealed.data();
    const uint8_t* cipher = sealed.data() + kGcmNonceSize;
    const uint8_t* tag = cipher + cipherSize;

    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_ObjectHandle keyObj = TEE_HANDLE_NULL;
    if (TEE_AllocateOperation(&op, TEE_ALG_AES_GCM, TEE_MODE_DECRYPT, keyBits) != TEE_SUCCESS) {
        return std::nullopt;
    }
    if (TEE_AllocateTransientObject(TEE_TYPE_AES, keyBits, &keyObj) != TEE_SUCCESS) {
        TEE_FreeOperation(op);
        return std::nullopt;
    }
    TEE_Attribute attr{};
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key.data(), static_cast<uint32_t>(key.size()));
    if (TEE_PopulateTransientObject(keyObj, &attr, 1) != TEE_SUCCESS
        || TEE_SetOperationKey(op, keyObj) != TEE_SUCCESS
        || TEE_AEInit(op, nonce, kGcmNonceSize, kGcmTagSize * 8, 0, static_cast<uint32_t>(cipherSize)) != TEE_SUCCESS) {
        TEE_FreeTransientObject(keyObj);
        TEE_FreeOperation(op);
        return std::nullopt;
    }

    Bytes plain(cipherSize);
    uint32_t plainLen = static_cast<uint32_t>(cipherSize);
    const TEE_Result res = TEE_AEDecryptFinal(op, cipher, static_cast<uint32_t>(cipherSize),
        plain.data(), &plainLen, const_cast<uint8_t*>(tag), kGcmTagSize);
    TEE_FreeTransientObject(keyObj);
    TEE_FreeOperation(op);
    if (res != TEE_SUCCESS || plainLen != cipherSize) {
        return std::nullopt;
    }
    return plain;
#else
    return ::aesGcmDecrypt(key, sealed);
#endif
}

Block poly1305Aes(const Bytes& key, const Block& nonce, const Bytes& message)
{
#ifdef __OPTEE_TA__
    if (key.size() != 32) {
        throw std::runtime_error("Poly1305-AES: key must be 32 bytes");
    }
    // key = k (16 bytes for AES-128) || r (16 bytes for Poly1305); s = AES_k(nonce)
    Block s = aes128EcbBlock(key.data(), nonce);
    const Block mac = poly1305OneTimeAuth(key.data() + 16, s.data(), message.data(), message.size());
    cleanse(s.data(), s.size());
    return mac;
#else
    return ::poly1305Aes(key, nonce, message);
#endif
}

std::string verifySubjectPublicKeyInfo(const Bytes& der)
{
#ifdef __OPTEE_TA__
    if (der.size() == kP256SpkiLen && std::memcmp(der.data(), kP256SpkiPrefix, sizeof(kP256SpkiPrefix)) == 0) {
        return "prime256v1";
    }
    return "";
#else
    const unsigned char* p = der.data();
    EVP_PKEY* key = d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size()));
    if (!key) {
        return "";
    }
    char curve[64] = "?";
    EVP_PKEY_get_group_name(key, curve, sizeof(curve), nullptr);
    EVP_PKEY_free(key);
    return curve;
#endif
}

EcdhDerived generateAndDeriveEcdh(const Bytes& peerPublicKeyDer)
{
#ifdef __OPTEE_TA__
    if (peerPublicKeyDer.size() != kP256SpkiLen
        || std::memcmp(peerPublicKeyDer.data(), kP256SpkiPrefix, sizeof(kP256SpkiPrefix)) != 0) {
        throw std::runtime_error("ECDH: peer public key is not P-256 SubjectPublicKeyInfo DER");
    }
    const uint8_t* peerX = peerPublicKeyDer.data() + sizeof(kP256SpkiPrefix);
    const uint8_t* peerY = peerX + 32;

    // 1. Generate ephemeral P-256 keypair inside OP-TEE
    TEE_ObjectHandle keyPair = TEE_HANDLE_NULL;
    if (TEE_AllocateTransientObject(TEE_TYPE_ECDH_KEYPAIR, 256, &keyPair) != TEE_SUCCESS) {
        throw std::runtime_error("TEE_AllocateTransientObject(ECDH_KEYPAIR) failed");
    }
    TEE_Attribute curveAttr{};
    TEE_InitValueAttribute(&curveAttr, TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0);
    if (TEE_GenerateKey(keyPair, 256, &curveAttr, 1) != TEE_SUCCESS) {
        TEE_FreeTransientObject(keyPair);
        throw std::runtime_error("TEE_GenerateKey(P256) failed");
    }

    // 2. Extract our uncompressed public point (X, Y) and wrap into 91-byte SPKI DER
    uint8_t myX[32]{}, myY[32]{};
    uint32_t xLen = 32, yLen = 32;
    if (TEE_GetObjectBufferAttribute(keyPair, TEE_ATTR_ECC_PUBLIC_VALUE_X, myX, &xLen) != TEE_SUCCESS
        || TEE_GetObjectBufferAttribute(keyPair, TEE_ATTR_ECC_PUBLIC_VALUE_Y, myY, &yLen) != TEE_SUCCESS) {
        TEE_FreeTransientObject(keyPair);
        throw std::runtime_error("TEE_GetObjectBufferAttribute(ECC_PUBLIC) failed");
    }
    Bytes mySpki(kP256SpkiLen, 0);
    std::memcpy(mySpki.data(), kP256SpkiPrefix, sizeof(kP256SpkiPrefix));
    std::memcpy(mySpki.data() + sizeof(kP256SpkiPrefix) + (32 - xLen), myX, xLen);
    std::memcpy(mySpki.data() + sizeof(kP256SpkiPrefix) + 32 + (32 - yLen), myY, yLen);

    // 3. Derive shared secret Z = ECDH(myKeyPair, peerPubKey)
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_ObjectHandle secretObj = TEE_HANDLE_NULL;
    if (TEE_AllocateOperation(&op, TEE_ALG_ECDH_P256, TEE_MODE_DERIVE, 256) != TEE_SUCCESS
        || TEE_SetOperationKey(op, keyPair) != TEE_SUCCESS
        || TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, 256, &secretObj) != TEE_SUCCESS) {
        if (secretObj != TEE_HANDLE_NULL) TEE_FreeTransientObject(secretObj);
        if (op != TEE_HANDLE_NULL) TEE_FreeOperation(op);
        TEE_FreeTransientObject(keyPair);
        throw std::runtime_error("TEE_AllocateOperation(ECDH_P256) failed");
    }

    TEE_Attribute peerAttrs[2]{};
    TEE_InitRefAttribute(&peerAttrs[0], TEE_ATTR_ECC_PUBLIC_VALUE_X, peerX, 32);
    TEE_InitRefAttribute(&peerAttrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y, peerY, 32);
    TEE_AsymmetricDeriveKey(op, peerAttrs, 2, secretObj);

    Bytes shared(32, 0);
    uint32_t sharedLen = 32;
    uint8_t rawSecret[32]{};
    const TEE_Result res = TEE_GetObjectBufferAttribute(secretObj, TEE_ATTR_SECRET_VALUE, rawSecret, &sharedLen);
    TEE_FreeTransientObject(secretObj);
    TEE_FreeOperation(op);
    TEE_FreeTransientObject(keyPair); // Ephemeral private key X is destroyed immediately
    if (res != TEE_SUCCESS || sharedLen == 0 || sharedLen > 32) {
        cleanse(rawSecret, sizeof(rawSecret));
        throw std::runtime_error("TEE_AsymmetricDeriveKey(P256) failed");
    }
    std::memcpy(shared.data() + (32 - sharedLen), rawSecret, sharedLen);
    cleanse(rawSecret, sizeof(rawSecret));
    return EcdhDerived{ std::move(mySpki), std::move(shared) };
#else
    const auto keyPair = ::newEcKey(kEcdhCurve);
    const auto peerKey = ::publicKeyFromDer(peerPublicKeyDer);
    return EcdhDerived{ ::publicKeyDer(keyPair.get()), ::ecdh(keyPair.get(), peerKey.get()) };
#endif
}

std::optional<PinnedCertificate> verifySelfSignedP256CertPem(const std::string& pem, std::string& errorReason)
{
#ifdef __OPTEE_TA__
    const std::string beginMarker = "-----BEGIN CERTIFICATE-----";
    const std::string endMarker   = "-----END CERTIFICATE-----";
    const size_t bPos = pem.find(beginMarker);
    const size_t ePos = pem.find(endMarker);
    if (bPos == std::string::npos || ePos == std::string::npos || ePos <= bPos + beginMarker.size()) {
        errorReason = "HTTPS session: the cloud's certificate is not a PEM certificate";
        return std::nullopt;
    }
    const auto certDer = base64DecodeLocal(pem.substr(bPos + beginMarker.size(), ePos - (bPos + beginMarker.size())));
    if (!certDer || certDer->empty()) {
        errorReason = "HTTPS session: the cloud's certificate is not a PEM certificate";
        return std::nullopt;
    }

    // Parse X.509 Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    size_t pos = 0, certLen = 0, start = 0, total = 0;
    uint8_t tag = 0;
    const uint8_t* certVal = nullptr;
    if (!readDerTlv(certDer->data(), certDer->size(), pos, tag, certVal, certLen, start, total) || tag != 0x30) {
        errorReason = "HTTPS session: the cloud's certificate is not a PEM certificate";
        return std::nullopt;
    }

    size_t cPos = 0;
    const uint8_t* tbsVal = nullptr;
    size_t tbsLen = 0, tbsStart = 0, tbsTotal = 0;
    if (!readDerTlv(certVal, certLen, cPos, tag, tbsVal, tbsLen, tbsStart, tbsTotal) || tag != 0x30) {
        errorReason = "HTTPS session: malformed tbsCertificate";
        return std::nullopt;
    }
    const Bytes tbsBytes(certVal + tbsStart, certVal + tbsStart + tbsTotal);

    const uint8_t* sigAlgVal = nullptr;
    size_t sigAlgLen = 0, dummyStart = 0, dummyTotal = 0;
    if (!readDerTlv(certVal, certLen, cPos, tag, sigAlgVal, sigAlgLen, dummyStart, dummyTotal) || tag != 0x30) {
        errorReason = "HTTPS session: malformed signatureAlgorithm";
        return std::nullopt;
    }

    const uint8_t* sigBitStr = nullptr;
    size_t sigBitLen = 0;
    if (!readDerTlv(certVal, certLen, cPos, tag, sigBitStr, sigBitLen, dummyStart, dummyTotal)
        || tag != 0x03 || sigBitLen < 2 || sigBitStr[0] != 0x00) {
        errorReason = "HTTPS session: malformed signatureValue";
        return std::nullopt;
    }

    // Locate the 91-byte P-256 SubjectPublicKeyInfo inside tbsCertificate
    auto spkiIt = std::search(tbsBytes.begin(), tbsBytes.end(),
        std::begin(kP256SpkiPrefix), std::end(kP256SpkiPrefix));
    if (spkiIt == tbsBytes.end()
        || static_cast<size_t>(std::distance(spkiIt, tbsBytes.end())) < kP256SpkiLen) {
        errorReason = "HTTPS session: the cloud's key is not P-256 (?)";
        return std::nullopt;
    }
    const Bytes spki(spkiIt, spkiIt + kP256SpkiLen);
    const uint8_t* pubX = spki.data() + sizeof(kP256SpkiPrefix);
    const uint8_t* pubY = pubX + 32;

    // Extract CN from subject if present (OID 2.5.4.3 = 55 04 03)
    std::string subject = "/CN=cloud";
    const uint8_t cnOid[3] = { 0x55, 0x04, 0x03 };
    auto cnIt = std::search(tbsBytes.begin(), tbsBytes.end(), std::begin(cnOid), std::end(cnOid));
    if (cnIt != tbsBytes.end() && std::distance(cnIt, tbsBytes.end()) > 5) {
        const size_t cnLen = static_cast<uint8_t>(*(cnIt + 4));
        if (static_cast<size_t>(std::distance(cnIt + 5, tbsBytes.end())) >= cnLen) {
            subject = "/CN=" + std::string(cnIt + 5, cnIt + 5 + cnLen);
        }
    }

    // Verify self-signature over SHA256(tbsCertificate) using OP-TEE TEE_ALG_ECDSA_P256
    uint8_t rawSig[64]{};
    if (!derEcdsaSigToRaw64(sigBitStr + 1, sigBitLen - 1, rawSig)) {
        errorReason = "HTTPS session: the cloud's certificate is not signed by its own key";
        return std::nullopt;
    }
    const Sha256 tbsHash = sha256(tbsBytes);

    TEE_ObjectHandle pubKeyObj = TEE_HANDLE_NULL;
    TEE_OperationHandle verifyOp = TEE_HANDLE_NULL;
    if (TEE_AllocateTransientObject(TEE_TYPE_ECDSA_PUBLIC_KEY, 256, &pubKeyObj) != TEE_SUCCESS) {
        errorReason = "TEE_AllocateTransientObject(ECDSA_PUBLIC_KEY) failed";
        return std::nullopt;
    }
    TEE_Attribute attrs[3]{};
    TEE_InitRefAttribute(&attrs[0], TEE_ATTR_ECC_PUBLIC_VALUE_X, pubX, 32);
    TEE_InitRefAttribute(&attrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y, pubY, 32);
    TEE_InitValueAttribute(&attrs[2], TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0);
    if (TEE_PopulateTransientObject(pubKeyObj, attrs, 3) != TEE_SUCCESS
        || TEE_AllocateOperation(&verifyOp, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY, 256) != TEE_SUCCESS
        || TEE_SetOperationKey(verifyOp, pubKeyObj) != TEE_SUCCESS) {
        if (verifyOp != TEE_HANDLE_NULL) TEE_FreeOperation(verifyOp);
        TEE_FreeTransientObject(pubKeyObj);
        errorReason = "TEE_SetOperationKey(ECDSA_P256) failed";
        return std::nullopt;
    }
    const TEE_Result vRes = TEE_AsymmetricVerify(verifyOp, nullptr, 0,
        tbsHash.data(), static_cast<uint32_t>(tbsHash.size()), rawSig, sizeof(rawSig));
    TEE_FreeOperation(verifyOp);
    TEE_FreeTransientObject(pubKeyObj);
    if (vRes != TEE_SUCCESS) {
        errorReason = "HTTPS session: the cloud's certificate is not signed by its own key";
        return std::nullopt;
    }

    return PinnedCertificate{ spki, subject, "prime256v1" };
#else
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    std::unique_ptr<X509, decltype(&X509_free)> cert(
        bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr) : nullptr, X509_free);
    if (!cert) {
        errorReason = "HTTPS session: the cloud's certificate is not a PEM certificate";
        return std::nullopt;
    }
    EVP_PKEY* key = X509_get0_pubkey(cert.get());
    char curve[64] = "?";
    if (!key || EVP_PKEY_get_group_name(key, curve, sizeof(curve), nullptr) != 1
        || std::strcmp(curve, "prime256v1") != 0) {
        errorReason = std::string("HTTPS session: the cloud's key is not P-256 (") + curve + ")";
        return std::nullopt;
    }
    if (X509_verify(cert.get(), key) != 1) {
        errorReason = "HTTPS session: the cloud's certificate is not signed by its own key";
        return std::nullopt;
    }
    char subject[128] = "?";
    X509_NAME_oneline(X509_get_subject_name(cert.get()), subject, sizeof(subject));
    return PinnedCertificate{ ::publicKeyDer(key), subject, curve };
#endif
}

std::string base64Encode(const Bytes& data)
{
    static const char kTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
        const uint32_t b0 = data[i];
        const uint32_t b1 = (i + 1 < data.size()) ? data[i + 1] : 0;
        const uint32_t b2 = (i + 2 < data.size()) ? data[i + 2] : 0;
        const uint32_t triple = (b0 << 16) | (b1 << 8) | b2;
        out.push_back(kTable[(triple >> 18) & 0x3f]);
        out.push_back(kTable[(triple >> 12) & 0x3f]);
        out.push_back((i + 1 < data.size()) ? kTable[(triple >> 6) & 0x3f] : '=');
        out.push_back((i + 2 < data.size()) ? kTable[triple & 0x3f] : '=');
    }
    return out;
}

#ifndef __OPTEE_TA__
// Host simulation mode: derive a deterministic hardware-like sealing key for Secure Storage emulation
static const Bytes& hostSealKey()
{
    static const Bytes kKey = [] {
        const char* label = "OPTEE-ARM-TRUSTZONE-SECURE-STORAGE-HUK-V2X-GATEWAY";
        const Sha256 h = ::sha256(Bytes(label, label + std::strlen(label)));
        return Bytes(h.begin(), h.end());
    }();
    return kKey;
}
#endif

bool savePersistentState(const std::string& storageId, const Bytes& plainState)
{
    if (storageId.empty()) return false;
#ifdef __OPTEE_TA__
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    const uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;
    const TEE_Result res = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE,
        storageId.data(), static_cast<uint32_t>(storageId.size()),
        flags,
        TEE_HANDLE_NULL,
        plainState.data(), static_cast<uint32_t>(plainState.size()),
        &obj);
    if (res != TEE_SUCCESS) {
        return false;
    }
    TEE_CloseObject(obj);
    return true;
#else
    const Bytes sealed = aesGcmEncrypt(hostSealKey(), plainState);
    std::FILE* file = std::fopen(storageId.c_str(), "wb");
    if (!file) {
        return false;
    }
    const size_t written = std::fwrite(sealed.data(), 1, sealed.size(), file);
    std::fclose(file);
    return written == sealed.size();
#endif
}

std::optional<Bytes> loadPersistentState(const std::string& storageId)
{
    if (storageId.empty()) return std::nullopt;
#ifdef __OPTEE_TA__
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    const uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ;
    if (TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, storageId.data(),
            static_cast<uint32_t>(storageId.size()), flags, &obj) != TEE_SUCCESS) {
        return std::nullopt;
    }
    TEE_ObjectInfo info{};
    if (TEE_GetObjectInfo1(obj, &info) != TEE_SUCCESS || info.dataSize == 0 || info.dataSize > 64 * 1024) {
        TEE_CloseObject(obj);
        return std::nullopt;
    }
    Bytes out(info.dataSize);
    uint32_t readBytes = 0;
    const TEE_Result res = TEE_ReadObjectData(obj, out.data(), info.dataSize, &readBytes);
    TEE_CloseObject(obj);
    if (res != TEE_SUCCESS || readBytes != info.dataSize) {
        return std::nullopt;
    }
    return out;
#else
    std::FILE* file = std::fopen(storageId.c_str(), "rb");
    if (!file) {
        return std::nullopt;
    }
    std::fseek(file, 0, SEEK_END);
    const long size = std::ftell(file);
    std::fseek(file, 0, SEEK_SET);
    if (size <= 0 || size > 64 * 1024) {
        std::fclose(file);
        return std::nullopt;
    }
    Bytes sealed(static_cast<size_t>(size));
    const size_t n = std::fread(sealed.data(), 1, sealed.size(), file);
    std::fclose(file);
    if (n != sealed.size()) {
        return std::nullopt;
    }
    return aesGcmDecrypt(hostSealKey(), sealed);
#endif
}

void deletePersistentState(const std::string& storageId)
{
    if (storageId.empty()) return;
#ifdef __OPTEE_TA__
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    const uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META;
    if (TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, storageId.data(),
            static_cast<uint32_t>(storageId.size()), flags, &obj) == TEE_SUCCESS) {
        TEE_CloseAndDeletePersistentObject1(obj);
    }
#else
    std::remove(storageId.c_str());
#endif
}

} // namespace ta_crypto
