#include "Crypto.h"
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <stdexcept>
#include <string>

void check(bool ok, const char* what)
{
    if (!ok) {
        char error[256];
        ERR_error_string_n(ERR_get_error(), error, sizeof(error));
        throw std::runtime_error(std::string("OpenSSL: ") + what + " failed (" + error + ")");
    }
}

Sha256 sha256(const Bytes& data)
{
    Sha256 hash;
    unsigned int length = 0;
    check(EVP_Digest(data.data(), data.size(), hash.data(), &length, EVP_sha256(), nullptr) == 1, "EVP_Digest");
    return hash;
}

Bytes aes256Encrypt(const Sha256& key, const Bytes& data)
{
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    check(ctx != nullptr, "EVP_CIPHER_CTX_new");
    check(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_ecb(), nullptr, key.data(), nullptr) == 1, "EVP_EncryptInit_ex");

    Bytes out(data.size() + EVP_CIPHER_block_size(EVP_aes_256_ecb()));
    int length = 0;
    int finalLength = 0;
    check(EVP_EncryptUpdate(ctx.get(), out.data(), &length, data.data(), data.size()) == 1, "EVP_EncryptUpdate");
    check(EVP_EncryptFinal_ex(ctx.get(), out.data() + length, &finalLength) == 1, "EVP_EncryptFinal_ex");
    out.resize(length + finalLength);
    return out;
}

static constexpr size_t kGcmNonceSize = 12;
static constexpr size_t kGcmTagSize = 16;

static const EVP_CIPHER* aesGcm(const Bytes& key)
{
    if (key.size() == 16) {
        return EVP_aes_128_gcm();
    }
    if (key.size() == 32) {
        return EVP_aes_256_gcm();
    }
    throw std::runtime_error("AES-GCM needs a 16 or 32-byte key (got " + std::to_string(key.size()) + ")");
}

Bytes aesGcmEncrypt(const Bytes& key, const Bytes& plaintext)
{
    const EVP_CIPHER* cipher = aesGcm(key);
    Bytes sealed = randomBytes(kGcmNonceSize); // a fresh nonce per message: never reused with the same key

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    check(ctx != nullptr, "EVP_CIPHER_CTX_new");
    check(EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, key.data(), sealed.data()) == 1, "EVP_EncryptInit_ex");

    sealed.resize(kGcmNonceSize + plaintext.size() + kGcmTagSize);
    int length = 0;
    int finalLength = 0;
    check(EVP_EncryptUpdate(ctx.get(), sealed.data() + kGcmNonceSize, &length, plaintext.data(), plaintext.size()) == 1,
        "EVP_EncryptUpdate");
    check(EVP_EncryptFinal_ex(ctx.get(), sealed.data() + kGcmNonceSize + length, &finalLength) == 1, "EVP_EncryptFinal_ex");
    check(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kGcmTagSize,
        sealed.data() + kGcmNonceSize + length + finalLength) == 1, "EVP_CTRL_GCM_GET_TAG");
    return sealed;
}

std::optional<Bytes> aesGcmDecrypt(const Bytes& key, const Bytes& sealed)
{
    const EVP_CIPHER* cipher = aesGcm(key);
    if (sealed.size() < kGcmNonceSize + kGcmTagSize) {
        return std::nullopt;
    }
    const size_t size = sealed.size() - kGcmNonceSize - kGcmTagSize;
    Bytes tag(sealed.end() - kGcmTagSize, sealed.end());

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    check(ctx != nullptr, "EVP_CIPHER_CTX_new");
    check(EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, key.data(), sealed.data()) == 1, "EVP_DecryptInit_ex");

    Bytes plaintext(size + 16);
    int length = 0;
    int finalLength = 0;
    check(EVP_DecryptUpdate(ctx.get(), plaintext.data(), &length, sealed.data() + kGcmNonceSize, size) == 1,
        "EVP_DecryptUpdate");
    check(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kGcmTagSize, tag.data()) == 1, "EVP_CTRL_GCM_SET_TAG");
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + length, &finalLength) != 1) {
        return std::nullopt; // tag mismatch
    }
    plaintext.resize(length + finalLength);
    return plaintext;
}

Bytes randomBytes(size_t size)
{
    Bytes out(size);
    check(RAND_bytes(out.data(), static_cast<int>(size)) == 1, "RAND_bytes");
    return out;
}

Block poly1305Aes(const Bytes& key, const Block& nonce, const Bytes& m)
{
    if (key.size() != 32) {
        throw std::runtime_error("Poly1305-AES needs a 32-byte key (got " + std::to_string(key.size()) + ")");
    }

    // s = AES_k(n): one AES-128 block, no padding
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> aes(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    check(aes != nullptr, "EVP_CIPHER_CTX_new");
    check(EVP_EncryptInit_ex(aes.get(), EVP_aes_128_ecb(), nullptr, key.data(), nullptr) == 1, "EVP_EncryptInit_ex");
    EVP_CIPHER_CTX_set_padding(aes.get(), 0);
    Block s;
    int length = 0;
    check(EVP_EncryptUpdate(aes.get(), s.data(), &length, nonce.data(), nonce.size()) == 1 && length == 16,
        "EVP_EncryptUpdate");

    // Poly1305 with the one-time key r || s (OpenSSL clamps r)
    Bytes oneTimeKey(key.begin() + 16, key.end());
    oneTimeKey.insert(oneTimeKey.end(), s.begin(), s.end());
    std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac(EVP_MAC_fetch(nullptr, "POLY1305", nullptr), EVP_MAC_free);
    check(mac != nullptr, "EVP_MAC_fetch");
    std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx(EVP_MAC_CTX_new(mac.get()), EVP_MAC_CTX_free);
    check(ctx != nullptr, "EVP_MAC_CTX_new");
    check(EVP_MAC_init(ctx.get(), oneTimeKey.data(), oneTimeKey.size(), nullptr) == 1, "EVP_MAC_init");
    check(EVP_MAC_update(ctx.get(), m.data(), m.size()) == 1, "EVP_MAC_update");
    Block tag;
    size_t tagLength = 0;
    check(EVP_MAC_final(ctx.get(), tag.data(), &tagLength, tag.size()) == 1 && tagLength == 16, "EVP_MAC_final");
    return tag;
}

std::shared_ptr<EVP_PKEY> newP256Key()
{
    return newEcKey("P-256");
}

std::shared_ptr<EVP_PKEY> newEcKey(const char* curve)
{
    std::shared_ptr<EVP_PKEY> key(EVP_EC_gen(curve), EVP_PKEY_free);
    check(key != nullptr, "EVP_EC_gen");
    return key;
}

Bytes publicKeyDer(EVP_PKEY* key)
{
    const int length = i2d_PUBKEY(key, nullptr);
    check(length > 0, "i2d_PUBKEY");
    Bytes der(length);
    unsigned char* out = der.data();
    i2d_PUBKEY(key, &out);
    return der;
}

std::shared_ptr<EVP_PKEY> publicKeyFromDer(const Bytes& der)
{
    const unsigned char* in = der.data();
    std::shared_ptr<EVP_PKEY> key(d2i_PUBKEY(nullptr, &in, der.size()), EVP_PKEY_free);
    check(key != nullptr, "d2i_PUBKEY");
    return key;
}

Bytes ecdh(EVP_PKEY* privateKey, EVP_PKEY* peerPublicKey)
{
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(EVP_PKEY_CTX_new(privateKey, nullptr), EVP_PKEY_CTX_free);
    check(ctx != nullptr, "EVP_PKEY_CTX_new");
    check(EVP_PKEY_derive_init(ctx.get()) == 1, "EVP_PKEY_derive_init");
    check(EVP_PKEY_derive_set_peer(ctx.get(), peerPublicKey) == 1, "EVP_PKEY_derive_set_peer");
    size_t length = 0;
    check(EVP_PKEY_derive(ctx.get(), nullptr, &length) == 1, "EVP_PKEY_derive");
    Bytes secret(length);
    check(EVP_PKEY_derive(ctx.get(), secret.data(), &length) == 1, "EVP_PKEY_derive");
    secret.resize(length);
    return secret;
}
