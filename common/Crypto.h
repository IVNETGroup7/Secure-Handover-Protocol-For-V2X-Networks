#ifndef BOOTSTRAP_CRYPTO_H_
#define BOOTSTRAP_CRYPTO_H_

// OpenSSL primitives used by the bootstrap protocols

#include <openssl/evp.h>
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;
using Sha256 = std::array<uint8_t, 32>;
using Block = std::array<uint8_t, 16>;

// throws std::runtime_error with the OpenSSL error when !ok
void check(bool ok, const char* what);

Sha256 sha256(const Bytes& data);

// AES-256-ECB with PKCS#7 padding (deterministic: same key and data, same output)
Bytes aes256Encrypt(const Sha256& key, const Bytes& data);

// AES-GCM (authenticated encryption), AES-128 or AES-256 by the key size (16 or 32 bytes)
//   sealed = nonce (12, random) | ciphertext | tag (16)
Bytes aesGcmEncrypt(const Bytes& key, const Bytes& plaintext);
// nullopt when the tag does not verify (wrong key or data changed on the way)
std::optional<Bytes> aesGcmDecrypt(const Bytes& key, const Bytes& sealed);

// random bytes from OpenSSL's CSPRNG
Bytes randomBytes(size_t size);

// base64 (RFC 4648, with padding, no line breaks); decode: nullopt when "text" is not base64
std::string base64Encode(const Bytes& data);
std::optional<Bytes> base64Decode(const std::string& text);

// Poly1305-AES (Bernstein): key = k (AES-128 key) || r, 16 bytes each; nonce n; message m
//   tag = (Poly1305_r(m) + AES_k(n)) mod 2^128
Block poly1305Aes(const Bytes& key, const Block& nonce, const Bytes& m);

// EC key pair on P-256 (prime256v1)
std::shared_ptr<EVP_PKEY> newP256Key();
// EC key pair on any named curve ("P-256", ...)
std::shared_ptr<EVP_PKEY> newEcKey(const char* curve);

// public key as DER SubjectPublicKeyInfo, and back
Bytes publicKeyDer(EVP_PKEY* key);
std::shared_ptr<EVP_PKEY> publicKeyFromDer(const Bytes& der);

// ECDH shared secret (x coordinate of X * Y): own private key X, peer public key Y
Bytes ecdh(EVP_PKEY* privateKey, EVP_PKEY* peerPublicKey);

#endif /* BOOTSTRAP_CRYPTO_H_ */
