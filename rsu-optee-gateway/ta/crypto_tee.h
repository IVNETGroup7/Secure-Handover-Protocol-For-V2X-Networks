#ifndef TA_CRYPTO_TEE_H_
#define TA_CRYPTO_TEE_H_

// Cryptographic and Secure Storage primitives inside the Trusted Application.
//
// When compiled for the OP-TEE Secure World (__OPTEE_TA__):
//   Uses the GlobalPlatform TEE Internal Core API (<tee_internal_api.h>):
//     - TEE_GenerateRandom
//     - TEE_ALG_SHA256 (TEE_AllocateOperation, TEE_DigestDoFinal)
//     - TEE_ALG_AES_GCM (TEE_AEInit, TEE_AEEncryptFinal, TEE_AEDecryptFinal)
//     - TEE_ALG_AES_ECB_NOPAD + RFC 8439 Poly1305 for Poly1305-AES OTPs
//     - TEE_ALG_ECDH_P256 / TEE_TYPE_ECDH_KEYPAIR (TEE_GenerateKey, TEE_AsymmetricDeriveKey)
//     - TEE_ALG_ECDSA_P256 / TEE_TYPE_ECDSA_PUBLIC_KEY (TEE_AsymmetricVerify for X.509 certificate pinning)
//     - TEE_CreatePersistentObject / TEE_OpenPersistentObject (TEE_STORAGE_PRIVATE) for sealing state
//
// When compiled in Host Simulation mode (for x86_64 host self-test and Artery simulation):
//   Uses the repository's OpenSSL 3 primitives (common/Crypto.h) and AES-256-GCM authenticated
//   persistence on disk, exposing the exact same interface to the TA session state machine.

#include "Crypto.h"
#include <cstdint>
#include <optional>
#include <string>

namespace ta_crypto
{

// Secure memory zeroing (TEE_MemFill or OPENSSL_cleanse)
void cleanse(void* ptr, size_t len);

// Constant-time memory comparison (0 if equal, non-zero otherwise)
int constTimeCmp(const void* a, const void* b, size_t len);

// CSPRNG bytes inside the TEE
Bytes randomBytes(size_t size);

// SHA-256 digest
Sha256 sha256(const Bytes& data);

// AES-128-GCM or AES-256-GCM (format: 12-byte nonce || ciphertext || 16-byte tag)
Bytes aesGcmEncrypt(const Bytes& key, const Bytes& plaintext);
std::optional<Bytes> aesGcmDecrypt(const Bytes& key, const Bytes& sealed);

// Poly1305-AES MAC (16-byte tag, 32-byte key: 16B AES-128 key k || 16B Poly1305 clamping key r)
Block poly1305Aes(const Bytes& key, const Block& nonce, const Bytes& message);

// P-256 SubjectPublicKeyInfo DER validation (returns curve name "prime256v1" if valid, empty if invalid)
std::string verifySubjectPublicKeyInfo(const Bytes& der);

// Fresh P-256 ECDH key generation + shared secret derivation:
// Generates ephemeral P-256 keypair (X, Y), derives shared secret Z = ECDH(X, peerPubKeyDer),
// immediately destroys private key X, and returns { Y in 91-byte SPKI DER, 32-byte shared secret Z }.
struct EcdhDerived
{
    Bytes publicKeyDer;     // 91-byte SubjectPublicKeyInfo DER (prime256v1 uncompressed point)
    Bytes sharedSecret;     // 32-byte raw X coordinate of the shared EC point
};
EcdhDerived generateAndDeriveEcdh(const Bytes& peerPublicKeyDer);

// X.509 self-signed P-256 certificate verification (for pinning Cloud certificate CY_e):
// Parses PEM certificate, verifies curve is prime256v1, verifies ECDSA-SHA256 self-signature,
// and outputs the 91-byte SubjectPublicKeyInfo DER and human-readable subject name.
struct PinnedCertificate
{
    Bytes publicKeyDer;
    std::string subject;
    std::string curve;
};
std::optional<PinnedCertificate> verifySelfSignedP256CertPem(const std::string& pem, std::string& errorReason);

// Base64 encoding (for X-Session-Key header and JSON Value field)
std::string base64Encode(const Bytes& data);

// Secure Storage persistence (OP-TEE TEE_STORAGE_PRIVATE persistent object or host-sealed file)
bool savePersistentState(const std::string& storageId, const Bytes& plainState);
std::optional<Bytes> loadPersistentState(const std::string& storageId);
void deletePersistentState(const std::string& storageId);

} // namespace ta_crypto

#endif /* TA_CRYPTO_TEE_H_ */

