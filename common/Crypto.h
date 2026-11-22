#ifndef COMMON_CRYPTO_H_
#define COMMON_CRYPTO_H_

#ifndef __OPTEE_TA__
#include <openssl/evp.h>
#endif
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;
using Sha256 = std::array<uint8_t, 32>;
using Block = std::array<uint8_t, 16>;

// CA-verified neighbor RSU identity key carried in Auth_Granted and Forwarding_Granted
struct NeighborRsuKey
{
    std::string name;
    Bytes publicKeyDer;
};
constexpr size_t kMaxNeighborRsus = 4;

void check(bool ok, const char* what);

Sha256 sha256(const Bytes& data);

// AES-256-ECB with PKCS#7 padding (deterministic: same key and data, same output)
Bytes aes256Encrypt(const Sha256& key, const Bytes& data);

// AES-GCM (authenticated encryption), AES-128 or AES-256 by the key size (16 or 32 bytes)
Bytes aesGcmEncrypt(const Bytes& key, const Bytes& plaintext);
std::optional<Bytes> aesGcmDecrypt(const Bytes& key, const Bytes& sealed);

// random bytes from CSPRNG
Bytes randomBytes(size_t size);

// base64 (RFC 4648, with padding, no line breaks)
std::string base64Encode(const Bytes& data);
std::optional<Bytes> base64Decode(const std::string& text);

// Poly1305-AES (Bernstein): key = k (AES-128 key) || r, 16 bytes each; nonce n; message m
Block poly1305Aes(const Bytes& key, const Block& nonce, const Bytes& m);

#ifndef __OPTEE_TA__
// EC key pair on P-256 (prime256v1)
std::shared_ptr<EVP_PKEY> newP256Key();
// EC key pair on any named curve ("P-256", ...)
std::shared_ptr<EVP_PKEY> newEcKey(const char* curve);

// public key as DER SubjectPublicKeyInfo, and back
Bytes publicKeyDer(EVP_PKEY* key);
std::shared_ptr<EVP_PKEY> publicKeyFromDer(const Bytes& der);

// ECDH shared secret (x coordinate of X * Y): own private key X, peer public key Y
Bytes ecdh(EVP_PKEY* privateKey, EVP_PKEY* peerPublicKey);

// self-signed X.509 certificate of "key" (CN = commonName, valid for one year), DER
Bytes selfSignedCertificate(EVP_PKEY* key, const std::string& commonName);

// CA-signed X.509 v3 certificate binding subjectPublicKeyDer (DER SPKI) to subjectCommonName
Bytes issueCertificate(EVP_PKEY* caKey, const std::string& caCommonName,
    const Bytes& subjectPublicKeyDer, const std::string& subjectCommonName, bool isCa = false);

// Verify an X.509 certificate (DER) against caPublicKeyDer (DER SPKI); returns subject's DER SPKI on success
std::optional<Bytes> verifyCertificateSignedByCa(const Bytes& certificateDer, const Bytes& caPublicKeyDer);

// Convert an X.509 DER certificate to PEM format
std::string certificateDerToPem(const Bytes& certificateDer);

// Certificate Authority (CA): issues and validates X.509 certificates for Gateways, ESA, and Cloud
struct CertificateAuthority
{
    std::shared_ptr<EVP_PKEY> key;          // Root CA P-256 keypair
    std::string commonName;                 // Root CA CN (e.g. "iiot-root-ca")
    Bytes certificateDer;                   // Self-signed Root CA X.509 certificate (DER)
    Bytes publicKeyDer;                     // Root CA public key (DER SPKI)

    Bytes issue(const Bytes& subjectPublicKeyDer, const std::string& subjectCommonName) const;
    std::optional<Bytes> verify(const Bytes& certificateDer) const;
};
CertificateAuthority newCertificateAuthority(const std::string& commonName = "iiot-root-ca");

// Mutually authenticated Gateway <-> ESA HTTPS session key:
//   K_esa = SHA256(ECDH_shared || CY_g || CY_e)
Bytes deriveEsaSessionKey(const Bytes& sharedSecret, const Bytes& gatewayPublicKey, const Bytes& esaPublicKey);
#endif

#endif /* COMMON_CRYPTO_H_ */
