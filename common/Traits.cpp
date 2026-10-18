#include "Traits.h"
#include <iomanip>
#include <sstream>

VehicleTraits manufactureVehicle(std::mt19937& rng)
{
    VehicleTraits traits;

    // UUID version 4 (random), from the seeded RNG
    for (auto& byte : traits.uuid) {
        byte = intuniform(rng, 0, 255);
    }
    traits.uuid[6] = (traits.uuid[6] & 0x0f) | 0x40; // version 4
    traits.uuid[8] = (traits.uuid[8] & 0x3f) | 0x80; // RFC 4122 variant

    // f_w = ECDSA-SHA256(firmware image), the manufacturer's signature of the firmware
    const auto manufacturerKey = newP256Key();
    const Bytes signedData(kFirmwareImage, kFirmwareImage + std::char_traits<char>::length(kFirmwareImage));
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    check(EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, manufacturerKey.get()) == 1, "EVP_DigestSignInit");
    size_t signatureLength = 0;
    check(EVP_DigestSign(ctx.get(), nullptr, &signatureLength, signedData.data(), signedData.size()) == 1, "EVP_DigestSign");
    traits.firmwareSignature.resize(signatureLength);
    check(EVP_DigestSign(ctx.get(), traits.firmwareSignature.data(), &signatureLength, signedData.data(), signedData.size()) == 1,
        "EVP_DigestSign");
    traits.firmwareSignature.resize(signatureLength); // DER signatures vary in length

    // SHA256(f_w): the hash of the firmware signature
    traits.firmwareHash = sha256(traits.firmwareSignature);

    // Auth_d, as the ESA computes it from the Activation_Request
    traits.authD = computeAuthD(computeIdD(traits.uuid, traits.firmwareHash));

    return traits;
}

Sha256 computeIdD(const Uuid& uuid, const Sha256& firmwareHash)
{
    Bytes uuidAndFirmware(uuid.begin(), uuid.end());
    uuidAndFirmware.insert(uuidAndFirmware.end(), firmwareHash.begin(), firmwareHash.end());
    return sha256(uuidAndFirmware);
}

Bytes computeAuthD(const Sha256& idD)
{
    return aes256Encrypt(idD, Bytes(idD.begin(), idD.end()));
}

Bytes computeAuthDe(const Sha256& idD, const Uuid& uuid, const Sha256& firmwareHash, const Bytes& esaPublicKey)
{
    Bytes data(uuid.begin(), uuid.end());
    data.insert(data.end(), firmwareHash.begin(), firmwareHash.end());
    data.insert(data.end(), esaPublicKey.begin(), esaPublicKey.end());
    const Sha256 hash = sha256(data);
    return aes256Encrypt(idD, Bytes(hash.begin(), hash.end()));
}

Sha256 computeKDe(const Sha256& idD, const Bytes& authD, const Bytes& authDe, const Block& otp)
{
    Bytes data(idD.begin(), idD.end());
    data.insert(data.end(), authD.begin(), authD.end());
    data.insert(data.end(), authDe.begin(), authDe.end());
    data.insert(data.end(), otp.begin(), otp.end());
    return sha256(data);
}

int intuniform(std::mt19937& rng, int a, int b)
{
    return std::uniform_int_distribution<int>(a, b)(rng);
}

std::string toHex(const uint8_t* data, size_t size)
{
    std::ostringstream hex;
    for (size_t i = 0; i < size; ++i) {
        hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return hex.str();
}

std::string toString(const Uuid& uuid)
{
    // 8-4-4-4-12
    const std::string hex = toHex(uuid.data(), uuid.size());
    return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) + "-" + hex.substr(16, 4) + "-" + hex.substr(20);
}
