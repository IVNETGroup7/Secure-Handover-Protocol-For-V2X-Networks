#ifndef BOOTSTRAP_TRAITS_H_
#define BOOTSTRAP_TRAITS_H_

// Vehicle data written at manufacturing time, shared by the bootstrap protocols

#include "Crypto.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <array>
#include <cstdint>
#include <memory>
#include <random>
#include <string>
#include <vector>

using Uuid = std::array<uint8_t, 16>;

struct VehicleTraits
{
    Uuid uuid;                              // UUID: manufacturing-time device identification (version 4)
    Bytes firmwareSignature;                // f_w: firmware signature (ECDSA-SHA256 of kFirmwareImage)
    Sha256 firmwareHash;                    // SHA256(f_w): the hash of the firmware signature
    Bytes authD;                            // Auth_d = AES(Id_d, Id_d): the vehicle derives the same value as the ESA
};

// firmware image installed at manufacturing; f_w is its signature, made by the manufacturer
constexpr const char* kFirmwareImage = "gateway-firmware v1.0";

// maximum execution time: after PTP, the protocol must finish between t_0 and t_f = t_0 + kActivationWindow
constexpr double kActivationWindow = 1.0; // s

// ECDH domain parameters (the "q" of K_dg = Y_d^(X_g) mod q): public, the same for every node
constexpr const char* kEcdhCurve = "P-256";

// OTP_dt = Poly1305(K_dg, Auth_d xor t, m): m and the time step of t are public, known by vehicle and RSU
constexpr const char* kOtpMessage = "secure-bootstrap OTP_dt";   // m
constexpr double kOtpTimeStep = 0.1;                            // s: t = floor(PTP-synchronized clock / step)
constexpr int kOtpWindow = 1;   // RSU: tries t = its own slot +- kOtpWindow slots (delay and residual clock error)

// K_g: group key the RSU hands to every vehicle it activates (Auth_Granted), for vehicle <-> vehicle messages
constexpr size_t kGroupKeySize = 16; // AES-128-GCM

// Id_d = SHA256(UUID + SHA256(f_w)) and Auth_d = AES(Id_d, Id_d), shared by the vehicle and the ESA
Sha256 computeIdD(const Uuid& uuid, const Sha256& firmwareHash);
Bytes computeAuthD(const Sha256& idD);
// Auth_de = AES(Id_d, SHA256(UUID + SHA256(f_w) + CY_e)): the vehicle binds its identity to the ESA key it accepted
Bytes computeAuthDe(const Sha256& idD, const Uuid& uuid, const Sha256& firmwareHash, const Bytes& esaPublicKey);
// K_de = SHA256(Id_d + Auth_d + Auth_de + OTP_dt): vehicle <-> ESA key, derived by both sides
Sha256 computeKDe(const Sha256& idD, const Bytes& authD, const Bytes& authDe, const Block& otp);

// builds the traits of one vehicle; "rng" makes the UUID reproducible
VehicleTraits manufactureVehicle(std::mt19937& rng);

// uniform integer in [a, b]
int intuniform(std::mt19937& rng, int a, int b);

std::string toHex(const uint8_t* data, size_t size);
std::string toString(const Uuid&);

#endif /* BOOTSTRAP_TRAITS_H_ */
