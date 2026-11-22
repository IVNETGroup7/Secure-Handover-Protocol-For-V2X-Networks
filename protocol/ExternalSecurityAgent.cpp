#include "ExternalSecurityAgent.h"
#include "BootstrapPayload.h"
#include "MessageType.h"
#include "ProtocolMsg.h"
#include "Trace.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <openssl/crypto.h>

ExternalSecurityAgent::ExternalSecurityAgent(const CertificateAuthority& ca, const std::string& name) :
    mName(name),
    mCaPublicKey(ca.publicKeyDer)
{
    mKey = newP256Key();
    mPublicKey = publicKeyDer(mKey.get());
    mCertificate = ca.issue(mPublicKey, name);
}

bool ExternalSecurityAgent::registerRsu(const std::string& rsu, const Bytes& gatewayCertDer)
{
    const auto cyG = verifyCertificateSignedByCa(gatewayCertDer, mCaPublicKey);
    if (!cyG) {
        trace::check(mName, false, rsu + ": gateway certificate is NOT signed by trusted CA: rejected");
        return false;
    }

    const Bytes shared = ecdh(mKey.get(), publicKeyFromDer(*cyG).get());
    const Bytes kEsa = deriveEsaSessionKey(shared, *cyG, mPublicKey);
    mGateways[rsu] = Gateway{ *cyG, kEsa };
    trace::check(mName, true, "CA-authenticated HTTPS session established with " + rsu + ", CY_g = "
        + toHex(cyG->data(), cyG->size()) + " (K_esa derived)");
    return true;
}

std::optional<Bytes> ExternalSecurityAgent::deviceKey(const Bytes& authD) const
{
    const auto it = mKde.find(authD);
    if (it == mKde.end()) {
        return std::nullopt;
    }
    return it->second;
}

void ExternalSecurityAgent::handleMessage(const ProtocolMsg& msg)
{
    ++mReceived;
    switch (msg.getType()) {
        case Activation_Request:
            // Step 1 MUST originate from the trusted Human Operator in IT — never relayed from OT/RSU
            if (msg.getSender() != "operator") {
                printCheck(false, "dropping Activation_Request from '" + msg.getSender()
                    + "' (must originate from IT Human Operator)");
                return;
            }
            activationToken(msg);
            break;
        case Active_02:
            if (mGateways.count(msg.getSender()) == 0) {
                std::cerr << mName << ": dropping Active_02 from " << msg.getSender()
                          << " (no CA-authenticated HTTPS session)" << std::endl;
                return;
            }
            active03(msg);
            break;
        default:
            break;
    }
}

void ExternalSecurityAgent::activationToken(const ProtocolMsg& received)
{
    // Step 1 -> Step 3:
    //   1. Validate target gateway CY_g has an authenticated HTTPS session with this ESA
    //   2. Compute Id_d = SHA256(UUID_d || SHA256(fw_d))
    //   3. Compute Auth_d = AES(Id_d, Id_d) and Auth_eg = AES(Id_d, CY_e)
    //   4. Seal Activation_Token(t_0, t_f, Auth_d, Auth_eg) under K_esa (TEE-terminated HTTPS)
    trace::step(mName, "activationToken", messageTypeName(received.getType()), received.getSender());

    const ActivationRequestPayload request = unpackActivationRequest(getPayload(received));
    for (const std::string& line : describe(request)) {
        printDetail(line);
    }

    if (request.t0 >= request.tf) {
        printCheck(false, "invalid activation window (t_0 >= t_f): ignored");
        return;
    }

    auto gateway = std::find_if(mGateways.begin(), mGateways.end(),
        [&](const auto& entry) { return entry.second.publicKey == request.gatewayPublicKey; });
    if (gateway == mGateways.end()) {
        printCheck(false, "CY_g is the certificate key of no CA-authenticated gateway: ignored");
        return;
    }
    printCheck(true, "CY_g is the CA-verified key of " + gateway->first + " (HTTPS session established)");

    const Sha256 idD = computeIdD(request.uuid, request.firmwareHash);

    ActivationTokenPayload token;
    token.type = Activation_Token;
    token.t0 = request.t0;
    token.tf = request.tf;
    token.authD = computeAuthD(idD);
    token.authEg = aes256Encrypt(idD, mPublicKey);
    mActivations[token.authD] = Activation{ idD, request.uuid, request.firmwareHash, gateway->first };

    // Encrypt under K_esa so Gateway Normal World (REE) cannot inspect Auth_d or Auth_eg
    const Bytes sealed = aesGcmEncrypt(gateway->second.sessionKey, pack(token));
    printDetail("E_K_esa(Activation_Token) = AES-256-GCM, " + std::to_string(sealed.size())
        + " bytes -> " + gateway->first + " TEE");

    sendToRsu(Activation_Token, gateway->first, received.getAckNum(), received.getSeqNum() + 1, sealed);
}

void ExternalSecurityAgent::active03(const ProtocolMsg& received)
{
    // Step 11 -> Step 12:
    //   1. Decrypt Active_02 under the sending Gateway's mutually-authenticated K_esa
    //   2. Verify Auth_d, authorized target gateway, and Auth_de
    //   3. Derive K_de = SHA256(Id_d || Auth_d || Auth_de || OTP_dt)
    //   4. Send Active_03(UUID_d, SHA256(fw_d)) to the Human Operator
    trace::step(mName, "active03", messageTypeName(received.getType()), received.getSender());

    const auto gw = mGateways.find(received.getSender());
    const auto plain = aesGcmDecrypt(gw->second.sessionKey, getPayload(received));
    if (!plain) {
        printCheck(false, "Active_02 does not decrypt with K_esa of " + received.getSender() + ": ignored");
        return;
    }
    printCheck(true, "E_K_esa(Active_02) decrypted with " + received.getSender() + "'s K_esa (GCM tag valid)");

    const Active01Payload m = unpackActive01(*plain);
    if (m.type != Active_02) {
        printCheck(false, "unexpected inner message type in Active_02: ignored");
        return;
    }
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }

    auto activation = mActivations.find(m.authD);
    if (activation == mActivations.end()) {
        printCheck(false, "Auth_d of no pending activation: ignored");
        return;
    }
    const Activation& a = activation->second;
    if (a.rsu != received.getSender()) {
        printCheck(false, "Active_02 came from " + received.getSender() + ", expected " + a.rsu + ": ignored");
        return;
    }

    const Sha256 idD = computeIdD(a.uuid, a.firmwareHash);
    const Bytes expectedAuthD = computeAuthD(idD);
    if (expectedAuthD.size() != m.authD.size()
        || CRYPTO_memcmp(expectedAuthD.data(), m.authD.data(), expectedAuthD.size()) != 0) {
        printCheck(false, "Auth_d != AES(Id_d, Id_d): ignored");
        return;
    }
    printCheck(true, "Auth_d = AES(Id_d, Id_d), Id_d = SHA256(UUID + SHA256(f_w))");

    const Bytes expectedAuthDe = computeAuthDe(idD, a.uuid, a.firmwareHash, mPublicKey);
    if (expectedAuthDe.size() != m.authDe.size()
        || CRYPTO_memcmp(expectedAuthDe.data(), m.authDe.data(), expectedAuthDe.size()) != 0) {
        printCheck(false, "Auth_de != AES(Id_d, SHA256(UUID + SHA256(f_w) + CY_e)): ignored");
        return;
    }
    printCheck(true, "Auth_de = AES(Id_d, SHA256(UUID + SHA256(f_w) + CY_e))");

    const Sha256 kDe = computeKDe(idD, m.authD, m.authDe, m.otp);
    mKde[m.authD] = Bytes(kDe.begin(), kDe.end());
    trace::keep(mName, "K_de", mKde[m.authD], toString(a.uuid));

    Active03Payload done;
    done.type = Active_03;
    done.uuid = a.uuid;
    done.firmwareHash = a.firmwareHash;
    for (const std::string& line : describe(done)) {
        printDetail(line);
    }
    mActivations.erase(activation); // one activation per token

    sendToOperator(Active_03, received.getAckNum(), received.getSeqNum() + 1, pack(done));
    trace::end(mName, "Protocol ended (" + toString(done.uuid) + ")");
}

void ExternalSecurityAgent::printDetail(const std::string& text) const
{
    trace::detail(mName, text);
}

void ExternalSecurityAgent::printCheck(bool ok, const std::string& text) const
{
    trace::check(mName, ok, text);
}

void ExternalSecurityAgent::sendToOperator(int type, int seqNum, int ackNum, const Bytes& payload)
{
    send(type, "operator", seqNum, ackNum, payload);
}

void ExternalSecurityAgent::sendToRsu(int type, const std::string& rsu, int seqNum, int ackNum, const Bytes& payload)
{
    if (mGateways.count(rsu) == 0) {
        throw std::runtime_error("esa: no CA-authenticated HTTPS session with '" + rsu + "'");
    }
    send(type, rsu, seqNum, ackNum, payload);
}

void ExternalSecurityAgent::send(int type, const std::string& destination, int seqNum, int ackNum, const Bytes& payload)
{
    if (!mTransport) {
        throw std::runtime_error("esa: no HTTPS transport");
    }

    ProtocolMsg msg;
    msg.setType(type);
    msg.setSender(getFullName());
    msg.setDestination(destination);
    msg.setVehicle("");
    msg.setSeqNum(seqNum);
    msg.setAckNum(ackNum);
    setPayload(msg, payload);
    ++mSent;

    mTransport(msg);
}
