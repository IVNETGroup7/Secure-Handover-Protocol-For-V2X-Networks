#include "ExternalSecurityAgent.h"
#include "BootstrapService.h"
#include "BootstrapMsg.h"
#include "BootstrapPayload.h"
#include "Trace.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>

ExternalSecurityAgent::ExternalSecurityAgent(const std::string& name) : mName(name)
{
    mKey = newP256Key();
    mPublicKey = publicKeyDer(mKey.get());
}

void ExternalSecurityAgent::registerRsu(const std::string& rsu, const std::string& sessionKey,
    const Bytes& gatewayPublicKey)
{
    mGateways[rsu] = Gateway{ sessionKey, gatewayPublicKey };
    trace::detail(mName, "HTTPS session established with " + rsu + ", CY_g = "
        + toHex(gatewayPublicKey.data(), gatewayPublicKey.size()));
}

void ExternalSecurityAgent::handleMessage(const BootstrapMsg& bootstrap)
{
    if (mGateways.count(bootstrap.getSender()) == 0) {
        std::cerr << mName << ": dropping message from " << bootstrap.getSender() << " (no HTTPS session)" << std::endl;
        return;
    }

    ++mReceived;
    switch (bootstrap.getType()) {
        case Activation_Request: activationToken(bootstrap); break; // from the vehicle, relayed by the RSU
        case Active_02:          active03(bootstrap); break;        // from the RSU
        default: break;
    }
}

void ExternalSecurityAgent::activationToken(const BootstrapMsg& received)
{
    // 1. we get the t_0 and t_f values (from the message that has arrived)
    // 2. we must calculate Id_d = SHA256(UUID + SHA256(fw_d)), values that we already received
    // 3. we must calculate Auth_d and send it
    //    Auth_d = AES(Id_d, Id_d)
    // 4. we must calculate Auth_eg and send it
    //    Auth_eg = AES(Id_d, CY_e), CY_e would be the ESA'S public key

    // the message that will be passed is
    // M = { Activation_Token, t_0, t_f, Auth_d, Auth_eg }

    // ESA, on the vehicle's Activation_Request, relayed by an RSU
    trace::step(mName, "activationToken", stageName(received.getType()), received.getSender(), received.getVehicle());

    // M = { Activation_Request, CY_g, t_0, t_f, UUID, SHA256(f_w) }
    const ActivationRequestPayload request = unpackActivationRequest(getPayload(received));
    for (const std::string& line : describe(request)) {
        printDetail(line);
    }

    // CY_g "enables the ESA to identify the target gateway and also to confirm that it has previously
    // authenticated itself to that ESA": the token goes to the gateway whose certificate key is CY_g, and only
    // if it established its HTTPS session with me
    auto gateway = std::find_if(mGateways.begin(), mGateways.end(),
        [&](const auto& entry) { return entry.second.publicKey == request.gatewayPublicKey; });
    if (gateway == mGateways.end()) {
        printCheck(false, "CY_g is the certificate key of no gateway with an HTTPS session: ignored");
        return;
    }
    printCheck(true, "CY_g is the certificate key of " + gateway->first + " (HTTPS session established)");

    // 2. Id_d = SHA256(UUID + SHA256(fw_d))
    const Sha256 idD = computeIdD(request.uuid, request.firmwareHash);

    // M = { Activation_Token, t_0, t_f, Auth_d, Auth_eg }
    ActivationTokenPayload token;
    token.type = Activation_Token;
    token.t0 = request.t0;                                              // 1. t_0 and t_f from the request
    token.tf = request.tf;
    token.authD = computeAuthD(idD);                                    // 3. Auth_d = AES(Id_d, Id_d)
    token.authEg = aes256Encrypt(idD, mPublicKey);                       // 4. Auth_eg = AES(Id_d, CY_e)
    mActivations[token.authD] = Activation{ idD, request.uuid, request.firmwareHash }; // for the Active_02

    sendToRsu(Activation_Token, gateway->first, received.getVehicle(),
        received.getAckNum(), received.getSeqNum() + 1, pack(token));
}

void ExternalSecurityAgent::active03(const BootstrapMsg& received)
{
    // ESA, on the Active_02 relayed by the RSU: the last step of the protocol
    trace::step(mName, "active03", stageName(received.getType()), received.getSender(), received.getVehicle());

    // M = { Active_02, Auth_d, OTP_dt, Auth_de }
    const Active01Payload m = unpackActive01(getPayload(received));
    for (const std::string& line : describe(m)) {
        printDetail(line);
    }

    // the activation this Auth_d belongs to (from the Activation_Request)
    auto activation = mActivations.find(m.authD);
    if (activation == mActivations.end()) {
        printCheck(false, "Auth_d of no pending activation: ignored");
        return;
    }
    const Activation& a = activation->second;

    // Id_d = SHA256(UUID + SHA256(f_w)), Auth_d = AES(Id_d, Id_d)
    const Sha256 idD = computeIdD(a.uuid, a.firmwareHash);
    if (computeAuthD(idD) != m.authD) {
        printCheck(false, "Auth_d != AES(Id_d, Id_d): ignored");
        return;
    }
    printCheck(true, "Auth_d = AES(Id_d, Id_d), Id_d = SHA256(UUID + SHA256(f_w)) of the Activation_Request");

    // Auth_de = AES(Id_d, SHA256(UUID + SHA256(f_w) + CY_e)): the vehicle knows Id_d and accepted my CY_e
    if (computeAuthDe(idD, a.uuid, a.firmwareHash, mPublicKey) != m.authDe) {
        printCheck(false, "Auth_de != AES(Id_d, SHA256(UUID + SHA256(f_w) + CY_e)): ignored");
        return;
    }
    printCheck(true, "Auth_de = AES(Id_d, SHA256(UUID + SHA256(f_w) + CY_e))");

    // K_de = SHA256(Id_d + Auth_d + Auth_de + OTP_dt): the same key the vehicle kept in SaveVehicle
    const Sha256 kDe = computeKDe(idD, m.authD, m.authDe, m.otp);
    mKde[received.getVehicle()] = Bytes(kDe.begin(), kDe.end());
    trace::keep(mName, "K_de", mKde[received.getVehicle()], received.getVehicle());

    // send the UUID and SHA256(f_w)
    // the message would be
    // M = { UUID, SHA256(f_w) }
    // here you can pass in plain text, we will consider the User already has a HTTPS connection with the ESA
    Active03Payload done;
    done.type = Active_03;
    done.uuid = a.uuid;
    done.firmwareHash = a.firmwareHash;
    for (const std::string& line : describe(done)) {
        printDetail(line);
    }
    mActivations.erase(activation); // one activation per token

    sendToUser(Active_03, received.getVehicle(), received.getAckNum(), received.getSeqNum() + 1, pack(done));
    trace::end(mName, "Protocol ended (" + received.getVehicle() + ")");
}

// ---------------------------------------------------------------------------------------------

void ExternalSecurityAgent::printDetail(const std::string& text) const
{
    trace::detail(mName, text);
}

void ExternalSecurityAgent::printCheck(bool ok, const std::string& text) const
{
    trace::check(mName, ok, text);
}

void ExternalSecurityAgent::sendToUser(int type, const std::string& vehicle, int seqNum, int ackNum,
    const Bytes& payload)
{
    send(type, "user", vehicle, seqNum, ackNum, payload);
}

void ExternalSecurityAgent::sendToRsu(int type, const std::string& rsu, const std::string& vehicle,
    int seqNum, int ackNum, const Bytes& payload)
{
    if (mGateways.count(rsu) == 0) {
        throw std::runtime_error("esa: no HTTPS session with '" + rsu + "'");
    }
    send(type, rsu, vehicle, seqNum, ackNum, payload);
}

void ExternalSecurityAgent::send(int type, const std::string& destination, const std::string& vehicle,
    int seqNum, int ackNum, const Bytes& payload)
{
    if (!mTransport) {
        throw std::runtime_error("esa: no HTTPS transport");
    }


    BootstrapMsg msg;
    msg.setType(type);
    msg.setSender(getFullName());
    msg.setDestination(destination);
    msg.setVehicle(vehicle);
    msg.setSeqNum(seqNum);
    msg.setAckNum(ackNum);
    setPayload(msg, payload);
    ++mSent;

    mTransport(msg);
}
