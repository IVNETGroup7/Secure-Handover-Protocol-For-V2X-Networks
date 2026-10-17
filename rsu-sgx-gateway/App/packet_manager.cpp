#include "packet_manager.h"
#include "BootstrapPayload.h"
#include "BootstrapService.h"
#include "Enclave_u.h"
#include "SimTime.h"
#include "Trace.h"
#include "gateway.h"
#include <cstdio>
#include <stdexcept>

namespace
{

constexpr size_t kMaxBootstrapReply = 1500;           // a reply goes in one radio frame (net/RawSocket.cpp)
constexpr size_t kMaxItPacket = 64 * 1024 + 1024;     // SmartData up to 64 KB (tee.pdf step 6) + HTTPS framing

// the ECALL itself failed (enclave lost, bad parameters for the bridge): not a gateway status
void check(sgx_status_t status, const char* ecall)
{
    if (status != SGX_SUCCESS) {
        char text[96];
        std::snprintf(text, sizeof(text), "%s failed: sgx_status_t 0x%04x", ecall, static_cast<unsigned>(status));
        throw std::runtime_error(text);
    }
}

// the RSU is the PTP master: its clock is the reference
uint64_t now()
{
    return static_cast<uint64_t>(SimTime::now().ns());
}

} // namespace

// ---------------------------------------------------------------------------------------------
// RSU steps (BootstrapService, role Rsu)

void PacketManager::onRadio(const BootstrapMsg& msg)
{
    // radio: unicast is logical (BootstrapService::isForMe); "esa": the ESA has no radio, the RSU relays it
    if (msg.getDestination() != mName && msg.getDestination() != "esa") {
        return;
    }

    switch (msg.getType()) {
        case Activation_Request: {
            // HTTPSEstablishment: relayed unchanged over the HTTPS session; the ESA unpacks M
            trace::step(mName, "HTTPSEstablishment", stageName(msg.getType()), msg.getSender(), msg.getVehicle());
            send(Activation_Request, "esa", msg.getSeqNum(), msg.getAckNum(), msg.getVehicle(), getPayload(msg));
            break;
        }
        case PTP_Delay_Request: {
            // PTPDelayResponse: M = { PTP_Delay_Response, t_4 }
            trace::step(mName, "PTPDelayResponse", stageName(msg.getType()), msg.getSender(), msg.getVehicle());
            PtpPayload m;
            m.type = PTP_Delay_Response;
            m.timestamp = SimTime::fromNs(static_cast<int64_t>(now())); // t_4: PTP_Delay_Request received
            send(PTP_Delay_Response, msg.getSender(), msg.getAckNum(), msg.getSeqNum() + 1, "", pack(m));
            break;
        }
        case ECDH_Request: enclaveStep("ECDHResponse", msg); break;
        case Auth_Request: enclaveStep("SaveRSU + AuthGranted", msg); break;
        case Active_01:    enclaveStep("Active02", msg); break;
        default: break;
    }
}

void PacketManager::onHttps(const BootstrapMsg& msg)
{
    if (msg.getDestination() != mName || msg.getType() != Activation_Token) {
        return;
    }

    // PTP: the activation goes into the enclave (pending until its OTP), then PTPSync starts the clock exchange
    trace::step(mName, "PTP", stageName(msg.getType()), msg.getSender(), msg.getVehicle());
    const ActivationTokenPayload token = unpackActivationToken(getPayload(msg));
    const int status = addActivationToken(msg.getVehicle(), static_cast<uint64_t>(token.t0.ns()),
        static_cast<uint64_t>(token.tf.ns()), token.authD, token.authEg);
    if (status != GW_OK) {
        trace::check(mName, false, std::string("ecall_control_add_activation_token: ") + statusName(status));
        return;
    }

    // PTPSync: M = { PTP_Sync, t_1 }, t_1 taken as it goes out
    trace::step(mName, "PTPSync", stageName(msg.getType()), msg.getSender(), msg.getVehicle());
    PtpPayload m;
    m.type = PTP_Sync;
    m.timestamp = SimTime::fromNs(static_cast<int64_t>(now()));
    send(PTP_Sync, msg.getVehicle(), msg.getAckNum(), msg.getSeqNum() + 1, "", pack(m));
}

// ECDH_Request, Auth_Request, Active_01: into the enclave; its reply goes where its type says
void PacketManager::enclaveStep(const char* step, const BootstrapMsg& received)
{
    trace::step(mName, std::string(step) + " (enclave)", stageName(received.getType()), received.getSender(),
        received.getVehicle());
    const Reply reply = handleBootstrap(received.getType(), received.getVehicle(), getPayload(received), now());
    if (reply.status == GW_IGNORED) {
        ++mIgnored;
        trace::detail(mName, "the enclave refused it: nothing sent"); // its reason: the enclave's own check
        return;
    }
    if (reply.status != GW_OK) {
        trace::check(mName, false, std::string("ecall_control_handle_bootstrap: ") + statusName(reply.status));
        return;
    }

    if (reply.type == Active_02) {
        // the same M to the ESA, over the HTTPS session; the protocol ends here for the RSU
        send(Active_02, "esa", received.getAckNum(), received.getSeqNum() + 1, received.getVehicle(), reply.payload);
        trace::end(mName, "RSU ready (" + received.getVehicle() + ")");
    } else {
        send(reply.type, received.getSender(), received.getAckNum(), received.getSeqNum() + 1, "", reply.payload);
    }
}

// BootstrapService::sendBootstrap (RSU): "esa" over HTTPS, anything else over the radio
void PacketManager::send(int type, const std::string& destination, int seqNum, int ackNum, const std::string& vehicle,
    const Bytes& payload)
{
    BootstrapMsg msg;
    msg.setType(type);
    msg.setSender(mName);
    msg.setDestination(destination);
    msg.setVehicle(!vehicle.empty() ? vehicle : destination);
    msg.setSeqNum(seqNum);
    msg.setAckNum(ackNum);
    setPayload(msg, payload);

    const bool https = destination == "esa";
    const auto& transport = https ? mTransport.https : mTransport.radio;
    if (!transport) {
        throw std::runtime_error(mName + ": no " + (https ? "HTTPS" : "radio") + " transport");
    }
    trace::send(mName, stageName(type), destination, msg.getVehicle(), https ? "HTTPS" : "radio", payload.size());
    transport(msg);
}

// ---------------------------------------------------------------------------------------------
// ECALLs

int PacketManager::initGateway(const Bytes& gatewayCert, const Bytes& esaPublicKey, const Bytes& groupKey)
{
    int ret = GW_ERR_STATE;
    check(ecall_init_gateway(mEid, &ret, gatewayCert.data(), gatewayCert.size(), esaPublicKey.data(),
        esaPublicKey.size(), groupKey.data(), groupKey.size()), "ecall_init_gateway");
    return ret;
}

int PacketManager::addActivationToken(const std::string& session, uint64_t t0, uint64_t tf, const Bytes& authD,
    const Bytes& authEg)
{
    int ret = GW_ERR_STATE;
    check(ecall_control_add_activation_token(mEid, &ret, session.c_str(), t0, tf, authD.data(), authD.size(),
        authEg.data(), authEg.size()), "ecall_control_add_activation_token");
    return ret;
}

Reply PacketManager::handleBootstrap(int type, const std::string& session, const Bytes& payload, uint64_t ptpTimeNs)
{
    Reply reply;
    Bytes out(kMaxBootstrapReply);
    size_t outLen = 0;
    check(ecall_control_handle_bootstrap(mEid, &reply.status, type, session.c_str(), payload.data(), payload.size(),
        out.data(), out.size(), &outLen, &reply.type, ptpTimeNs), "ecall_control_handle_bootstrap");
    if (reply.status == GW_OK) {
        out.resize(outLen);
        reply.payload = std::move(out);
    }
    return reply;
}

Reply PacketManager::marshal(const Bytes& otPacket, uint64_t ptpTimeNs)
{
    Reply reply;
    Bytes out(kMaxItPacket);
    size_t outLen = 0;
    check(ecall_secure_marshal_ot_to_it(mEid, &reply.status, otPacket.data(), otPacket.size(), ptpTimeNs,
        out.data(), out.size(), &outLen), "ecall_secure_marshal_ot_to_it");
    if (reply.status == GW_OK) {
        out.resize(outLen);
        reply.payload = std::move(out);
    }
    return reply;
}

const char* statusName(int status)
{
    switch (status) {
        case GW_OK: return "GW_OK";
        case GW_IGNORED: return "GW_IGNORED";
        case GW_ERR_ARGS: return "GW_ERR_ARGS";
        case GW_ERR_BUFFER: return "GW_ERR_BUFFER";
        case GW_ERR_CRYPTO: return "GW_ERR_CRYPTO";
        case GW_ERR_STATE: return "GW_ERR_STATE";
        case GW_ERR_NOT_IMPLEMENTED: return "GW_ERR_NOT_IMPLEMENTED";
        default: return "?";
    }
}
