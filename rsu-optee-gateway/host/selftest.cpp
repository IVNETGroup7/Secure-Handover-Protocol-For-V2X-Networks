#include "modes.h"
#include "BootstrapPayload.h"
#include "ExternalSecurityAgent.h"
#include "HumanOperator.h"
#include "Link.h"
#include "MessageType.h"
#include "ProtocolMsg.h"
#include "SimTime.h"
#include "SmartData.h"
#include "Traits.h"
#include "VehicleAgent.h"
#include "gateway_ta.h"
#include "packet_manager.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <deque>
#include <exception>
#include <functional>
#include <map>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace
{

// In-memory links: OT wireless radio vs IT backhaul (Operator <-> ESA <-> RSU)
enum class Link { Radio, It };

struct Frame
{
    Link link;
    Bytes bytes;    // serialize(ProtocolMsg): as on a socket
};

struct Outcome
{
    bool vehicleReady = false;
    bool operatorConfirmed = false; // Step 12: HumanOperator verified Active_03(UUID_d, SHA256(fw_d))
    bool noOtSecretLeak = true;     // Neither Activation_Request nor UUID_d / SHA256(fw_d) ever touched OT radio
    bool itPayloadsSealed = true;   // Activation_Token & Active_02 carried no plaintext Auth_d / OTP_active in REE
    bool freshActiveOtp = false;    // Theorem 2: Active_01 OTP_dt != Auth_Request OTP_dt
    bool kdeMatchesEsa = false;     // Vehicle K_de == ESA K_de
    int ignored = 0;                // Messages refused by the TA
    BootstrapResult result;
    VehicleTraits traits;
};

bool containsBytes(const Bytes& haystack, const uint8_t* needle, size_t len)
{
    if (len == 0 || haystack.size() < len) {
        return false;
    }
    return std::search(haystack.begin(), haystack.end(), needle, needle + len) != haystack.end();
}

// Step 2 helper: generate Gateway identity inside TA, sign with CA, register with ESA, initialize TA with CA certs
Bytes provisionGateway(const CertificateAuthority& ca, ExternalSecurityAgent& esa, PacketManager& gateway,
    const Bytes& groupKey = {}, Bytes* outGwCert = nullptr)
{
    Bytes cyG;
    const int idStatus = gateway.initIdentity(cyG);
    if (idStatus != GW_OK) {
        throw std::runtime_error(gateway.name() + ": TA_GATEWAY_CMD_INIT_IDENTITY: " + statusName(idStatus));
    }
    const Bytes gwCert = ca.issue(cyG, gateway.name());
    if (!esa.registerRsu(gateway.name(), gwCert)) {
        throw std::runtime_error(gateway.name() + ": ESA rejected CA-signed gateway certificate");
    }
    const int init = gateway.initGateway(ca.publicKeyDer, gwCert, esa.certificate(), groupKey);
    if (init != GW_OK) {
        throw std::runtime_error(gateway.name() + ": TA_GATEWAY_CMD_INIT_GATEWAY: " + statusName(init));
    }
    if (outGwCert) {
        *outGwCert = gwCert;
    }
    return cyG;
}

// One vehicle's bootstrap via IT HumanOperator (Phase A) + OT radio (Phase B & C).
// "windowOffsetSec" shifts [t_0, t_f] relative to now (e.g., +10.0 s to test before-t_0 rejection);
// "windowDurationSec" sets t_f - t_0; "onAir" may mutate or delay any OT/IT frame in flight.
Outcome bootstrapViaOperator(const std::string& vehicleName, unsigned seed, PacketManager& gateway,
    ExternalSecurityAgent& esa, HumanOperator& op, const Bytes& targetCyG,
    const std::function<void(ProtocolMsg&)>& onAir = nullptr, double clockOffset = 0.0,
    double windowOffsetSec = 0.0, double windowDurationSec = kActivationWindow)
{
    std::deque<Frame> bus;
    Outcome outcome;
    const int ignoredBefore = gateway.ignored();

    VehicleAgent::Config config;
    config.name = vehicleName;
    config.targetRsu = gateway.name();
    config.seed = seed;
    config.clockOffset = clockOffset;
    VehicleAgent vehicle(config);
    outcome.traits = vehicle.session().traits();

    vehicle.setTransport([&](const ProtocolMsg& msg) { bus.push_back({ Link::Radio, serialize(msg) }); });

    PacketManager::Transport gatewayLinks;
    gatewayLinks.radio = [&](const ProtocolMsg& msg) { bus.push_back({ Link::Radio, serialize(msg) }); };
    gatewayLinks.https = [&](const ProtocolMsg& msg) { bus.push_back({ Link::It, serialize(msg) }); };
    gateway.setTransport(gatewayLinks);

    op.setTransport([&](const ProtocolMsg& msg) { bus.push_back({ Link::It, serialize(msg) }); });
    op.setConfirmationCallback([&](const Uuid& uuid, const Sha256&) {
        if (uuid == outcome.traits.uuid) {
            outcome.operatorConfirmed = true;
        }
    });
    esa.setTransport([&](const ProtocolMsg& msg) { bus.push_back({ Link::It, serialize(msg) }); });

    Bytes active02WirePayload;
    auto drainBus = [&] {
        while (!bus.empty()) {
            Frame frame = std::move(bus.front());
            bus.pop_front();
            ProtocolMsg msg = deserialize(frame.bytes);
            if (onAir) {
                onAir(msg);
            }

            if (frame.link == Link::Radio) {
                // Critical Spec Invariant: Activation_Request, UUID_d, and SHA256(fw_d) must NEVER appear on OT radio
                if (msg.getType() == Activation_Request
                    || containsBytes(frame.bytes, outcome.traits.uuid.data(), outcome.traits.uuid.size())
                    || containsBytes(frame.bytes, outcome.traits.firmwareHash.data(), outcome.traits.firmwareHash.size())) {
                    outcome.noOtSecretLeak = false;
                }
                vehicle.indicate(msg);
                gateway.onRadio(msg);
            } else {
                // Critical Spec Invariant: Activation_Token & Active_02 must remain encrypted (under K_esa) in REE/IT
                if (msg.getType() == Activation_Token || msg.getType() == Active_02) {
                    const Bytes& payload = getPayload(msg);
                    if (containsBytes(payload, outcome.traits.authD.data(), outcome.traits.authD.size())) {
                        outcome.itPayloadsSealed = false;
                    }
                    if (msg.getType() == Active_02) {
                        active02WirePayload = payload;
                    }
                }
                if (msg.getDestination() == esa.getFullName()) {
                    esa.handleMessage(msg);
                } else if (msg.getDestination() == op.name()) {
                    op.handleMessage(msg);
                } else if (msg.getDestination() == gateway.name()) {
                    gateway.onHttps(msg);
                }
            }
        }
    };

    // Phase A (IT Domain): Human Operator sends Activation_Request directly to ESA -> encrypted Activation_Token -> RSU
    const simtime_t t0 = SimTime::now() + SimTime(windowOffsetSec);
    const simtime_t tf = t0 + SimTime(windowDurationSec);
    op.requestActivation(targetCyG, t0, tf, outcome.traits.uuid, outcome.traits.firmwareHash);
    drainBus();

    // Phase B & C (OT Domain): Vehicle initiates PTP -> ECDH -> Auth_Request -> Auth_Granted -> Active_01
    vehicle.bootstrap().start([&](const BootstrapResult& result) {
        outcome.vehicleReady = true;
        outcome.result = result;
    });
    drainBus();

    if (outcome.vehicleReady) {
        outcome.freshActiveOtp = outcome.result.activeOtp != outcome.result.authReqOtp;
        if (!active02WirePayload.empty()
            && containsBytes(active02WirePayload, outcome.result.activeOtp.data(), outcome.result.activeOtp.size())) {
            outcome.itPayloadsSealed = false;
        }
        const auto esaKde = esa.deviceKey(outcome.result.authD);
        outcome.kdeMatchesEsa = esaKde.has_value() && *esaKde == outcome.result.kDe;
    }

    op.setConfirmationCallback(nullptr);
    outcome.ignored = gateway.ignored() - ignoredBefore;
    return outcome;
}

bool report(const char* scenario, bool ok, const Outcome& outcome)
{
    std::printf("  %-38s vehicle: %-3s  operator Active_03: %-3s  ignored: %d   %s\n", scenario,
        outcome.vehicleReady ? "yes" : "no", outcome.operatorConfirmed ? "yes" : "no", outcome.ignored,
        ok ? "ok" : "UNEXPECTED");
    return ok;
}

// the JSON the cloud must get for "data" (Fig. 5; the format of ta/gateway_session.cpp)
std::string expectedJson(const SmartData& data)
{
    return "{\"Location\":" + std::to_string(data.location) + ",\"Timing\":" + std::to_string(data.timing)
        + ",\"Metadata\":" + std::to_string(data.metadata) + ",\"Value\":\"" + base64Encode(data.value)
        + "\",\"Trust\":\"" + toHex(data.authD.data(), data.authD.size()) + "\"}";
}

// what the cloud does with an IT packet (HTTPS Header | AES(K_eg, JSON)): K_eg from Y_s and its own X_cloud
std::optional<std::string> openAsCloud(const CloudIdentity& cloud, const Bytes& itPacket, std::string* ys = nullptr)
{
    const std::string text(itPacket.begin(), itPacket.end());
    const size_t end = text.find("\r\n\r\n");
    const std::string field = std::string("\r\n") + kSessionKeyHeader + ": ";
    const size_t start = text.find(field);
    if (end == std::string::npos || start == std::string::npos || start > end) {
        return std::nullopt;
    }
    const std::string key = text.substr(start + field.size(), text.find("\r\n", start + 2) - start - field.size());
    const auto der = base64Decode(key);
    if (!der) {
        return std::nullopt;
    }
    const Bytes kEg = computeKEg(cloud.key.get(), publicKeyFromDer(*der).get());
    const auto json = aesGcmDecrypt(kEg, Bytes(itPacket.begin() + static_cast<long>(end) + 4, itPacket.end()));
    if (!json) {
        return std::nullopt;
    }
    if (ys) {
        *ys = key;
    }
    return std::string(json->begin(), json->end());
}

bool marshalCase(PacketManager& gateway, const CloudIdentity& cloud, const char* name, const Bytes& packet,
    int expected, const SmartData* data = nullptr)
{
    const Reply reply = gateway.marshal(packet, static_cast<uint64_t>(SimTime::now().ns()));
    bool ok = reply.status == expected;
    std::string detail = statusName(reply.status);
    if (ok && expected == GW_OK && data) {
        const std::string json = expectedJson(*data);
        const std::string it(reply.payload.begin(), reply.payload.end());
        const bool clear = it.find("\"Location\"") != std::string::npos
            || it.find(base64Encode(data->value)) != std::string::npos;
        const auto opened = openAsCloud(cloud, reply.payload);
        ok = !clear && opened && *opened == json;
        detail += clear ? ", JSON IN CLEAR in the IT packet" : !opened ? ", the cloud CANNOT OPEN it"
            : *opened != json ? ", JSON DIFFERS from what the vehicle sent"
            : ", no JSON in clear; K_eg opens it to what the vehicle sent (" + std::to_string(reply.payload.size()) + " B)";
    }
    std::printf("  %-38s %s   %s\n", name, detail.c_str(), ok ? "ok" : "UNEXPECTED");
    return ok;
}

bool secureMarshaling(PacketManager& gateway, const CloudIdentity& cloud, const BootstrapResult& vehicle)
{
    if (vehicle.authD.empty()) {
        std::printf("  (the vehicle of 1 did not get ready: nothing to send)\n");
        return false;
    }
    auto smartData = [&](size_t size) {
        SmartData data;
        data.location = 4242;
        data.timing = static_cast<uint64_t>(SimTime::now().ns());
        data.metadata = 1;
        data.value = randomBytes(size);
        data.authD = vehicle.authD;
        return data;
    };
    auto seal = [&](const SmartData& data, int64_t at) {
        return sealSmartData(data, vehicle.kG, vehicle.kDg, at);
    };
    const int64_t now = SimTime::now().ns();
    bool ok = true;

    const SmartData small = smartData(32);
    ok &= marshalCase(gateway, cloud, "4a. SmartData 32 B", packDataMessage(seal(small, now)), GW_OK, &small);
    const SmartData large = smartData(kMaxSmartDataValue);
    ok &= marshalCase(gateway, cloud, "4b. SmartData 64 KB - 1", packDataMessage(seal(large, now)), GW_OK, &large);

    DataMessage otp = seal(small, now);
    otp.otp[3] ^= 1;
    ok &= marshalCase(gateway, cloud, "4c. OTP_dt changed", packDataMessage(otp), GW_IGNORED);

    DataMessage data = seal(small, now);
    data.sealedData[20] ^= 1;
    data.otp = dataOtp(vehicle.kDg, data.authD, dataOtpSlot(now), data.sealedData);
    ok &= marshalCase(gateway, cloud, "4d. AES(K_G, Data) changed", packDataMessage(data), GW_IGNORED);

    SmartData stranger = small;
    stranger.authD = randomBytes(vehicle.authD.size());
    ok &= marshalCase(gateway, cloud, "4e. Auth_d of no activated vehicle", packDataMessage(seal(stranger, now)),
        GW_IGNORED);

    const int64_t old = now - static_cast<int64_t>((kOtpWindow + 2) * kOtpTimeStep * 1e9);
    ok &= marshalCase(gateway, cloud, "4f. t outside the OTP window", packDataMessage(seal(small, old)), GW_IGNORED);

    std::string first, ys;
    int packets = 0;
    bool renewed = false, opened = true;
    for (; packets <= kMessagesPerSession && !renewed; ++packets) {
        const Reply reply = gateway.marshal(packDataMessage(seal(small, SimTime::now().ns())),
            static_cast<uint64_t>(SimTime::now().ns()));
        opened = opened && reply.status == GW_OK && openAsCloud(cloud, reply.payload, &ys).has_value();
        if (first.empty()) {
            first = ys;
        }
        renewed = ys != first;
    }
    const bool sessionOk = renewed && opened;
    std::printf("  %-38s %s   %s\n", "4g. new K_eg per session", (renewed ? "new Y_s after " + std::to_string(packets - 1)
        + " more packet(s), every one opened by the cloud" : std::string("NO NEW SESSION")).c_str(),
        sessionOk ? "ok" : "UNEXPECTED");
    return ok && sessionOk;
}

// 4h-4m: fresh vehicle node[5] bootstraps via Operator on rsu[0], hands over via Secrecy Forwarding to rsu[1]
bool secrecyForwarding(PacketManager& rsu0, PacketManager& rsu1, const Bytes& kG1, ExternalSecurityAgent& esa,
    HumanOperator& op, const Bytes& cyG0, const CloudIdentity& cloud)
{
    std::deque<Frame> bus;
    std::vector<std::pair<std::string, Bytes>> toCloud;
    std::optional<Bytes> forwardingRequest;
    const std::map<std::string, PacketManager*> rsus = { { rsu0.name(), &rsu0 }, { rsu1.name(), &rsu1 } };

    // Use a distinct vehicle (node[5], seed=5) since node[0] is already active on rsu[0] and reboot-protected!
    VehicleAgent::Config config;
    config.name = "node[5]";
    config.targetRsu = rsu0.name();
    config.seed = 5;
    VehicleAgent vehicle(config);
    vehicle.setTransport([&](const ProtocolMsg& msg) { bus.push_back({ Link::Radio, serialize(msg) }); });

    for (const auto& [name, rsu] : rsus) {
        PacketManager::Transport links;
        links.radio = [&](const ProtocolMsg& msg) { bus.push_back({ Link::Radio, serialize(msg) }); };
        links.https = [&](const ProtocolMsg& msg) { bus.push_back({ Link::It, serialize(msg) }); };
        links.cloud = [&toCloud, name = name](ItPacket packet) { toCloud.emplace_back(name, std::move(packet.bytes)); };
        rsu->setTransport(links);
    }
    op.setTransport([&](const ProtocolMsg& msg) { bus.push_back({ Link::It, serialize(msg) }); });
    esa.setTransport([&](const ProtocolMsg& msg) { bus.push_back({ Link::It, serialize(msg) }); });

    Bytes predictWirePayload, noticeWirePayload;
    auto run = [&] {
        while (!bus.empty()) {
            Frame frame = std::move(bus.front());
            bus.pop_front();
            const ProtocolMsg msg = deserialize(frame.bytes);
            if (frame.link == Link::Radio) {
                if (msg.getType() == Handover_Predict) {
                    predictWirePayload = getPayload(msg);
                } else if (msg.getType() == Forwarding_Request) {
                    forwardingRequest = frame.bytes;
                }
                vehicle.indicate(msg);
                rsu0.onRadio(msg);
                rsu1.onRadio(msg);
            } else {
                if (msg.getType() == Forwarding_Notice) {
                    noticeWirePayload = getPayload(msg);
                }
                if (msg.getDestination() == esa.getFullName()) {
                    esa.handleMessage(msg);
                } else if (msg.getDestination() == op.name()) {
                    op.handleMessage(msg);
                } else if (auto rsu = rsus.find(msg.getDestination()); rsu != rsus.end()) {
                    rsu->second->onHttps(msg);
                }
            }
        }
    };

    bool ok = true;
    auto result = [&](const char* name, bool passed, const std::string& detail) {
        std::printf("  %-38s %s   %s\n", name, detail.c_str(), passed ? "ok" : "UNEXPECTED");
        std::fflush(stdout);
        ok &= passed;
        return passed;
    };
    auto smartData = [&](const char* name, const std::string& rsu) {
        const size_t before = toCloud.size();
        const SmartData data = vehicle.data().send(randomBytes(32), 4242, 1);
        run();
        const bool marshaled = toCloud.size() == before + 1 && toCloud.back().first == rsu;
        const auto opened = marshaled ? openAsCloud(cloud, toCloud.back().second) : std::nullopt;
        const bool same = opened && *opened == expectedJson(data);
        return result(name, same, !marshaled ? "NOT MARSHALED by " + rsu : !opened ? "the cloud CANNOT OPEN it"
            : !same ? "JSON DIFFERS from what node[5] sent"
            : "marshaled by " + rsu + ", the cloud's K_eg opens it to what node[5] sent");
    };

    std::optional<BootstrapResult> ready;
    std::optional<HandoverResult> handedOver;
    vehicle.handover().setHandoverCallback([&](const HandoverResult& r) { handedOver = r; });

    // Phase A: Operator authorizes node[5] on rsu[0] in IT
    const simtime_t t0 = SimTime::now();
    const VehicleTraits& traits = vehicle.session().traits();
    op.requestActivation(cyG0, t0, t0 + kActivationWindow, traits.uuid, traits.firmwareHash);
    run();

    // Phase B & C: node[5] bootstraps on rsu[0]
    vehicle.bootstrap().start([&](const BootstrapResult& r) { ready = r; });
    run();
    if (result("4h. node[5] bootstraps with rsu[0]", ready && ready->rsu == rsu0.name()
        && vehicle.session().currentRsu() == rsu0.name()
        && vehicle.session().neighborKey(rsu1.name()).has_value()
        && op.isConfirmed(traits.uuid),
        ready ? "ready with " + ready->rsu + " (pre-loaded Y_{rsu[1]}, Operator confirmed)" : std::string("NOT READY"))) {
        smartData("4i. SmartData to rsu[0]", rsu0.name());

        vehicle.handover().requestPrediction(rsu1.name());
        run();
        const bool encryptedHandoff = vehicle.handover().pending()
            && !predictWirePayload.empty()
            && !containsBytes(predictWirePayload, traits.authD.data(), traits.authD.size())
            && !containsBytes(predictWirePayload, reinterpret_cast<const uint8_t*>(rsu1.name().data()), rsu1.name().size())
            && !noticeWirePayload.empty()
            && !containsBytes(noticeWirePayload, traits.authD.data(), traits.authD.size());
        vehicle.handover().requestForwarding();
        run();
        const bool moved = handedOver && handedOver->rsu == rsu1.name() && vehicle.session().currentRsu() == rsu1.name();
        const bool keys = encryptedHandoff && moved && vehicle.session().groupKey() == kG1
            && kG1 != ready->kG && handedOver->kDg != ready->kDg;
        result("4j. Secrecy Forwarding to rsu[1]", keys, !encryptedHandoff ? "PREDICT OR NOTICE LEAKED PLAINTEXT"
            : !handedOver ? "NO Forwarding_Granted accepted"
            : !moved ? "node[5] is NOT with rsu[1]" : !keys ? "node[5] does NOT hold rsu[1]'s K_g"
            : "CTRA predict + E_K_rsu(Notice) -> node[5] with rsu[1] (fresh OTP', K_dh_i)");

        if (keys) {
            smartData("4k. SmartData to rsu[1]", rsu1.name());

            const int ignored = rsu1.ignored();
            const size_t onAir = bus.size();
            if (forwardingRequest) {
                rsu1.onRadio(deserialize(*forwardingRequest));
            }
            const bool refused = forwardingRequest && rsu1.ignored() == ignored + 1 && bus.size() == onAir;
            bus.clear();
            result("4l. Forwarding_Request replayed", refused, refused ? "refused by rsu[1] (handover used)"
                : std::string("NOT REFUSED"));

            SmartData data;
            data.timing = static_cast<uint64_t>(SimTime::now().ns());
            data.value = randomBytes(32);
            data.authD = ready->authD;
            ok &= marshalCase(rsu1, cloud, "4m. rsu[0]'s keys at rsu[1]",
                packDataMessage(sealSmartData(data, ready->kG, ready->kDg, SimTime::now().ns())), GW_IGNORED);
        }
    }

    rsu0.setTransport({});
    rsu1.setTransport({});
    esa.setTransport(nullptr);
    op.setTransport(nullptr);
    return ok;
}

bool securityAndHilChecks(const CertificateAuthority& ca, PacketManager& rsu0, const Bytes& cyG0,
    ExternalSecurityAgent& esa, HumanOperator& op, const CloudIdentity& cloud,
    const Outcome& activeNode0, const Outcome& expiredNode2, const std::string& storageId)
{
    bool ok = true;
    auto checkItem = [&](const char* name, bool passed, const std::string& detail) {
        std::printf("  %-38s %s   %s\n", name, detail.c_str(), passed ? "ok" : "UNEXPECTED");
        ok &= passed;
    };

    // 7a. Post-t_f DoS & Reboot Protection: spoofed ECDH_Request, Auth_Request, Active_01 naming active node[0]
    //     MUST NOT evict node[0] from mActiveSessions, and node[0] must keep marshaling SmartData!
    const uint64_t farFutureNs = static_cast<uint64_t>((SimTime::now() + SimTime(100.0)).ns());
    const auto rogueKey = newP256Key();
    const Reply ecdhReply = rsu0.handleBootstrap(ECDH_Request, "node[0]",
        pack(EcdhPayload{ ECDH_Request, publicKeyDer(rogueKey.get()) }), farFutureNs);
    const Reply spoofAuth = rsu0.handleBootstrap(Auth_Request, "node[0]",
        pack(AuthRequestPayload{ Auth_Request, Block{} }), farFutureNs);
    const Reply spoofActive = rsu0.handleBootstrap(Active_01, "node[0]", randomBytes(64), farFutureNs);

    // Also test a real Auth_Request computed by already-active node[0] using its own K_dg & Auth_d (reboot protection)
    const int64_t nowNs = SimTime::now().ns();
    const Block rebootOtp = dataOtp(activeNode0.result.kDg, activeNode0.result.authD, dataOtpSlot(nowNs),
        Bytes(kOtpMessage, kOtpMessage + std::char_traits<char>::length(kOtpMessage)));
    const Reply rebootAuth = rsu0.handleBootstrap(Auth_Request, "node[0]",
        pack(AuthRequestPayload{ Auth_Request, rebootOtp }), static_cast<uint64_t>(nowNs));

    // Verify node[0] is STILL active and marshals SmartData cleanly!
    SmartData postAttackData;
    postAttackData.location = 777;
    postAttackData.timing = static_cast<uint64_t>(nowNs);
    postAttackData.metadata = 1;
    postAttackData.value = randomBytes(32);
    postAttackData.authD = activeNode0.result.authD;
    const Reply stillActive = rsu0.marshal(
        packDataMessage(sealSmartData(postAttackData, activeNode0.result.kG, activeNode0.result.kDg, nowNs)),
        static_cast<uint64_t>(nowNs));
    const bool dosProtected = (ecdhReply.status == GW_OK)
        && (spoofAuth.status == GW_IGNORED)
        && (spoofActive.status == GW_IGNORED)
        && (rebootAuth.status == GW_IGNORED)
        && (stillActive.status == GW_OK)
        && openAsCloud(cloud, stillActive.payload).has_value();
    checkItem("7a. post-t_f DoS & reboot protection", dosProtected,
        dosProtected ? "spoofed/reboot Auth_Request discarded; node[0] stayed active" : "FAILED");

    // 7b. Already-active Auth_d & expired/compromised Auth_d Activation_Token rejection
    std::deque<ProtocolMsg> itQueue;
    op.setTransport([&](const ProtocolMsg& msg) { itQueue.push_back(msg); });
    esa.setTransport([&](const ProtocolMsg& msg) { itQueue.push_back(msg); });
    int activeTokenStatus = GW_OK;
    int compromisedTokenStatus = GW_OK;
    auto sendToken = [&](const VehicleTraits& traits) -> int {
        const simtime_t t0 = SimTime::now();
        op.requestActivation(cyG0, t0, t0 + kActivationWindow, traits.uuid, traits.firmwareHash);
        int lastStatus = GW_ERR_STATE;
        while (!itQueue.empty()) {
            ProtocolMsg m = std::move(itQueue.front());
            itQueue.pop_front();
            if (m.getDestination() == esa.getFullName()) {
                esa.handleMessage(m);
            } else if (m.getDestination() == rsu0.name() && m.getType() == Activation_Token) {
                lastStatus = rsu0.addActivationToken(getPayload(m), static_cast<uint64_t>(SimTime::now().ns()));
            }
        }
        return lastStatus;
    };
    activeTokenStatus = sendToken(activeNode0.traits);
    compromisedTokenStatus = sendToken(expiredNode2.traits);
    const bool tokenRejectionOk = (activeTokenStatus == GW_IGNORED) && (compromisedTokenStatus == GW_IGNORED);
    checkItem("7b. active & expired Auth_d excluded", tokenRejectionOk,
        tokenRejectionOk ? "both active and expired/compromised Auth_d rejected (GW_IGNORED)" : "FAILED");

    // 7c. CA PKI enforcement + ESA rejects Activation_Request from RSU (non-operator)
    const auto rogueGwKey = newP256Key();
    const Bytes selfSignedGwCert = selfSignedCertificate(rogueGwKey.get(), "rogue-rsu");
    const bool esaRejectedSelfSigned = !esa.registerRsu("rogue-rsu", selfSignedGwCert);

    // ESA must drop Activation_Request sent by an RSU instead of HumanOperator
    int esaEmitted = 0;
    esa.setTransport([&](const ProtocolMsg&) { ++esaEmitted; });
    ProtocolMsg spoofedFromRsu;
    spoofedFromRsu.setType(Activation_Request);
    spoofedFromRsu.setSender(rsu0.name());
    spoofedFromRsu.setDestination(esa.getFullName());
    ActivationRequestPayload fakeReq{ Activation_Request, cyG0, SimTime::now(), SimTime::now() + kActivationWindow,
        activeNode0.traits.uuid, activeNode0.traits.firmwareHash };
    setPayload(spoofedFromRsu, pack(fakeReq));
    esa.handleMessage(spoofedFromRsu);
    const bool esaRejectedRsuReq = (esaEmitted == 0);

    // TA must reject self-signed ESA cert and self-signed Cloud cert
    TeeSession rogueTee(storageId + ".rogue", true);
    PacketManager rogueRsu(rogueTee, "rogue-test");
    Bytes roguePub;
    rogueRsu.initIdentity(roguePub);
    const Bytes validGwCert = ca.issue(roguePub, "rogue-test");
    const auto fakeEsaKey = newP256Key();
    const Bytes selfSignedEsaCert = selfSignedCertificate(fakeEsaKey.get(), "fake-esa");
    const int taRejectedEsaCert = rogueRsu.initGateway(ca.publicKeyDer, validGwCert, selfSignedEsaCert);
    const int taAcceptedValid = rogueRsu.initGateway(ca.publicKeyDer, validGwCert, esa.certificate());
    const CloudIdentity rogueCloud = newSelfSignedCloudIdentity(kCloudAddress);
    const int taRejectedCloudCert = rogueRsu.initCloudSession(rogueCloud.pem(), kCloudAddress);

    const bool pkiOk = esaRejectedSelfSigned && esaRejectedRsuReq
        && (taRejectedEsaCert == GW_ERR_CRYPTO)
        && (taAcceptedValid == GW_OK)
        && (taRejectedCloudCert == GW_ERR_CRYPTO);
    checkItem("7c. CA PKI & operator-only Step 1", pkiOk,
        pkiOk ? "self-signed GW/ESA/Cloud certs & RSU-relayed Activation_Request rejected" : "FAILED");

    // 7d. HIL shared-bus wire helpers + anchored clock hook + 4 concurrent TA sessions (rsu[2], rsu[3])
    const auto peerCert = parsePeerCert(packPeerCert("rsu[1]", "rsu[0]", validGwCert));
    const auto peerAck = parsePeerCertAck(packPeerCertAck("rsu[1]", "rsu[0]"));
    const auto anchor = parseClockAnchor(packClockAnchor(1234567890LL));
    const auto tag = parseRsuTag(toBytes("rsu[1]\n"));
    const auto hello = parseSessionHello(packSessionHello("rsu[0]", cyG0));
    const auto ack = parseSessionAck(packSessionAck("rsu[0]", ca.publicKeyDer, validGwCert, esa.certificate()));

    bool clockCalled = false;
    int radioReplies = 0;
    PacketManager::Transport tClock;
    tClock.radio = [&](const ProtocolMsg&) { ++radioReplies; };
    rsu0.setTransport(tClock);
    rsu0.setClock([&]() -> uint64_t {
        clockCalled = true;
        return static_cast<uint64_t>(SimTime::now().ns());
    });
    ProtocolMsg ptp;
    ptp.setType(PTP);
    ptp.setSender("node[0]");
    ptp.setDestination("rsu[0]");
    setPayload(ptp, pack(PtpPayload{ PTP, {} }));
    rsu0.onRadio(ptp);
    rsu0.setClock(nullptr);
    rsu0.setTransport({});

    TeeSession tee2(storageId + ".rsu2", true);
    TeeSession tee3(storageId + ".rsu3", true);
    PacketManager rsu2(tee2, "rsu[2]");
    PacketManager rsu3(tee3, "rsu[3]");
    Bytes cert2, cert3;
    const Bytes cyG2 = provisionGateway(ca, esa, rsu2, {}, &cert2);
    provisionGateway(ca, esa, rsu3, {}, &cert3);
    const int reg23 = rsu2.registerPeerRsu("rsu[3]", cert3);
    const int reg32 = rsu3.registerPeerRsu("rsu[2]", cert2);

    const bool hilOk = peerCert && peerCert->destRsu == "rsu[1]" && peerCert->peerName == "rsu[0]"
        && peerCert->peerCertDer == validGwCert
        && peerAck && peerAck->destRsu == "rsu[1]" && peerAck->peerName == "rsu[0]"
        && anchor && *anchor == 1234567890LL
        && tag && *tag == "rsu[1]"
        && hello && hello->rsu == "rsu[0]" && hello->gatewayPublicKey == cyG0
        && ack && ack->rsu == "rsu[0]" && ack->caPublicKey == ca.publicKeyDer
        && reg23 == GW_OK && reg32 == GW_OK
        && clockCalled && radioReplies == 1;
    checkItem("7d. HIL wire helpers & 4 TA sessions", hilOk,
        hilOk ? "Session_Hello/Ack, PeerCert/Ack, ClockAnchor, PTP & 4 RSUs OK" : "FAILED");

    // 7e. Secrecy Forwarding security checks: rogue peer cert, spoofed predict, forged notice, fan-out cap & rate limit
    const int roguePeerStatus = rsu2.registerPeerRsu("rogue-rsu", selfSignedGwCert);
    std::string dummyTarget;
    Bytes dummyNotice;
    const uint64_t tNowNs = static_cast<uint64_t>(SimTime::now().ns());
    const int spoofPredictStatus = rsu2.handleHandoverPredict(randomBytes(64), tNowNs, dummyTarget, dummyNotice);
    const int forgedNoticeStatus = rsu3.receiveForwardingNotice("rogue-rsu", randomBytes(96), tNowNs);
    const int tamperedNoticeStatus = rsu3.receiveForwardingNotice("rsu[2]", randomBytes(96), tNowNs);

    // Bootstrap node[6] cleanly on rsu[2] -> test 4-notice fan-out cap and 5/s Forwarding_Request rate limit on rsu[3]
    const Outcome activeNode6 = bootstrapViaOperator("node[6]", 19, rsu2, esa, op, cyG2);
    Bytes dummySealed;
    int fanoutOk = 0;
    for (int i = 0; i < 4; ++i) {
        if (rsu2.triggerHandover("node[6]", "rsu[3]", 0, dummySealed) == GW_OK) {
            ++fanoutOk;
        }
    }
    const int fanoutBlocked = rsu2.triggerHandover("node[6]", "rsu[3]", 0, dummySealed);

    const Bytes bogusFwdReq = pack(ForwardingRequestPayload{ Forwarding_Request, Sha256{}, Block{} });
    int rateAllowedBeforeLimit = 0;
    for (int i = 0; i < 5; ++i) {
        if (rsu3.handleForwardingRequest("dos-sender", bogusFwdReq, tNowNs).status == GW_IGNORED) {
            ++rateAllowedBeforeLimit;
        }
    }
    const Reply rateBlocked = rsu3.handleForwardingRequest("dos-sender", bogusFwdReq, tNowNs);
    const bool secFwdOk = (roguePeerStatus == GW_ERR_CRYPTO)
        && (spoofPredictStatus == GW_IGNORED)
        && (forgedNoticeStatus == GW_IGNORED)
        && (tamperedNoticeStatus == GW_IGNORED)
        && activeNode6.vehicleReady
        && (fanoutOk == 4)
        && (fanoutBlocked == GW_IGNORED)
        && (rateAllowedBeforeLimit == 5)
        && (rateBlocked.status == GW_IGNORED);
    checkItem("7e. Secrecy Forwarding security/DoS", secFwdOk,
        secFwdOk ? "rogue peer, spoofed predict/notice, fan-out <= 4 & req rate limit OK" : "FAILED");

    esa.setTransport(nullptr);
    op.setTransport(nullptr);
    return ok;
}

void title(const char* text)
{
    std::printf("\n=== %s ===\n", text);
    std::fflush(stdout);
}

} // namespace

int runSelfTest(TeeSession& tee, const std::string& storageId)
{
    bool ok = true;
    bool marshaling = false;
    bool forwarding = false;
    bool securityHil = false;
    Outcome normal, tampered, late, stranger, early;
    try {
        // Root CA issues X.509 certificates for ESA, Cloud, and every RSU Gateway
        const CertificateAuthority ca = newCertificateAuthority("iiot-root-ca");
        ExternalSecurityAgent esa(ca, "esa");
        HumanOperator op("operator");
        PacketManager gateway(tee, "rsu[0]");
        const CloudIdentity cloud = newCloudIdentity(ca, kCloudAddress);

        Bytes gwCert0;
        const Bytes cyG0 = provisionGateway(ca, esa, gateway, {}, &gwCert0);
        const int session = gateway.initCloudSession(cloud.pem(), kCloudAddress);
        if (session != GW_OK) {
            throw std::runtime_error(std::string("TA_GATEWAY_CMD_INIT_CLOUD_SESSION: ") + statusName(session));
        }

        const std::string storage1 = storageId + ".rsu1";
        TeeSession tee1(storage1, true);
        std::printf("OP-TEE TA session opened for rsu[1] (session %llu, storage %s)\n",
            static_cast<unsigned long long>(tee1.sessionId()), storage1.c_str());
        PacketManager target(tee1, "rsu[1]");
        const Bytes kG1 = randomBytes(kGroupKeySize);
        Bytes gwCert1;
        provisionGateway(ca, esa, target, kG1, &gwCert1);
        const int session1 = target.initCloudSession(cloud.pem(), kCloudAddress);
        if (session1 != GW_OK) {
            throw std::runtime_error(std::string("rsu[1]: ") + statusName(session1));
        }
        if (gateway.registerPeerRsu("rsu[1]", gwCert1) != GW_OK
            || target.registerPeerRsu("rsu[0]", gwCert0) != GW_OK) {
            throw std::runtime_error("failed to register CA-signed peer RSU certificates");
        }

        title("1. normal bootstrap via Human Operator (node[0] with rsu[0], +0.25 s clock skew)");
        normal = bootstrapViaOperator("node[0]", 1, gateway, esa, op, cyG0, nullptr, 0.25);

        title("2. OTP changed on the air (rejected by OP-TEE TA)");
        tampered = bootstrapViaOperator("node[1]", 7, gateway, esa, op, cyG0, [](ProtocolMsg& msg) {
            if (msg.getType() == Auth_Request) {
                Bytes payload = getPayload(msg);
                payload[5] ^= 1; // one bit of OTP_dt
                setPayload(msg, payload);
            }
        });

        title("3. Auth_Request after t_f (expired & marked compromised by OP-TEE TA)");
        late = bootstrapViaOperator("node[2]", 11, gateway, esa, op, cyG0, [](ProtocolMsg& msg) {
            if (msg.getType() == Auth_Request) {
                std::this_thread::sleep_for(std::chrono::milliseconds(400));
            }
        }, 0.0, 0.0, 0.3);

        title("4. Secure Marshaling (OT -> IT) + Secrecy Forwarding handover (node[5]: rsu[0] -> rsu[1])");
        marshaling = secureMarshaling(gateway, cloud, normal.result);
        forwarding = secrecyForwarding(gateway, target, kG1, esa, op, cyG0, cloud);

        title("5. CY_g of no CA-registered gateway (node[3])");
        const auto rogueKey = newP256Key();
        stranger = bootstrapViaOperator("node[3]", 13, gateway, esa, op, publicKeyDer(rogueKey.get()));

        title("6. before t_0: Operator window opens 10 s later (node[4])");
        early = bootstrapViaOperator("node[4]", 17, gateway, esa, op, cyG0, nullptr, 0.0, 10.0, kActivationWindow);

        title("7. Reboot/DoS protection, CA PKI & HIL 4-RSU checks");
        securityHil = securityAndHilChecks(ca, gateway, cyG0, esa, op, cloud, normal, late, storageId);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        ok = false;
    }

    const bool normalOk = normal.vehicleReady && normal.operatorConfirmed && normal.noOtSecretLeak
        && normal.itPayloadsSealed && normal.freshActiveOtp && normal.kdeMatchesEsa && normal.ignored == 0;
    std::printf("\nresults:\n");
    ok &= report("1. normal (Operator + CA + Theorem 2)", normalOk, normal);
    ok &= report("2. OTP changed on the air", !tampered.vehicleReady && !tampered.operatorConfirmed
        && tampered.ignored == 1, tampered);
    ok &= report("3. Auth_Request after t_f", !late.vehicleReady && !late.operatorConfirmed && late.ignored == 1, late);
    std::printf("  %-38s Secure Marshaling (4a-4g): %s, Secrecy Forwarding (4h-4m): %s   %s\n",
        "4. handover rsu[0] -> rsu[1]", marshaling ? "ok" : "FAILED", forwarding ? "ok" : "FAILED",
        marshaling && forwarding ? "ok" : "UNEXPECTED");
    ok &= marshaling && forwarding;
    ok &= report("5. CY_g of no gateway", !stranger.vehicleReady && !stranger.operatorConfirmed, stranger);
    ok &= report("6. before t_0 (TA enforced)", !early.vehicleReady && !early.operatorConfirmed && early.ignored == 1,
        early);
    std::printf("  %-38s Reboot/DoS, CA PKI, Operator-only, HIL & SecFwd   %s\n",
        "7. security & HIL checks (7a-7e)", securityHil ? "ok" : "FAILED");
    ok &= securityHil;

    std::printf("%s\n", ok ? "gateway OK" : "gateway FAILED");
    return ok ? 0 : 1;
}
