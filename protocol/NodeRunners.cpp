#include "NodeRunners.h"
#include "Bootstrap.h"
#include "BootstrapMsg.h"
#include "BootstrapService.h"
#include "HandoverService.h"
#include "ExternalSecurityAgent.h"
#include "Https.h"
#include "Link.h"
#include "RawSocket.h"
#include "SimTime.h"
#include "SmartData.h"
#include "Trace.h"
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <deque>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>

volatile std::sig_atomic_t gStop = 0;

void signalReady(const Options& options)
{
    ::signalReady(std::stoi(options.get("--ready-fd", "-1")));
}

int runEsa(const Options& options)
{
    ExternalSecurityAgent esa("esa");
    RawSocket backhaul(options.get("--iface", "lo"), kBackhaulEtherType);
    esa.setTransport([&](const BootstrapMsg& msg) { sendMsg(backhaul, msg); });
    std::cout << "[esa] on the backhaul (EtherType 0x88b6)" << std::endl;
    signalReady(options);

    std::map<std::string, std::string> sessions; // RSU -> session key (registered once)
    while (true) {
        waitFor({ &backhaul });
        drain(backhaul, [&](FrameKind kind, const Bytes& body) {
            if (kind == FrameKind::Session_Hello) {
                // pre-established HTTPS session: "rsu name\nsession key"
                const std::string text(body.begin(), body.end());
                const auto newline = text.find('\n');
                const std::string rsu = text.substr(0, newline);
                const std::string key = newline == std::string::npos ? "" : text.substr(newline + 1);
                if (sessions[rsu] != key) {
                    sessions[rsu] = key;
                    esa.registerRsu(rsu, key);
                }
                Bytes ack = toBytes(rsu + "\n");
                ack.insert(ack.end(), esa.publicKey().begin(), esa.publicKey().end());
                sendFrame(backhaul, FrameKind::Session_Ack, ack);
            } else if (kind == FrameKind::Bootstrap) {
                const BootstrapMsg msg = deserialize(body);
                if (msg.getSender() != esa.getFullName()) { // the link also returns our own frames
                    esa.handleMessage(msg);
                }
            }
        });
        if (gStop) {
            break;
        }
    }
    return 0;
}

int runRsu(const Options& options)
{
    BootstrapService::Config config;
    config.name = options.get("--name", "rsu[0]");
    config.role = BootstrapService::Role::Rsu;
    config.seed = std::stoul(options.get("--seed", "2"));
    const std::string iface = options.get("--iface", "lo");

    BootstrapService rsu(config);
    RawSocket radio(iface, kRadioEtherType);
    RawSocket backhaul(iface, kBackhaulEtherType);

    // HTTPS session with the ESA first: Session_Hello until its Session_Ack, which carries CY_e
    rsu.setEsaPublicKey(openHttpsSession(backhaul, rsu.myName(), rsu.httpsSessionKey(), iface,
        [] { return gStop != 0; }));

    BootstrapService::Transport transport;
    transport.radio = [&](const BootstrapMsg& msg) { sendMsg(radio, msg); };
    transport.https = [&](const BootstrapMsg& msg) { sendMsg(backhaul, msg); };
    rsu.setTransport(transport);
    std::cout << "[" << rsu.myName() << "] HTTPS session with the ESA, radio on " << iface << " (EtherType 0x88b5)"
        << std::endl;
    signalReady(options);

    while (true) {
        waitFor({ &radio, &backhaul });
        drain(backhaul, [&](FrameKind kind, const Bytes& body) {
            if (kind == FrameKind::Bootstrap) {
                const BootstrapMsg msg = deserialize(body);
                if (msg.getDestination() == rsu.myName()) { // the session is ours alone; the link is shared
                    rsu.handleHttps(msg);
                }
            }
        });
        drain(radio, [&](FrameKind kind, const Bytes& body) {
            if (kind == FrameKind::Bootstrap) {
                const BootstrapMsg msg = deserialize(body);
                if (msg.getSender() != rsu.myName()) { // the link also returns our own frames
                    rsu.indicate(msg);
                }
            }
        });
        if (gStop) {
            break;
        }
    }
    return 0;
}

std::vector<size_t> parseSizes(const std::string& text)
{
    std::vector<size_t> sizes;
    std::stringstream list(text);
    for (std::string item; std::getline(list, item, ',');) {
        const size_t size = std::stoul(item);
        if (size > kMaxSmartDataValue) {
            throw std::runtime_error("SmartData value of " + item + " bytes: at most " + std::to_string(kMaxSmartDataValue));
        }
        sizes.push_back(size);
    }
    return sizes;
}

void sendSmartData(RawSocket& radio, const BootstrapResult& result, const std::vector<size_t>& sizes, int count,
    std::chrono::milliseconds interval)
{
    const std::string& name = result.vehicle;
    size_t packets = 0, bytes = 0, frames = 0;
    for (int round = 0; round < count && !gStop; ++round) {
        for (size_t size : sizes) {
            std::this_thread::sleep_for(interval);
            if (gStop) {
                break;
            }
            SmartData data;
            data.location = 4242;                   // a road segment
            data.timing = static_cast<uint64_t>(SimTime::now().ns());
            data.metadata = 1;                      // e.g. the sensor type
            data.value = randomBytes(size);         // the measurement
            data.authD = result.authD;
            const int64_t now = SimTime::now().ns();
            const DataMessage message = sealSmartData(data, result.kG, result.kDg, now);
            const Bytes packet = packDataMessage(message);

            if (round == 0) {
                trace::step(name, "SmartData (" + std::to_string(size) + " B)", "", "", name);
                trace::detail(name, "Data = { location " + std::to_string(data.location) + ", timing "
                    + SimTime::fromNs(static_cast<int64_t>(data.timing)).str() + ", metadata "
                    + std::to_string(data.metadata) + ", value " + std::to_string(size) + " B, Auth_d }");
                trace::detail(name, "AES(K_G, Data) = " + std::to_string(message.sealedData.size())
                    + " B (AES-128-GCM with K_g)");
                trace::detail(name, "OTP_dt = Poly1305(K_dg, Auth_d xor t, AES(K_G, Data)) = "
                    + toHex(message.otp.data(), message.otp.size()) + " (t = " + std::to_string(dataOtpSlot(now)) + ")");
                trace::detail(name, "OT packet = Message(AES(K_G, Data), Auth_d, OTP_dt) = "
                    + std::to_string(packet.size()) + " B");
                trace::send(name, "SmartData", result.rsu, name, "radio", packet.size());
            }
            const size_t pieces = sendData(radio, name, result.rsu, packet);
            if (round == 0) {
                trace::detail(name, "sent in " + std::to_string(pieces) + " radio frame(s) of at most "
                    + std::to_string(kMaxFrameData) + " B");
            }
            ++packets;
            bytes += packet.size();
            frames += pieces;
        }
    }
    std::cout << "[" << name << "] " << packets << " SmartData packet(s) sent to " << result.rsu << " ("
        << bytes << " B in " << frames << " radio frames)" << std::endl;
}

int runVehicle(const Options& options)
{
    BootstrapService::Config config;
    config.name = options.get("--name", "node[0]");
    config.role = BootstrapService::Role::Vehicle;
    config.clockOffset = std::stod(options.get("--clock-offset", "0"));
    config.seed = std::stoul(options.get("--seed", "1"));
    const auto timeout = std::chrono::duration<double>(std::stod(options.get("--timeout", "5")));
    const std::vector<size_t> sizes = parseSizes(options.get("--smartdata", ""));
    const int rounds = std::stoi(options.get("--smartdata-count", "1"));
    const std::chrono::milliseconds interval(std::stoi(options.get("--smartdata-interval", "20")));

    BootstrapService vehicle(config);
    RawSocket radio(options.get("--iface", "lo"), kRadioEtherType);

    BootstrapService::Transport transport;
    transport.radio = [&](const BootstrapMsg& msg) { sendMsg(radio, msg); };
    vehicle.setTransport(transport); // a vehicle has no HTTPS link: "esa" goes over the radio

    bool done = false;
    BootstrapResult bootstrap;
    initBootstrap(vehicle, [&](const BootstrapResult& result) {
        done = true;
        bootstrap = result;
        std::cout << "[" << result.vehicle << "] bootstrap completed with " << result.rsu
            << ", K_dg = " << toHex(result.kDg.data(), result.kDg.size())
            << ", K_g = " << toHex(result.kG.data(), result.kG.size())
            << ", K_de = " << toHex(result.kDe.data(), result.kDe.size()) << std::endl;
    });

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!done && !gStop) {
        if (std::chrono::steady_clock::now() >= deadline) {
            std::cerr << "[" << vehicle.myName() << "] bootstrap not completed after " << timeout.count() << " s" << std::endl;
            break;
        }
        waitFor({ &radio });
        drain(radio, [&](FrameKind kind, const Bytes& body) {
            if (kind == FrameKind::Bootstrap) {
                const BootstrapMsg msg = deserialize(body);
                if (msg.getSender() != vehicle.myName()) { // the link also returns our own frames
                    vehicle.indicate(msg);
                }
            }
        });
    }
    if (done && !sizes.empty()) {
        sendSmartData(radio, bootstrap, sizes, rounds, interval);
    }
    return done ? 0 : 1;
}

std::string preview(const std::string& body)
{
    const bool text = std::all_of(body.begin(), body.end(), [](unsigned char c) { return std::isprint(c) || std::isspace(c); });
    if (text) {
        return body.size() <= 400 ? body : body.substr(0, 400) + "… (" + std::to_string(body.size()) + " B)";
    }
    const size_t shown = std::min<size_t>(body.size(), 32);
    return std::to_string(body.size()) + " B, binary: "
        + toHex(reinterpret_cast<const uint8_t*>(body.data()), shown) + (shown < body.size() ? "…" : "");
}

int runCloud(const Options& options)
{
    const std::string address = options.get("--address", kCloudAddress);
    const auto port = static_cast<uint16_t>(std::stoi(options.get("--port", std::to_string(kCloudPort))));
    const std::string certificate = options.get("--cert-out", "cloud.crt");

    HttpsServer server(address, port, certificate);
    std::cout << "[cloud] HTTPS on " << address << ":" << port << ", self-signed P-256 certificate in "
        << certificate << std::endl;
    signalReady(options);

    std::map<size_t, int> posts; // body size -> requests
    int total = 0;
    server.serve(
        [&](const HttpRequest& request, const std::string& peer) {
            HttpResponse response;
            if (request.method != "POST" || request.path != kSmartDataPath) {
                response.status = 404;
                response.reason = "Not Found";
                response.body = R"({"error":"no such resource"})";
                return response;
            }
            ++total;
            if (posts[request.body.size()]++ == 0) {
                auto header = [&](const char* name) {
                    auto value = request.headers.find(name);
                    return value != request.headers.end() ? value->second : std::string("?");
                };
                trace::step("cloud", "store SmartData", "POST " + request.path, header("x-gateway"),
                    header("x-vehicle"));
                trace::detail("cloud", "from " + peer + ", " + std::to_string(request.body.size()) + " B, "
                    + header("content-type"));
                trace::detail("cloud", "body = " + preview(request.body));
            }
            response.body = R"({"status":"stored"})";
            return response;
        },
        [](const std::string& peer, const std::string& session) {
            trace::detail("cloud", "HTTPS session from " + peer + ": " + session);
        },
        [] { return gStop != 0; });

    std::cout << "[cloud] " << total << " SmartData POST(s) received" << std::endl;
    return 0;
}

int runNode(const std::string& role, const Options& options)
{
    try {
        if (role == "esa") return runEsa(options);
        if (role == "rsu") return runRsu(options);
        if (role == "vehicle") return runVehicle(options);
        if (role == "cloud") return runCloud(options);
        throw std::runtime_error("unknown role '" + role + "' (use esa, rsu, vehicle or cloud)");
    } catch (const std::exception& e) {
        std::cerr << "[" << role << "] error: " << e.what() << std::endl;
        return 1;
    }
}

int runHandoverTest()
{
    std::cout << "\n=== Running Handover (Secrecy Forwarding) Simulation Test ===\n" << std::endl;

    enum class LinkType { Radio, HttpsToEsa, HttpsToRsu, InterRsu };
    struct SimPacket {
        LinkType link;
        std::string target;
        BootstrapMsg msg;
    };
    std::deque<SimPacket> queue;

    ExternalSecurityAgent esa("esa");
    esa.registerRsu("rsu[0]", "rsu0-session");
    esa.registerRsu("rsu[1]", "rsu1-session");

    BootstrapService::Config cfgRsu1;
    cfgRsu1.name = "rsu[0]";
    cfgRsu1.role = BootstrapService::Role::Rsu;
    cfgRsu1.seed = 2;
    BootstrapService rsu1(cfgRsu1);
    rsu1.setEsaPublicKey(esa.publicKey());

    BootstrapService::Config cfgRsu2;
    cfgRsu2.name = "rsu[1]";
    cfgRsu2.role = BootstrapService::Role::Rsu;
    cfgRsu2.seed = 3;
    BootstrapService rsu2(cfgRsu2);
    rsu2.setEsaPublicKey(esa.publicKey());

    BootstrapService::Config cfgVeh;
    cfgVeh.name = "node[0]";
    cfgVeh.role = BootstrapService::Role::Vehicle;
    cfgVeh.seed = 1;
    BootstrapService vehicle(cfgVeh);

    // Wire simulated in-memory transports
    BootstrapService::Transport tVeh;
    tVeh.radio = [&](const BootstrapMsg& m) { queue.push_back({ LinkType::Radio, m.getDestination(), m }); };
    vehicle.setTransport(tVeh);

    BootstrapService::Transport tRsu1;
    tRsu1.radio = [&](const BootstrapMsg& m) { queue.push_back({ LinkType::Radio, m.getDestination(), m }); };
    tRsu1.https = [&](const BootstrapMsg& m) {
        if (m.getDestination() == "esa") {
            queue.push_back({ LinkType::HttpsToEsa, "esa", m });
        } else {
            queue.push_back({ LinkType::InterRsu, m.getDestination(), m });
        }
    };
    rsu1.setTransport(tRsu1);

    BootstrapService::Transport tRsu2;
    tRsu2.radio = [&](const BootstrapMsg& m) { queue.push_back({ LinkType::Radio, m.getDestination(), m }); };
    tRsu2.https = [&](const BootstrapMsg& m) {
        if (m.getDestination() == "esa") {
            queue.push_back({ LinkType::HttpsToEsa, "esa", m });
        } else {
            queue.push_back({ LinkType::InterRsu, m.getDestination(), m });
        }
    };
    rsu2.setTransport(tRsu2);

    esa.setTransport([&](const BootstrapMsg& m) {
        queue.push_back({ LinkType::HttpsToRsu, m.getDestination(), m });
    });

    bool vehBootstrapCompleted = false;
    bool rsu1BootstrapCompleted = false;
    BootstrapResult vehBootstrapResult;
    BootstrapResult rsu1BootstrapResult;

    initBootstrap(vehicle, [&](const BootstrapResult& res) {
        vehBootstrapCompleted = true;
        vehBootstrapResult = res;
        std::cout << "[HANDOVER-TEST] Phase 1: Initial bootstrap completed on vehicle with " << res.rsu << std::endl;
    });

    rsu1.onCompleted([&](const BootstrapResult& res) {
        rsu1BootstrapCompleted = true;
        rsu1BootstrapResult = res;
        std::cout << "[HANDOVER-TEST] Phase 1: Initial bootstrap completed on RSU " << res.rsu << " for " << res.vehicle << std::endl;
    });

    // 1. Run initial bootstrap phase
    size_t steps = 0;
    while ((!vehBootstrapCompleted || !rsu1BootstrapCompleted) && !queue.empty() && steps < 50) {
        ++steps;
        SimPacket p = std::move(queue.front());
        queue.pop_front();
        if (p.link == LinkType::Radio) {
            if (p.msg.getSender() != "node[0]") vehicle.indicate(p.msg);
            if (p.msg.getSender() != "rsu[0]") rsu1.indicate(p.msg);
        } else if (p.link == LinkType::HttpsToEsa) {
            esa.handleMessage(p.msg);
        } else if (p.link == LinkType::HttpsToRsu) {
            if (p.target == "rsu[0]") rsu1.handleHttps(p.msg);
            else if (p.target == "rsu[1]") rsu2.handleHttps(p.msg);
        }
    }

    // Drain any remaining bootstrap messages (e.g. Active_03 from ESA)
    while (!queue.empty() && steps < 60) {
        ++steps;
        SimPacket p = std::move(queue.front());
        queue.pop_front();
        if (p.link == LinkType::Radio) {
            if (p.msg.getSender() != "node[0]") vehicle.indicate(p.msg);
            if (p.msg.getSender() != "rsu[0]") rsu1.indicate(p.msg);
        } else if (p.link == LinkType::HttpsToEsa) {
            esa.handleMessage(p.msg);
        } else if (p.link == LinkType::HttpsToRsu) {
            if (p.target == "rsu[0]") rsu1.handleHttps(p.msg);
            else if (p.target == "rsu[1]") rsu2.handleHttps(p.msg);
        }
    }

    if (!vehBootstrapCompleted || !rsu1BootstrapCompleted) {
        std::cerr << "[HANDOVER-TEST] Initial bootstrap failed." << std::endl;
        return 1;
    }

    // 2. Initialize dedicated HandoverService instances
    std::cout << "\n[HANDOVER-TEST] Phase 2: Initializing HandoverService (decoupled from bootstrap)..." << std::endl;

    HandoverService::Config cfgVehH;
    cfgVehH.name = "node[0]";
    cfgVehH.role = HandoverService::Role::Vehicle;
    HandoverService vehHandover(cfgVehH);
    vehHandover.initVehicle(vehBootstrapResult);

    HandoverService::Config cfgRsu1H;
    cfgRsu1H.name = "rsu[0]";
    cfgRsu1H.role = HandoverService::Role::Rsu;
    cfgRsu1H.groupKey = rsu1.groupKey();
    HandoverService rsu1Handover(cfgRsu1H);
    rsu1Handover.registerVehicle("node[0]", rsu1BootstrapResult.kDg, rsu1BootstrapResult.vehiclePublicKey);

    HandoverService::Config cfgRsu2H;
    cfgRsu2H.name = "rsu[1]";
    cfgRsu2H.role = HandoverService::Role::Rsu;
    cfgRsu2H.groupKey = rsu2.groupKey();
    HandoverService rsu2Handover(cfgRsu2H);

    HandoverService::Transport tVehH;
    tVehH.radio = [&](const BootstrapMsg& m) { queue.push_back({ LinkType::Radio, m.getDestination(), m }); };
    vehHandover.setTransport(tVehH);

    HandoverService::Transport tRsu1H;
    tRsu1H.radio = [&](const BootstrapMsg& m) { queue.push_back({ LinkType::Radio, m.getDestination(), m }); };
    tRsu1H.https = [&](const BootstrapMsg& m) { queue.push_back({ LinkType::InterRsu, m.getDestination(), m }); };
    rsu1Handover.setTransport(tRsu1H);

    HandoverService::Transport tRsu2H;
    tRsu2H.radio = [&](const BootstrapMsg& m) { queue.push_back({ LinkType::Radio, m.getDestination(), m }); };
    tRsu2H.https = [&](const BootstrapMsg& m) { queue.push_back({ LinkType::InterRsu, m.getDestination(), m }); };
    rsu2Handover.setTransport(tRsu2H);

    bool handoverCompleted = false;
    std::string currentRsu = "none";
    Bytes finalVehKdg;
    Bytes finalTargetRsuKdg;

    vehHandover.onCompleted([&](const HandoverResult& res) {
        handoverCompleted = true;
        currentRsu = res.targetRsu;
        finalVehKdg = res.newKdg;
        std::cout << "[HANDOVER-TEST] Handover completed on vehicle with target RSU " << res.targetRsu << std::endl;
    });

    rsu2Handover.onCompleted([&](const HandoverResult& res) {
        finalTargetRsuKdg = res.newKdg;
        std::cout << "[HANDOVER-TEST] Handover completed on target RSU " << res.targetRsu << " for " << res.vehicle << std::endl;
    });

    // 3. Trigger handover from rsu[0] to rsu[1]
    std::cout << "[HANDOVER-TEST] Triggering Handover via rsu1Handover.triggerHandover(\"node[0]\", \"rsu[1]\")..." << std::endl;
    rsu1Handover.triggerHandover("node[0]", "rsu[1]");

    steps = 0;
    while (!handoverCompleted && !queue.empty() && steps < 50) {
        ++steps;
        SimPacket p = std::move(queue.front());
        queue.pop_front();
        if (p.link == LinkType::Radio) {
            if (p.msg.getSender() != "node[0]") vehHandover.indicate(p.msg);
            if (p.msg.getSender() != "rsu[1]") rsu2Handover.indicate(p.msg);
        } else if (p.link == LinkType::InterRsu) {
            if (p.target == "rsu[1]") rsu2Handover.handleHttps(p.msg);
        }
    }

    if (handoverCompleted && currentRsu == "rsu[1]" && !finalVehKdg.empty() && finalVehKdg == finalTargetRsuKdg) {
        std::cout << "\n[HANDOVER-TEST] SUCCESS: Handover Secrecy Forwarding verified end-to-end." << std::endl;
        return 0;
    } else {
        std::cerr << "\n[HANDOVER-TEST] FAILED: Handover did not complete successfully (currentRsu=" << currentRsu << ")" << std::endl;
        return 1;
    }
}

int runFullNetworkHandoverTest()
{
    std::cout << "\n========================================================================\n"
              << "   FULL END-TO-END NETWORK + SECRECY FORWARDING HANDOVER TEST\n"
              << "   (Bootstrap + SmartData + Cloud TLS + Handover + Forward Secrecy)\n"
              << "========================================================================\n" << std::endl;

    // 1. Start live HTTPS Cloud Server with self-signed certificate and TLS
    const std::string certFile = "network_handover_cloud.crt";
    uint16_t cloudPort = 8443;
    std::unique_ptr<HttpsServer> cloudServer;
    for (uint16_t p = 8443; p <= 8460; ++p) {
        try {
            cloudServer = std::make_unique<HttpsServer>(kCloudAddress, p, certFile);
            cloudPort = p;
            break;
        } catch (...) {
            // port busy, try next
        }
    }
    if (!cloudServer) {
        std::cerr << "[TEST-FAILED] Cannot bind HttpsServer on ports 8443..8460" << std::endl;
        return 1;
    }

    struct CloudRecord {
        std::string gateway;
        std::string vehicle;
        std::string body;
    };
    std::mutex cloudMutex;
    std::vector<CloudRecord> cloudRecords;
    std::atomic<bool> stopCloud{ false };

    std::thread cloudThread([&] {
        cloudServer->serve(
            [&](const HttpRequest& req, const std::string&) -> HttpResponse {
                HttpResponse res;
                if (req.method == "POST" && req.path == kSmartDataPath) {
                    std::lock_guard<std::mutex> lock(cloudMutex);
                    std::string gw = req.headers.count("x-gateway") ? req.headers.at("x-gateway") : "";
                    std::string veh = req.headers.count("x-vehicle") ? req.headers.at("x-vehicle") : "";
                    cloudRecords.push_back({ gw, veh, req.body });
                    res.status = 200;
                    res.reason = "OK";
                    res.body = "{\"status\":\"stored\"}";
                } else {
                    res.status = 404;
                    res.reason = "Not Found";
                }
                return res;
            },
            [](const std::string&, const std::string&) {},
            [&] { return stopCloud.load(); }
        );
    });

    auto cleanupCloud = [&]() {
        stopCloud = true;
        try {
            HttpsClient unblocker(kCloudAddress, cloudPort, certFile);
            unblocker.connect();
        } catch (...) {}
        if (cloudThread.joinable()) {
            cloudThread.join();
        }
        std::remove(certFile.c_str());
    };

    enum class LinkType { Radio, HttpsToEsa, HttpsToRsu, InterRsu };
    struct SimPacket {
        LinkType link;
        std::string target;
        BootstrapMsg msg;
    };
    std::deque<SimPacket> queue;

    // 2. Initialize ESA
    ExternalSecurityAgent esa("esa");
    esa.registerRsu("rsu[0]", "rsu0-session");
    esa.registerRsu("rsu[1]", "rsu1-session");
    esa.setTransport([&](const BootstrapMsg& m) {
        queue.push_back({ LinkType::HttpsToRsu, m.getDestination(), m });
    });

    // 3. Initialize Source RSU (rsu[0]) and Target RSU (rsu[1])
    BootstrapService::Config cfgRsu1;
    cfgRsu1.name = "rsu[0]";
    cfgRsu1.role = BootstrapService::Role::Rsu;
    cfgRsu1.seed = 2;
    BootstrapService rsu1(cfgRsu1);
    rsu1.setEsaPublicKey(esa.publicKey());

    BootstrapService::Transport tRsu1;
    tRsu1.radio = [&](const BootstrapMsg& m) { queue.push_back({ LinkType::Radio, m.getDestination(), m }); };
    tRsu1.https = [&](const BootstrapMsg& m) {
        if (m.getDestination() == "esa") {
            queue.push_back({ LinkType::HttpsToEsa, "esa", m });
        } else {
            queue.push_back({ LinkType::InterRsu, m.getDestination(), m });
        }
    };
    rsu1.setTransport(tRsu1);

    BootstrapService::Config cfgRsu2;
    cfgRsu2.name = "rsu[1]";
    cfgRsu2.role = BootstrapService::Role::Rsu;
    cfgRsu2.seed = 3;
    BootstrapService rsu2(cfgRsu2);
    rsu2.setEsaPublicKey(esa.publicKey());

    BootstrapService::Transport tRsu2;
    tRsu2.radio = [&](const BootstrapMsg& m) { queue.push_back({ LinkType::Radio, m.getDestination(), m }); };
    tRsu2.https = [&](const BootstrapMsg& m) {
        if (m.getDestination() == "esa") {
            queue.push_back({ LinkType::HttpsToEsa, "esa", m });
        } else {
            queue.push_back({ LinkType::InterRsu, m.getDestination(), m });
        }
    };
    rsu2.setTransport(tRsu2);

    // 4. Initialize Vehicle (node[0])
    BootstrapService::Config cfgVeh;
    cfgVeh.name = "node[0]";
    cfgVeh.role = BootstrapService::Role::Vehicle;
    cfgVeh.seed = 1;
    BootstrapService vehicle(cfgVeh);

    BootstrapService::Transport tVeh;
    tVeh.radio = [&](const BootstrapMsg& m) { queue.push_back({ LinkType::Radio, m.getDestination(), m }); };
    vehicle.setTransport(tVeh);

    // =========================================================================
    // PHASE 1: Initial Bootstrap
    // =========================================================================
    std::cout << "[PHASE 1] Starting initial bootstrap (node[0] <-> rsu[0] <-> esa)..." << std::endl;
    bool vehBootstrapDone = false;
    bool rsu1BootstrapDone = false;
    BootstrapResult vehBootstrapResult;
    BootstrapResult rsu1BootstrapResult;

    initBootstrap(vehicle, [&](const BootstrapResult& res) {
        vehBootstrapDone = true;
        vehBootstrapResult = res;
    });
    rsu1.onCompleted([&](const BootstrapResult& res) {
        rsu1BootstrapDone = true;
        rsu1BootstrapResult = res;
    });

    size_t steps = 0;
    while ((!vehBootstrapDone || !rsu1BootstrapDone) && !queue.empty() && steps < 60) {
        ++steps;
        SimPacket p = std::move(queue.front());
        queue.pop_front();
        if (p.link == LinkType::Radio) {
            if (p.msg.getSender() != "node[0]") vehicle.indicate(p.msg);
            if (p.msg.getSender() != "rsu[0]") rsu1.indicate(p.msg);
        } else if (p.link == LinkType::HttpsToEsa) {
            esa.handleMessage(p.msg);
        } else if (p.link == LinkType::HttpsToRsu) {
            if (p.target == "rsu[0]") rsu1.handleHttps(p.msg);
            else if (p.target == "rsu[1]") rsu2.handleHttps(p.msg);
        }
    }
    while (!queue.empty() && steps < 80) {
        ++steps;
        SimPacket p = std::move(queue.front());
        queue.pop_front();
        if (p.link == LinkType::Radio) {
            if (p.msg.getSender() != "node[0]") vehicle.indicate(p.msg);
            if (p.msg.getSender() != "rsu[0]") rsu1.indicate(p.msg);
        } else if (p.link == LinkType::HttpsToEsa) {
            esa.handleMessage(p.msg);
        } else if (p.link == LinkType::HttpsToRsu) {
            if (p.target == "rsu[0]") rsu1.handleHttps(p.msg);
            else if (p.target == "rsu[1]") rsu2.handleHttps(p.msg);
        }
    }

    if (!vehBootstrapDone || !rsu1BootstrapDone) {
        std::cerr << "[TEST-FAILED] Phase 1: Initial bootstrap failed!" << std::endl;
        cleanupCloud();
        return 1;
    }
    std::cout << "[PHASE 1] Initial bootstrap SUCCESSFUL. Keys established: K_dg="
              << toHex(vehBootstrapResult.kDg.data(), 8) << "... K_g="
              << toHex(vehBootstrapResult.kG.data(), 8) << "..." << std::endl;

    // =========================================================================
    // PHASE 2: Pre-Handover SmartData transmission to rsu[0] and Cloud HTTPS POST
    // =========================================================================
    std::cout << "\n[PHASE 2] Pre-Handover SmartData (node[0] -> rsu[0] -> Cloud HTTPS)..." << std::endl;
    const int64_t tNow1 = SimTime::now().ns();
    SmartData sd1;
    sd1.location = 4242;
    sd1.timing = static_cast<uint64_t>(tNow1);
    sd1.metadata = 1;
    sd1.value = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    sd1.authD = vehBootstrapResult.authD;

    const DataMessage dm1 = sealSmartData(sd1, vehBootstrapResult.kG, vehBootstrapResult.kDg, tNow1);
    const Bytes packet1 = packDataMessage(dm1);

    const DataMessage rsuDm1 = unpackDataMessage(packet1);
    const uint64_t slot1 = dataOtpSlot(tNow1);
    const Block candidateOtp1 = dataOtp(rsu1BootstrapResult.kDg, rsuDm1.authD, slot1, rsuDm1.sealedData);
    if (CRYPTO_memcmp(candidateOtp1.data(), rsuDm1.otp.data(), 16) != 0) {
        std::cerr << "[TEST-FAILED] Phase 2: RSU 0 failed to verify pre-handover SmartData OTP!" << std::endl;
        cleanupCloud();
        return 1;
    }
    const auto plain1 = aesGcmDecrypt(rsu1.groupKey(), rsuDm1.sealedData);
    if (!plain1) {
        std::cerr << "[TEST-FAILED] Phase 2: RSU 0 failed to decrypt pre-handover SmartData!" << std::endl;
        cleanupCloud();
        return 1;
    }
    const SmartData unsealedSd1 = unpackSmartData(*plain1);

    std::string json1 = "{\"Location\":" + std::to_string(unsealedSd1.location)
        + ",\"Timing\":" + std::to_string(unsealedSd1.timing)
        + ",\"Metadata\":" + std::to_string(unsealedSd1.metadata)
        + ",\"ValueBytes\":" + std::to_string(unsealedSd1.value.size())
        + ",\"Trust\":\"" + toHex(unsealedSd1.authD.data(), unsealedSd1.authD.size()) + "\"}";
    Bytes jsonBytes1(json1.begin(), json1.end());

    {
        HttpsClient client1(kCloudAddress, cloudPort, certFile);
        client1.connect();
        HttpResponse resp1 = client1.post(kSmartDataPath, "application/json", jsonBytes1,
            { { "x-gateway", "rsu[0]" }, { "x-vehicle", "node[0]" }, { "connection", "close" } });
        if (resp1.status != 200) {
            std::cerr << "[TEST-FAILED] Phase 2: Cloud returned status " << resp1.status << std::endl;
            cleanupCloud();
            return 1;
        }
    }
    std::cout << "[PHASE 2] Pre-Handover SmartData verified and POSTed to Cloud (Status: 200 OK)." << std::endl;

    // =========================================================================
    // PHASE 3: Secrecy Forwarding Handover from rsu[0] to rsu[1]
    // =========================================================================
    std::cout << "\n[PHASE 3] Triggering Handover & Secrecy Forwarding (rsu[0] -> rsu[1])..." << std::endl;
    HandoverService::Config cfgVehH;
    cfgVehH.name = "node[0]";
    cfgVehH.role = HandoverService::Role::Vehicle;
    HandoverService vehHandover(cfgVehH);
    vehHandover.initVehicle(vehBootstrapResult);

    HandoverService::Config cfgRsu1H;
    cfgRsu1H.name = "rsu[0]";
    cfgRsu1H.role = HandoverService::Role::Rsu;
    cfgRsu1H.groupKey = rsu1.groupKey();
    HandoverService rsu1Handover(cfgRsu1H);
    rsu1Handover.registerVehicle("node[0]", rsu1BootstrapResult.kDg, rsu1BootstrapResult.vehiclePublicKey);

    HandoverService::Config cfgRsu2H;
    cfgRsu2H.name = "rsu[1]";
    cfgRsu2H.role = HandoverService::Role::Rsu;
    cfgRsu2H.groupKey = rsu2.groupKey();
    HandoverService rsu2Handover(cfgRsu2H);

    HandoverService::Transport tVehH;
    tVehH.radio = [&](const BootstrapMsg& m) { queue.push_back({ LinkType::Radio, m.getDestination(), m }); };
    vehHandover.setTransport(tVehH);

    HandoverService::Transport tRsu1H;
    tRsu1H.radio = [&](const BootstrapMsg& m) { queue.push_back({ LinkType::Radio, m.getDestination(), m }); };
    tRsu1H.https = [&](const BootstrapMsg& m) { queue.push_back({ LinkType::InterRsu, m.getDestination(), m }); };
    rsu1Handover.setTransport(tRsu1H);

    HandoverService::Transport tRsu2H;
    tRsu2H.radio = [&](const BootstrapMsg& m) { queue.push_back({ LinkType::Radio, m.getDestination(), m }); };
    tRsu2H.https = [&](const BootstrapMsg& m) { queue.push_back({ LinkType::InterRsu, m.getDestination(), m }); };
    rsu2Handover.setTransport(tRsu2H);

    bool handoverDone = false;
    HandoverResult vehHandoverResult;
    HandoverResult rsu2HandoverResult;

    vehHandover.onCompleted([&](const HandoverResult& res) {
        handoverDone = true;
        vehHandoverResult = res;
    });
    rsu2Handover.onCompleted([&](const HandoverResult& res) {
        rsu2HandoverResult = res;
    });

    rsu1Handover.triggerHandover("node[0]", "rsu[1]");

    steps = 0;
    while (!handoverDone && !queue.empty() && steps < 50) {
        ++steps;
        SimPacket p = std::move(queue.front());
        queue.pop_front();
        if (p.link == LinkType::Radio) {
            if (p.msg.getSender() != "node[0]") vehHandover.indicate(p.msg);
            if (p.msg.getSender() != "rsu[1]") rsu2Handover.indicate(p.msg);
        } else if (p.link == LinkType::InterRsu) {
            if (p.target == "rsu[1]") rsu2Handover.handleHttps(p.msg);
        }
    }

    if (!handoverDone || vehHandoverResult.targetRsu != "rsu[1]") {
        std::cerr << "[TEST-FAILED] Phase 3: Handover protocol did not complete!" << std::endl;
        cleanupCloud();
        return 1;
    }
    if (vehHandoverResult.newKdg != rsu2HandoverResult.newKdg) {
        std::cerr << "[TEST-FAILED] Phase 3: Key mismatch between vehicle and target RSU!" << std::endl;
        cleanupCloud();
        return 1;
    }
    std::cout << "[PHASE 3] Handover SUCCESSFUL. Transitioned to target RSU rsu[1]. New forward-secret KT_i="
              << toHex(vehHandoverResult.newKdg.data(), 8) << "... New K_g="
              << toHex(vehHandoverResult.newKg.data(), 8) << "..." << std::endl;

    // =========================================================================
    // PHASE 4: Post-Handover SmartData (node[0] -> rsu[1] -> Cloud HTTPS)
    // =========================================================================
    std::cout << "\n[PHASE 4] Post-Handover SmartData (node[0] -> rsu[1] -> Cloud HTTPS)..." << std::endl;
    const int64_t tNow2 = SimTime::now().ns();
    SmartData sd2;
    sd2.location = 5353;
    sd2.timing = static_cast<uint64_t>(tNow2);
    sd2.metadata = 2;
    sd2.value = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    sd2.authD = vehBootstrapResult.authD;

    const DataMessage dm2 = sealSmartData(sd2, vehHandoverResult.newKg, vehHandoverResult.newKdg, tNow2);
    const Bytes packet2 = packDataMessage(dm2);

    const DataMessage rsuDm2 = unpackDataMessage(packet2);
    const uint64_t slot2 = dataOtpSlot(tNow2);
    const Block candidateOtp2 = dataOtp(rsu2HandoverResult.newKdg, rsuDm2.authD, slot2, rsuDm2.sealedData);
    if (CRYPTO_memcmp(candidateOtp2.data(), rsuDm2.otp.data(), 16) != 0) {
        std::cerr << "[TEST-FAILED] Phase 4: Target RSU 1 failed to verify post-handover OTP with KT_i!" << std::endl;
        cleanupCloud();
        return 1;
    }
    const auto plain2 = aesGcmDecrypt(rsu2Handover.groupKey(), rsuDm2.sealedData);
    if (!plain2) {
        std::cerr << "[TEST-FAILED] Phase 4: Target RSU 1 failed to decrypt post-handover SmartData!" << std::endl;
        cleanupCloud();
        return 1;
    }
    const SmartData unsealedSd2 = unpackSmartData(*plain2);

    std::string json2 = "{\"Location\":" + std::to_string(unsealedSd2.location)
        + ",\"Timing\":" + std::to_string(unsealedSd2.timing)
        + ",\"Metadata\":" + std::to_string(unsealedSd2.metadata)
        + ",\"ValueBytes\":" + std::to_string(unsealedSd2.value.size())
        + ",\"Trust\":\"" + toHex(unsealedSd2.authD.data(), unsealedSd2.authD.size()) + "\"}";
    Bytes jsonBytes2(json2.begin(), json2.end());

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    {
        HttpsClient client2(kCloudAddress, cloudPort, certFile);
        client2.connect();
        HttpResponse resp2 = client2.post(kSmartDataPath, "application/json", jsonBytes2,
            { { "x-gateway", "rsu[1]" }, { "x-vehicle", "node[0]" }, { "connection", "close" } });
        if (resp2.status != 200) {
            std::cerr << "[TEST-FAILED] Phase 4: Cloud returned status " << resp2.status << " for target RSU!" << std::endl;
            cleanupCloud();
            return 1;
        }
    }
    std::cout << "[PHASE 4] Post-Handover SmartData successfully received and POSTed to Cloud by rsu[1]." << std::endl;

    // =========================================================================
    // PHASE 5: Cryptographic Security & Forward Secrecy Assertions
    // =========================================================================
    std::cout << "\n[PHASE 5] Cryptographic Assertions & Attack Resilience Verifications..." << std::endl;

    // 1. Forward Secrecy: KT_i != K_dg1
    if (vehHandoverResult.newKdg == vehBootstrapResult.kDg) {
        std::cerr << "[TEST-FAILED] Forward Secrecy VIOLATION: KT_i is identical to bootstrap K_dg!" << std::endl;
        cleanupCloud();
        return 1;
    }
    std::cout << "  [OK] Forward Secrecy: KT_i != K_dg1 (compromise of old RSU cannot decrypt new session)" << std::endl;

    // 2. Key Revocation: Old group key K_G1 cannot decrypt post-handover data
    const auto badPlain = aesGcmDecrypt(vehBootstrapResult.kG, rsuDm2.sealedData);
    if (badPlain.has_value()) {
        std::cerr << "[TEST-FAILED] Security VIOLATION: Old group key decrypted new SmartData!" << std::endl;
        cleanupCloud();
        return 1;
    }
    std::cout << "  [OK] Key Revocation: Old group key K_G1 fails to decrypt post-handover data" << std::endl;

    // 3. Cloud Audit: verify 2 distinct records
    {
        std::lock_guard<std::mutex> lock(cloudMutex);
        if (cloudRecords.size() != 2) {
            std::cerr << "[TEST-FAILED] Cloud record count expected 2, got " << cloudRecords.size() << std::endl;
            cleanupCloud();
            return 1;
        }
        if (cloudRecords[0].gateway != "rsu[0]" || cloudRecords[1].gateway != "rsu[1]") {
            std::cerr << "[TEST-FAILED] Gateways logged to cloud mismatch!" << std::endl;
            cleanupCloud();
            return 1;
        }
        std::cout << "  [OK] Cloud Audit: Verified 2 SmartData POSTs received (1 from rsu[0], 1 from rsu[1])" << std::endl;
    }

    cleanupCloud();
    std::cout << "\n========================================================================\n"
              << "   ALL VERIFICATIONS PASSED: FULL NETWORK + HANDOVER TEST OK\n"
              << "========================================================================\n" << std::endl;
    return 0;
}


