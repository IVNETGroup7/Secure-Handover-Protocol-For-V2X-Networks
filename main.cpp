#include "Bootstrap.h"
#include "BootstrapMsg.h"
#include "BootstrapService.h"
#include "ExternalSecurityAgent.h"
#include "Https.h"
#include "Link.h"
#include "RawSocket.h"
#include "SimTime.h"
#include "SmartData.h"
#include "Trace.h"
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <fstream>
#include <csignal>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace
{

volatile std::sig_atomic_t gStop = 0;   // SIGINT / SIGTERM: servers leave their loop

void onStopSignal(int)
{
    gStop = 1;
}

// --key value options after the role
class Options
{
    public:
        Options(int argc, char** argv, int first)
        {
            for (int i = first; i < argc; ++i) {
                const std::string key = argv[i];
                if (key.rfind("--", 0) != 0) {
                    throw std::runtime_error("unexpected argument '" + key + "'");
                }
                if (i + 1 >= argc) {
                    throw std::runtime_error("missing value for " + key);
                }
                mValues[key] = argv[++i];
            }
        }

        std::string get(const std::string& key, const std::string& fallback) const
        {
            auto value = mValues.find(key);
            return value != mValues.end() ? value->second : fallback;
        }

    private:
        std::map<std::string, std::string> mValues;
};

// fork mode: tells the parent this node is ready (internal --ready-fd)
void signalReady(const Options& options)
{
    ::signalReady(std::stoi(options.get("--ready-fd", "-1")));
}

// ---------------------------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------------------------

// "32,1024,65535": the sizes of the SmartData values
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

// after the bootstrap, the vehicle as an OBU (tee.pdf step 6): SmartData to its RSU over the radio, one packet
// per size in "sizes", "count" rounds, one packet every "interval" (the first one too: the RSU ends its part of
// the bootstrap first). The first round is printed, the others only counted. t of OTP_dt: this process's clock
// (the PTP-synchronized one when --clock-offset is 0, as in fork mode)
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

    // the protocol is reactive: just deliver what arrives until the bootstrap ends (or gives up)
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

// ---------------------------------------------------------------------------------------------

// what the cloud prints of a body: the text itself, or its size and first bytes in hex
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

// the cloud of Fig. 5: an HTTPS server that receives the marshaled SmartData (POST /smartdata), as the RSU's
// enclave made it: HTTPS Header | AES(K_eg, JSON). Its key X_c and certificate CY_c are fresh per run; the
// certificate goes to --cert-out, which the RSU is configured with (its enclave pins it). Each session key Y_s
// of the header gives K_eg = SHA256(ECDH(X_c, Y_s)) (common/SmartData.h), which opens the body.
// The first request of each size is printed, the others only counted
int runCloud(const Options& options)
{
    const std::string address = options.get("--address", kCloudAddress);
    const auto port = static_cast<uint16_t>(std::stoi(options.get("--port", std::to_string(kCloudPort))));
    const std::string certificate = options.get("--cert-out", "cloud.crt");

    const CloudIdentity identity = newCloudIdentity(address);
    {
        std::ofstream file(certificate);
        file << identity.pem();
        if (!file) {
            throw std::runtime_error("cannot write " + certificate);
        }
    }
    HttpsServer server(address, port, identity);
    std::cout << "[cloud] HTTPS on " << address << ":" << port << ", self-signed P-256 certificate CY_c in "
        << certificate << std::endl;
    signalReady(options);

    struct Session
    {
        int number;
        Bytes kEg;
    };
    std::map<std::string, Session> sessions; // Y_s (base64) -> its K_eg
    std::map<size_t, int> posts;             // body size -> requests
    int total = 0, refused = 0;
    server.serve(
        [&](const HttpRequest& request, const std::string& peer) {
            HttpResponse response;
            if (request.method != "POST" || request.path != kSmartDataPath) {
                response.status = 404;
                response.reason = "Not Found";
                response.body = R"({"error":"no such resource"})";
                return response;
            }
            auto header = [&](const std::string& name) {
                std::string lower = name;
                std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });
                auto value = request.headers.find(lower);
                return value != request.headers.end() ? value->second : std::string();
            };
            auto refuse = [&](const std::string& why) {
                ++refused;
                trace::check("cloud", false, "POST " + request.path + " from " + peer + ": " + why);
                response.status = 400;
                response.reason = "Bad Request";
                response.body = R"({"error":")" + why + R"("})";
                return response;
            };
            const bool traced = posts[request.body.size()]++ == 0;
            ++total;
            if (traced) {
                trace::step("cloud", "store SmartData", "POST " + request.path, header("X-Gateway"),
                    header("X-Vehicle"));
                trace::detail("cloud", "from " + peer + ", " + std::to_string(request.body.size()) + " B, "
                    + header("Content-Type") + ", " + header("X-Encrypted"));
            }

            // K_eg of this session: SHA256(ECDH(X_c, Y_s)), derived once per Y_s
            const std::string ys = header(kSessionKeyHeader);
            auto session = sessions.find(ys);
            if (session == sessions.end()) {
                const auto der = base64Decode(ys);
                if (ys.empty() || !der) {
                    return refuse(std::string("no session key (") + kSessionKeyHeader + ")");
                }
                try {
                    const auto peerKey = publicKeyFromDer(*der);
                    const int number = static_cast<int>(sessions.size()) + 1;
                    session = sessions.emplace(ys, Session{ number, computeKEg(identity.key.get(), peerKey.get()) }).first;
                } catch (const std::exception& e) {
                    return refuse(std::string("bad session key: ") + e.what());
                }
                trace::detail("cloud", "HTTPS session #" + std::to_string(session->second.number) + ": Y_s = "
                    + ys.substr(36, 16) + "..., K_eg = SHA256(ECDH(X_c, Y_s))");
            }

            const auto json = aesGcmDecrypt(session->second.kEg, Bytes(request.body.begin(), request.body.end()));
            if (!json) {
                return refuse("AES(K_eg, JSON) does not decrypt with the K_eg of its session");
            }
            if (traced) {
                trace::check("cloud", true, "AES(K_eg, JSON) decrypts with the K_eg of session #"
                    + std::to_string(session->second.number) + " (GCM tag valid)");
                trace::detail("cloud", "JSON = " + preview(std::string(json->begin(), json->end())));
            }
            response.body = R"({"status":"stored"})";
            return response;
        },
        [](const std::string& peer, const std::string& session) {
            trace::detail("cloud", "TLS transport from " + peer + ": " + session);
        },
        [] { return gStop != 0; });

    std::cout << "[cloud] " << total << " SmartData POST(s) received, " << total - refused << " stored, "
        << sessions.size() << " HTTPS session key(s) K_eg" << std::endl;
    return 0;
}

// ---------------------------------------------------------------------------------------------

int run(const std::string& role, const Options& options)
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

// fork mode: one node in a child process; its stdout and stderr come back through "out"
struct Child
{
    std::string label;      // shown in the separators ("esa", "rsu[0]", "node[0]")
    pid_t pid = -1;         // -1: not started, or already reaped
    int out = -1;           // read end of its output (-1 once closed)
    std::string pending;    // output after the last newline
    int code = 1;           // exit code
};

// runs "role" in a child; with waitReady, returns only once the child is ready (or has failed: pid -1).
// "program": run that executable as the node instead of this one; "extra": more --option value pairs for the node
Child spawn(const std::string& role, const std::string& label, const std::string& iface, bool waitReady,
    const std::string& program = "", const std::vector<std::string>& extra = {})
{
    int out[2];
    int ready[2] = { -1, -1 };
    if (pipe(out) < 0 || (waitReady && pipe(ready) < 0)) {
        throw std::runtime_error("pipe failed");
    }

    std::cout.flush();
    const pid_t pid = fork();
    if (pid < 0) {
        throw std::runtime_error("fork failed");
    }
    if (pid == 0) {
        dup2(out[1], STDOUT_FILENO);
        dup2(out[1], STDERR_FILENO);
        close(out[0]);
        close(out[1]);
        std::vector<std::string> args{ "bootstrap", role, "--iface", iface };
        if (waitReady) {
            close(ready[0]);
            args.insert(args.end(), { "--ready-fd", std::to_string(ready[1]) });
        }
        args.insert(args.end(), extra.begin(), extra.end());
        std::vector<char*> argv;
        for (std::string& arg : args) {
            argv.push_back(arg.data());
        }
        if (!program.empty()) {
            argv[0] = const_cast<char*>(program.c_str());
            argv.push_back(nullptr);
            execv(program.c_str(), argv.data());
            std::cerr << "[" << label << "] error: cannot run " << program << ": " << std::strerror(errno) << std::endl;
            _exit(127);
        }
        const int code = run(role, Options(argv.size(), argv.data(), 2));
        std::cout.flush();
        _exit(code);
    }

    Child child;
    child.label = label;
    child.pid = pid;
    child.out = out[0];
    close(out[1]);

    if (waitReady) {
        close(ready[1]);
        char byte = 0;
        const bool ok = read(ready[0], &byte, 1) == 1; // EOF: the child exited before being ready
        close(ready[0]);
        if (!ok) {
            int status = 0;
            waitpid(pid, &status, 0);
            child.pid = -1;
            child.code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
        }
    }
    return child;
}

// prints the children's lines; "pretty": a bar with the component's name whenever the speaker changes
class Printer
{
    public:
        explicit Printer(bool pretty) : mPretty(pretty) {}

        void line(const Child& from, const std::string& text)
        {
            if (mPretty && &from != mLast) {
                std::cout << (mLast ? "\n" : "") << bar(" " + from.label + " ") << "\n";
            }
            mLast = &from;
            std::cout << text << "\n";
        }

        void end()
        {
            std::cout << "\n";
            if (mPretty) {
                std::cout << bar("") << "\n";
            }
        }

    private:
        static std::string bar(const std::string& title)
        {
            std::string out = "───" + title;
            for (size_t i = title.size(); i < 77; ++i) {
                out += "─";
            }
            return out;
        }

        bool mPretty;
        const Child* mLast = nullptr;
};

// reads what child.out has and prints its complete lines; false on EOF (then prints what is left)
bool relay(Child& child, Printer& printer)
{
    char buffer[4096];
    ssize_t n;
    do {
        n = read(child.out, buffer, sizeof(buffer));
    } while (n < 0 && errno == EINTR);

    if (n > 0) {
        child.pending.append(buffer, n);
    }
    for (size_t newline; (newline = child.pending.find('\n')) != std::string::npos;) {
        printer.line(child, child.pending.substr(0, newline));
        child.pending.erase(0, newline + 1);
    }
    if (n <= 0 && !child.pending.empty()) {
        printer.line(child, child.pending);
        child.pending.clear();
    }
    return n > 0;
}

// what runAll runs (the options of fork mode)
struct Scenario
{
    bool pretty = false;
    std::string rsuProgram;         // --rsu-exec: another program as the RSU (e.g. the SGX gateway)
    std::string cloudCertificate;   // --cloud: start the cloud; its certificate goes there (the RSU trusts it)
    std::string smartdata;          // --smartdata: sizes of the SmartData the vehicle sends after the bootstrap
    std::string smartdataCount = "1";
    std::string smartdataInterval = "20";
};

// everything from one command, on the loopback: no frame is sent before its receiver is listening
int runAll(const Scenario& scenario)
{
    const std::string iface = "lo";
    auto notStarted = [](const std::string& label) { Child child; child.label = label; return child; };
    const bool withCloud = !scenario.cloudCertificate.empty();
    Child cloud = withCloud ? spawn("cloud", "cloud", iface, true, "", { "--cert-out", scenario.cloudCertificate })
        : notStarted("cloud");
    Child esa = !withCloud || cloud.pid > 0 ? spawn("esa", "esa", iface, true) : notStarted("esa");
    std::vector<std::string> rsuExtra;
    if (withCloud && !scenario.rsuProgram.empty()) {
        rsuExtra = { "--cloud-cert", scenario.cloudCertificate };
    }
    Child rsu = esa.pid > 0 ? spawn("rsu", "rsu[0]", iface, true, scenario.rsuProgram, rsuExtra)
        : notStarted("rsu[0]");
    std::vector<std::string> vehicleExtra;
    if (!scenario.smartdata.empty()) {
        vehicleExtra = { "--smartdata", scenario.smartdata, "--smartdata-count", scenario.smartdataCount,
            "--smartdata-interval", scenario.smartdataInterval };
    }
    Child vehicle = rsu.pid > 0 ? spawn("vehicle", "node[0]", iface, false, "", vehicleExtra)
        : notStarted("node[0]");
    std::vector<Child*> children{ &esa, &rsu, &vehicle };
    if (withCloud) {
        children.insert(children.begin(), &cloud);
    }

    // until every output closes: the vehicle leaves on its own, then the servers are stopped
    Printer printer(scenario.pretty);
    auto stopServersAt = std::chrono::steady_clock::time_point::max();
    bool stopped = false;
    while (true) {
        std::vector<pollfd> fds;
        std::vector<Child*> open;
        for (Child* child : children) {
            if (child->out >= 0) {
                fds.push_back({ child->out, POLLIN, 0 });
                open.push_back(child);
            }
        }
        if (fds.empty()) {
            break;
        }
        poll(fds.data(), fds.size(), 50);
        for (size_t i = 0; i < fds.size(); ++i) {
            if ((fds[i].revents & (POLLIN | POLLHUP | POLLERR)) && !relay(*open[i], printer)) {
                close(open[i]->out);
                open[i]->out = -1;
            }
        }

        int status = 0;
        if (vehicle.pid > 0 && waitpid(vehicle.pid, &status, WNOHANG) == vehicle.pid) {
            vehicle.code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
            vehicle.pid = -1;
            // the last messages in flight: the Active_03, the last SmartData (marshaled, then POSTed)
            stopServersAt = std::chrono::steady_clock::now()
                + std::chrono::milliseconds(scenario.smartdata.empty() ? 100 : 500);
        }
        if (vehicle.pid <= 0 && stopServersAt == std::chrono::steady_clock::time_point::max()) {
            stopServersAt = std::chrono::steady_clock::now(); // the vehicle never started
        }
        if (!stopped && (gStop || std::chrono::steady_clock::now() >= stopServersAt)) {
            for (Child* child : children) {
                if (child->pid > 0) {
                    kill(child->pid, SIGTERM);
                }
            }
            stopped = true;
        }
    }

    for (Child* child : children) {
        if (child->pid > 0) {
            int status = 0;
            waitpid(child->pid, &status, 0);
            child->code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
        }
    }

    printer.end();
    std::cout << "bootstrap " << (vehicle.code == 0 ? "OK" : "FAILED") << " (exit codes: vehicle " << vehicle.code
        << ", rsu " << rsu.code << ", esa " << esa.code << (withCloud ? ", cloud " + std::to_string(cloud.code) : "")
        << ")" << std::endl;
    for (const Child* child : { &vehicle, &rsu, &esa, &cloud }) {
        if (child->code != 0 && (child != &cloud || withCloud)) {
            return child->code;
        }
    }
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    struct sigaction action{};
    action.sa_handler = onStopSignal; // no SA_RESTART: poll() returns at once
    sigaction(SIGINT, &action, nullptr);
    sigaction(SIGTERM, &action, nullptr);

    const std::string first = argc >= 2 ? argv[1] : "";
    if (first == "-h" || first == "--help") {
        std::cout << "usage: " << argv[0] << " [--pretty] [--rsu-exec <program>]   (ESA, RSU and vehicle)\n"
            << "         [--cloud <certificate.pem>]      also the cloud (HTTPS); its certificate is written there\n"
            << "         [--smartdata <size,size,...> [--smartdata-count <n>] [--smartdata-interval <ms>]]\n"
            << "                                          after the bootstrap, the vehicle sends SmartData\n"
            << "       " << argv[0] << " esa|rsu|vehicle|cloud [--option value ...]   (one node, see main.cpp)" << std::endl;
        return 0;
    }
    if (argc >= 2 && first.rfind("--", 0) != 0) {
        try {
            return run(first, Options(argc, argv, 2));
        } catch (const std::exception& e) { // bad options
            std::cerr << "error: " << e.what() << std::endl;
            return 1;
        }
    }

    Scenario scenario;
    for (int i = 1; i < argc; ++i) {
        const std::string option = argv[i];
        const bool hasValue = i + 1 < argc;
        if (option == "--rsu-exec" && hasValue) {
            scenario.rsuProgram = argv[++i];
        } else if (option == "--cloud" && hasValue) {
            scenario.cloudCertificate = argv[++i];
        } else if (option == "--smartdata" && hasValue) {
            scenario.smartdata = argv[++i];
        } else if (option == "--smartdata-count" && hasValue) {
            scenario.smartdataCount = argv[++i];
        } else if (option == "--smartdata-interval" && hasValue) {
            scenario.smartdataInterval = argv[++i];
        } else if (option == "--pretty") {
            scenario.pretty = true;
        } else {
            std::cerr << "error: unexpected argument '" << argv[i] << "' (see --help)" << std::endl;
            return 1;
        }
    }
    return runAll(scenario);
}
