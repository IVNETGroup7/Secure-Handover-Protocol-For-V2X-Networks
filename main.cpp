// Secure bootstrap between 3 processes (ESA, RSU, vehicle) over raw Ethernet sockets (needs CAP_NET_RAW)
//
//   ./bootstrap [--pretty | --view [--color]]
//                                forks ESA, RSU and vehicle (in this order) and waits for the vehicle's bootstrap;
//                                --pretty: a bar with the component's name whenever the speaker changes
//                                --view: at the end, the protocol as a sequence diagram (TraceView.h)
//   ./bootstrap esa     [--iface lo]
//   ./bootstrap rsu     [--iface lo] [--name rsu[0]] [--seed 2]
//   ./bootstrap vehicle [--iface lo] [--name node[0]] [--seed 1] [--clock-offset 0] [--timeout 5]
//   (separately: start the ESA, then the RSU, then the vehicles; the servers stop on Ctrl+C)
//
// links (RawSocket.h): every frame is a broadcast, every node on the link gets it
//   radio     (EtherType 0x88B5)  vehicles and RSUs; each one keeps only what is for it (isForMe)
//   backhaul  (EtherType 0x88B6)  RSUs and ESA: the "HTTPS" session, established by Session_Hello/Session_Ack
//
// data of a frame: kind (1) | body
//   Bootstrap      body = serialize(BootstrapMsg)
//   Session_Hello  body = "rsu name\nsession key"  (RSU -> ESA, repeated until the ack)
//   Session_Ack    body = "rsu name\n" CY_e         (ESA -> RSU; CY_e: ESA public key, DER)

#include "Bootstrap.h"
#include "BootstrapMsg.h"
#include "BootstrapService.h"
#include "ExternalSecurityAgent.h"
#include "RawSocket.h"
#include "Trace.h"
#include "TraceView.h"
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{

enum class FrameKind : uint8_t { Bootstrap = 0, Session_Hello = 1, Session_Ack = 2 };

constexpr auto kSessionTimeout = std::chrono::seconds(5);         // RSU: waiting for the ESA's Session_Ack
constexpr auto kSessionRetry = std::chrono::milliseconds(100);    // RSU: Session_Hello period
constexpr int kPollPeriodMs = 100;                                // loops check the stop flag at least this often

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
    const int fd = std::stoi(options.get("--ready-fd", "-1"));
    if (fd >= 0) {
        const char ready = 1;
        if (write(fd, &ready, 1) != 1) {
            throw std::runtime_error("cannot signal readiness");
        }
        close(fd);
    }
}

void sendFrame(RawSocket& link, FrameKind kind, const Bytes& body)
{
    Bytes data{ static_cast<uint8_t>(kind) };
    data.insert(data.end(), body.begin(), body.end());
    link.send(data);
}

void sendMsg(RawSocket& link, const BootstrapMsg& msg)
{
    sendFrame(link, FrameKind::Bootstrap, serialize(msg));
}

Bytes toBytes(const std::string& text)
{
    return Bytes(text.begin(), text.end());
}

// hands every frame waiting on "link" to onFrame(kind, body)
template<typename OnFrame>
void drain(RawSocket& link, OnFrame onFrame)
{
    while (auto data = link.receive()) {
        if (!data->empty()) {
            onFrame(static_cast<FrameKind>((*data)[0]), Bytes(data->begin() + 1, data->end()));
        }
    }
}

// waits until one of the links has a frame (or kPollPeriodMs passes, or a signal arrives)
void waitFor(std::initializer_list<const RawSocket*> links, int timeoutMs = kPollPeriodMs)
{
    std::vector<pollfd> fds;
    for (const RawSocket* link : links) {
        fds.push_back({ link->fd(), POLLIN, 0 });
    }
    poll(fds.data(), fds.size(), timeoutMs);
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

    // HTTPS session with the ESA first: Session_Hello until its Session_Ack
    const auto giveUp = std::chrono::steady_clock::now() + kSessionTimeout;
    for (bool acked = false; !acked;) {
        if (std::chrono::steady_clock::now() >= giveUp || gStop) {
            throw std::runtime_error("no Session_Ack from the ESA (is it running on " + iface + "?)");
        }
        sendFrame(backhaul, FrameKind::Session_Hello, toBytes(rsu.myName() + "\n" + rsu.httpsSessionKey()));
        waitFor({ &backhaul }, std::chrono::duration_cast<std::chrono::milliseconds>(kSessionRetry).count());
        drain(backhaul, [&](FrameKind kind, const Bytes& body) {
            // "rsu name\n" CY_e
            const Bytes name = toBytes(rsu.myName() + "\n");
            if (kind == FrameKind::Session_Ack && body.size() > name.size()
                && std::equal(name.begin(), name.end(), body.begin())) {
                rsu.setEsaPublicKey(Bytes(body.begin() + name.size(), body.end()));
                acked = true;
            }
        });
    }

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

int runVehicle(const Options& options)
{
    BootstrapService::Config config;
    config.name = options.get("--name", "node[0]");
    config.role = BootstrapService::Role::Vehicle;
    config.clockOffset = std::stod(options.get("--clock-offset", "0"));
    config.seed = std::stoul(options.get("--seed", "1"));
    const auto timeout = std::chrono::duration<double>(std::stod(options.get("--timeout", "5")));

    BootstrapService vehicle(config);
    RawSocket radio(options.get("--iface", "lo"), kRadioEtherType);

    BootstrapService::Transport transport;
    transport.radio = [&](const BootstrapMsg& msg) { sendMsg(radio, msg); };
    vehicle.setTransport(transport); // a vehicle has no HTTPS link: "esa" goes over the radio

    bool done = false;
    initBootstrap(vehicle, [&](const BootstrapResult& result) {
        done = true;
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
    return done ? 0 : 1;
}

// ---------------------------------------------------------------------------------------------

int run(const std::string& role, const Options& options)
{
    try {
        if (role == "esa") return runEsa(options);
        if (role == "rsu") return runRsu(options);
        if (role == "vehicle") return runVehicle(options);
        throw std::runtime_error("unknown role '" + role + "' (use esa, rsu or vehicle)");
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

// runs "role" in a child; with waitReady, returns only once the child is ready (or has failed: pid -1)
Child spawn(const std::string& role, const std::string& label, const std::string& iface, bool waitReady)
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
        std::vector<char*> argv;
        for (std::string& arg : args) {
            argv.push_back(arg.data());
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

// prints the children's lines; "pretty": a bar with the component's name whenever the speaker changes;
// with a view, collects them instead and draws the view at the end
class Printer
{
    public:
        explicit Printer(bool pretty, TraceView* view = nullptr) : mPretty(pretty), mView(view) {}

        void line(const Child& from, const std::string& text)
        {
            if (mView) {
                mView->line(from.label, text);
                return;
            }
            if (mPretty && &from != mLast) {
                std::cout << (mLast ? "\n" : "") << bar(" " + from.label + " ") << "\n";
            }
            mLast = &from;
            std::cout << text << "\n";
        }

        void end()
        {
            if (mView) {
                mView->render(std::cout);
            }
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
        TraceView* mView;
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

// everything from one command, on the loopback: no frame is sent before its receiver is listening
int runAll(bool pretty, bool view, bool color)
{
    // view: the children (forked from here) print Trace events, drawn at the end
    TraceView traceView(color);
    if (view) {
        trace::setMode(trace::Mode::Events);
    }

    const std::string iface = "lo";
    Child esa = spawn("esa", "esa", iface, true);
    auto notStarted = [](const std::string& label) { Child child; child.label = label; return child; };
    Child rsu = esa.pid > 0 ? spawn("rsu", "rsu[0]", iface, true) : notStarted("rsu[0]");
    Child vehicle = rsu.pid > 0 ? spawn("vehicle", "node[0]", iface, false) : notStarted("node[0]");
    std::vector<Child*> children{ &esa, &rsu, &vehicle };

    // until every output closes: the vehicle leaves on its own, then the servers are stopped
    Printer printer(pretty, view ? &traceView : nullptr);
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
            stopServersAt = std::chrono::steady_clock::now() + std::chrono::milliseconds(100); // RSU: last Active_03
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
        << ", rsu " << rsu.code << ", esa " << esa.code << ")" << std::endl;
    return vehicle.code != 0 ? vehicle.code : rsu.code != 0 ? rsu.code : esa.code;
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
        std::cout << "usage: " << argv[0] << " [--pretty | --view [--color]]         (ESA, RSU and vehicle)\n"
            << "       " << argv[0] << " esa|rsu|vehicle [--option value ...]   (one node, see main.cpp)" << std::endl;
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

    bool pretty = false;
    bool view = false;
    bool color = false;
    for (int i = 1; i < argc; ++i) {
        const std::string option = argv[i];
        if (option == "--pretty") {
            pretty = true;
        } else if (option == "--view") {
            view = true;
        } else if (option == "--color") {
            color = true;
        } else {
            std::cerr << "error: unexpected argument '" << argv[i] << "' (see --help)" << std::endl;
            return 1;
        }
    }
    return runAll(pretty, view, color);
}
