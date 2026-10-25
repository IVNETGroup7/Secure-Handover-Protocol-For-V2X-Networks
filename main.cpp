#include "NodeRunners.h"
#include "Trace.h"
#include "TraceView.h"
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <csignal>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{

void onStopSignal(int)
{
    gStop = 1;
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
// "program": run that executable as the node instead of this one ("events": it prints Trace events);
// "extra": more --option value pairs for the node
Child spawn(const std::string& role, const std::string& label, const std::string& iface, bool waitReady,
    const std::string& program = "", bool events = false, const std::vector<std::string>& extra = {})
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
        if (!program.empty() && events) {
            args.push_back("--events");
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
        const int code = runNode(role, Options(argv.size(), argv.data(), 2));
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

// what runAll runs (the options of fork mode)
struct Scenario
{
    bool pretty = false;
    bool view = false;
    bool color = false;
    std::string rsuProgram;         // --rsu-exec: another program as the RSU (e.g. the SGX gateway)
    std::string cloudCertificate;   // --cloud: start the cloud; its certificate goes there (the RSU trusts it)
    std::string smartdata;          // --smartdata: sizes of the SmartData the vehicle sends after the bootstrap
    std::string smartdataCount = "1";
    std::string smartdataInterval = "20";
};

// everything from one command, on the loopback: no frame is sent before its receiver is listening
int runAll(const Scenario& scenario)
{
    // view: the children (forked from here) print Trace events, drawn at the end
    TraceView traceView(scenario.color);
    if (scenario.view) {
        trace::setMode(trace::Mode::Events);
    }

    const std::string iface = "lo";
    auto notStarted = [](const std::string& label) { Child child; child.label = label; return child; };
    const bool withCloud = !scenario.cloudCertificate.empty();
    Child cloud = withCloud ? spawn("cloud", "cloud", iface, true, "", false, { "--cert-out", scenario.cloudCertificate })
        : notStarted("cloud");
    Child esa = !withCloud || cloud.pid > 0 ? spawn("esa", "esa", iface, true) : notStarted("esa");
    std::vector<std::string> rsuExtra;
    if (withCloud && !scenario.rsuProgram.empty()) {
        rsuExtra = { "--cloud-cert", scenario.cloudCertificate };
    }
    Child rsu = esa.pid > 0 ? spawn("rsu", "rsu[0]", iface, true, scenario.rsuProgram, scenario.view, rsuExtra)
        : notStarted("rsu[0]");
    std::vector<std::string> vehicleExtra;
    if (!scenario.smartdata.empty()) {
        vehicleExtra = { "--smartdata", scenario.smartdata, "--smartdata-count", scenario.smartdataCount,
            "--smartdata-interval", scenario.smartdataInterval };
    }
    Child vehicle = rsu.pid > 0 ? spawn("vehicle", "node[0]", iface, false, "", false, vehicleExtra)
        : notStarted("node[0]");
    std::vector<Child*> children{ &esa, &rsu, &vehicle };
    if (withCloud) {
        children.insert(children.begin(), &cloud);
    }

    // until every output closes: the vehicle leaves on its own, then the servers are stopped
    Printer printer(scenario.pretty, scenario.view ? &traceView : nullptr);
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
        std::cout << "usage: " << argv[0] << " [--pretty | --view [--color]] [--rsu-exec <program>]   (ESA, RSU and vehicle)\n"
            << "         [--cloud <certificate.pem>]      also the cloud (HTTPS); its certificate is written there\n"
            << "         [--smartdata <size,size,...> [--smartdata-count <n>] [--smartdata-interval <ms>]]\n"
            << "                                          after the bootstrap, the vehicle sends SmartData\n"
            << "         [--test-handover]                run in-memory handover secrecy forwarding verification\n"
            << "         [--test-network-handover]        run full network (bootstrap + SmartData + TLS Cloud + Handover + forward secrecy)\n"
            << "       " << argv[0] << " esa|rsu|vehicle|cloud [--option value ...]   (one node, see main.cpp)" << std::endl;
        return 0;
    }
    if (first == "--test-handover") {
        return runHandoverTest();
    }
    if (first == "--test-network-handover" || first == "--network-handover") {
        return runFullNetworkHandoverTest();
    }
    if (argc >= 2 && first.rfind("--", 0) != 0) {
        try {
            return runNode(first, Options(argc, argv, 2));
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
        } else if (option == "--view") {
            scenario.view = true;
        } else if (option == "--color") {
            scenario.color = true;
        } else {
            std::cerr << "error: unexpected argument '" << argv[i] << "' (see --help)" << std::endl;
            return 1;
        }
    }
    return runAll(scenario);
}
