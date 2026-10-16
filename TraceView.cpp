#include "TraceView.h"
#include "SimTime.h"
#include "Trace.h"
#include <algorithm>
#include <cstdio>
#include <map>
#include <set>

namespace
{

constexpr size_t kWidth = 80;   // columns of the drawing
constexpr size_t kIndent = 6;   // details under a block

// ANSI SGR codes
const char* kBold = "1";
const char* kDim = "2";
const char* kRed = "31";
const char* kGreen = "32";
const char* kYellow = "33";
const char* kCyan = "36";

std::vector<std::string> split(const std::string& text, char separator)
{
    std::vector<std::string> parts;
    size_t start = 0;
    for (size_t end; (end = text.find(separator, start)) != std::string::npos; start = end + 1) {
        parts.push_back(text.substr(start, end - start));
    }
    parts.push_back(text.substr(start));
    return parts;
}

// columns taken by a UTF-8 string (one per code point)
size_t columns(const std::string& text)
{
    return std::count_if(text.begin(), text.end(), [](char c) { return (static_cast<unsigned char>(c) & 0xC0) != 0x80; });
}

// "text" cut in lines of at most "width" columns, breaking at spaces (or anywhere inside a long word, e.g. hex)
std::vector<std::string> wrap(const std::string& text, size_t width)
{
    std::vector<std::string> lines;
    std::string rest = text;
    while (columns(rest) > width) {
        size_t cut = rest.rfind(' ', width);
        if (cut == std::string::npos || cut < width / 2) {
            cut = width; // hex and other long words: break anywhere (they are ASCII)
            lines.push_back(rest.substr(0, cut));
            rest.erase(0, cut);
        } else {
            lines.push_back(rest.substr(0, cut));
            rest.erase(0, cut + 1);
        }
    }
    lines.push_back(rest);
    return lines;
}

// lane of a node in the diagram: vehicles, RSUs, the ESA, the user
int laneKind(const std::string& node)
{
    if (node == "user") return 3;
    if (node == "esa") return 2;
    if (node.rfind("rsu", 0) == 0) return 1;
    return 0;
}

std::string abbreviate(const std::string& hex)
{
    return hex.size() <= 24 ? hex : hex.substr(0, 16) + "…" + hex.substr(hex.size() - 8);
}

} // namespace

void TraceView::line(const std::string& source, const std::string& text)
{
    Event event;
    event.order = mEvents.size();
    if (!text.empty() && text[0] == trace::kMark) {
        std::vector<std::string> parts = split(text.substr(1), trace::kMark);
        if (parts.size() >= 3) {
            event.t = std::stoll(parts[0]);
            event.kind = parts[1];
            event.node = parts[2];
            event.fields.assign(parts.begin() + 3, parts.end());
            mEvents.push_back(event);
            return;
        }
    }
    // any other line (setup, errors): when it was read
    event.t = SimTime::now().ns();
    event.kind = "out";
    event.node = source;
    event.fields = { text };
    mEvents.push_back(event);
}

void TraceView::render(std::ostream& out) const
{
    auto paint = [this](const char* code, const std::string& text) {
        return mColor ? "\033[" + std::string(code) + "m" + text + "\033[0m" : text;
    };
    auto field = [](const Event& event, size_t i) { return i < event.fields.size() ? event.fields[i] : std::string(); };

    std::vector<Event> events = mEvents;
    std::stable_sort(events.begin(), events.end(), [](const Event& a, const Event& b) { return a.t < b.t; });
    if (events.empty()) {
        return;
    }

    // lanes: every node that runs a step, sends, or is sent to
    std::vector<std::string> lanes;
    auto addLane = [&](const std::string& node) {
        if (!node.empty() && std::find(lanes.begin(), lanes.end(), node) == lanes.end()) {
            lanes.push_back(node);
        }
    };
    for (const Event& event : events) {
        if (event.kind == "step" || event.kind == "send" || event.kind == "end") {
            addLane(event.node);
        }
        if (event.kind == "send") {
            addLane(field(event, 1));
        }
    }
    std::stable_sort(lanes.begin(), lanes.end(), [](const std::string& a, const std::string& b) {
        return laneKind(a) < laneKind(b);
    });
    std::map<std::string, size_t> laneX; // column of each lane
    for (size_t i = 0; i < lanes.size(); ++i) {
        laneX[lanes[i]] = lanes.size() == 1 ? kWidth / 2 : 6 + i * (kWidth - 12) / (lanes.size() - 1);
    }

    auto laneRow = [&](std::vector<std::string>& cells) {
        for (const auto& lane : laneX) {
            cells[lane.second] = "│";
        }
    };
    auto join = [](const std::vector<std::string>& cells) {
        std::string text;
        for (const std::string& cell : cells) {
            text += cell;
        }
        while (!text.empty() && text.back() == ' ') {
            text.pop_back();
        }
        return text;
    };
    // sender -> receiver, with the type of the message on the arrow when it fits
    auto arrow = [&](const std::string& from, const std::string& to, const std::string& label) {
        std::vector<std::string> cells(kWidth, " ");
        laneRow(cells);
        if (!laneX.count(from) || !laneX.count(to) || from == to) {
            return join(cells);
        }
        const size_t a = laneX[from], b = laneX[to];
        const size_t lo = std::min(a, b), hi = std::max(a, b);
        for (size_t x = lo + 1; x < hi; ++x) {
            cells[x] = "─";
        }
        cells[b > a ? hi - 1 : lo + 1] = b > a ? "▶" : "◀";
        const std::string text = " " + label + " ";
        if (hi - lo > text.size() + 4) {
            const size_t start = lo + (hi - lo - text.size()) / 2;
            for (size_t i = 0; i < text.size(); ++i) {
                cells[start + i] = std::string(1, text[i]);
            }
        }
        return join(cells);
    };
    auto rule = [&](const std::string& title) {
        std::string text = "── " + title + " ";
        while (columns(text) < kWidth) {
            text += "─";
        }
        return text;
    };

    // time from the first step of the protocol (setup lines come before it)
    int64_t t0 = events.front().t;
    for (const Event& event : events) {
        if (event.kind == "step") {
            t0 = event.t;
            break;
        }
    }
    auto elapsed = [&](int64_t t) {
        char text[32];
        std::snprintf(text, sizeof(text), "+%.3f ms", (t - t0) / 1e6);
        return std::string(text);
    };
    auto printWrapped = [&](const std::string& prefix, const std::string& text, const char* code) {
        // continuation lines aligned after " = " (field values), or after the prefix
        const size_t equals = text.find(" = ");
        const size_t hang = equals != std::string::npos && equals < 32 ? equals + 3 : 2;
        const size_t width = kWidth - columns(prefix);
        std::vector<std::string> lines = wrap(text, width);
        if (lines.size() > 1) {
            const std::string first = lines.front();
            lines = wrap(text.substr(first.size() + (text[first.size()] == ' ' ? 1 : 0)), width - hang);
            lines.insert(lines.begin(), first);
        }
        for (size_t i = 0; i < lines.size(); ++i) {
            const std::string lead = i == 0 ? prefix : std::string(columns(prefix) + hang, ' ');
            out << lead << (code ? paint(code, lines[i]) : lines[i]) << "\n";
        }
    };

    // header: the lanes
    {
        std::vector<std::string> cells(kWidth, " ");
        for (const auto& lane : laneX) {
            const size_t start = lane.second >= lane.first.size() / 2 ? lane.second - lane.first.size() / 2 : 0;
            for (size_t i = 0; i < lane.first.size() && start + i < kWidth; ++i) {
                cells[start + i] = std::string(1, lane.first[i]);
            }
        }
        out << paint(kBold, join(cells)) << "\n";
        std::vector<std::string> lanesOnly(kWidth, " ");
        laneRow(lanesOnly);
        out << paint(kDim, join(lanesOnly)) << "\n";
        out << "  " << paint(kGreen, "✔") << paint(kDim, " validated   ") << paint(kRed, "✘")
            << paint(kDim, " failed   ") << paint(kYellow, "◆") << paint(kDim, " kept   ") << paint(kGreen, "●")
            << paint(kDim, " ended   ↳ next step, same message") << "\n";
    }

    // which send each step reacts to (the last one of that type from that sender)
    std::map<size_t, size_t> sendOf; // step index -> send index
    std::set<size_t> received;       // send indexes some step reacted to
    std::map<std::string, std::vector<std::string>> lastTrigger; // node -> { onType, from, vehicle }
    std::set<size_t> subSteps;       // steps run on the same message as the step before them (e.g. PTP -> PTPSync)
    for (size_t i = 0; i < events.size(); ++i) {
        const Event& event = events[i];
        if (event.kind != "step" || field(event, 1).empty()) {
            continue;
        }
        const std::vector<std::string> trigger{ field(event, 1), field(event, 2), field(event, 3) };
        if (lastTrigger[event.node] == trigger) {
            subSteps.insert(i);
            continue;
        }
        lastTrigger[event.node] = trigger;
        for (size_t j = i; j-- > 0;) {
            const Event& send = events[j];
            if (send.kind == "send" && !received.count(j) && field(send, 0) == trigger[0] && send.node == trigger[1]) {
                sendOf[i] = j;
                received.insert(j);
                break;
            }
        }
    }

    int block = 0;
    std::string blockNode;                                  // node whose block is open
    std::map<std::string, std::vector<const Event*>> held;  // checks made before their step (t_f)
    std::map<std::pair<std::string, std::string>, std::vector<std::pair<std::string, std::string>>> kept;
    std::vector<std::string> failures;
    std::vector<std::pair<bool, std::string>> ends;
    std::vector<const Event*> others;
    int passed = 0;

    auto title = [&](const std::string& left, const std::string& right, int64_t t) {
        const std::string time = elapsed(t);
        std::string text = left;
        const size_t used = columns(left) + columns(right) + time.size();
        text += std::string(used + 2 < kWidth ? kWidth - used - 2 : 1, ' ');
        out << "\n" << paint(kBold, text) << paint(kDim, right + "  " + time) << "\n";
    };
    auto printCheck = [&](const Event& event) {
        const bool ok = field(event, 0) == "1";
        const std::string mark = ok ? "✔ " : "✘ ";
        printWrapped(std::string(kIndent, ' ') + paint(ok ? kGreen : kRed, mark), field(event, 2), ok ? nullptr : kRed);
        if (ok) {
            ++passed;
        } else {
            failures.push_back(event.node + ": " + field(event, 2));
        }
    };

    for (size_t i = 0; i < events.size(); ++i) {
        const Event& event = events[i];
        // before the first block (e.g. the HTTPS sessions): a note; in another node's block: tagged with the node
        const std::string prefix = blockNode.empty() ? "  " + paint(kDim, "· [" + event.node + "] ")
            : std::string(kIndent, ' ') + (event.node != blockNode ? paint(kDim, "[" + event.node + "] ") : "");

        if (event.kind == "step") {
            if (subSteps.count(i)) {
                out << std::string(kIndent - 2, ' ') << paint(kCyan, "↳ " + event.node + " · " + field(event, 0)) << "\n";
            } else if (sendOf.count(i)) {
                const Event& send = events[sendOf[i]];
                ++block;
                title(std::to_string(block) + ". " + field(event, 1),
                    send.node + " → " + event.node + " · " + field(send, 3) + " · " + field(send, 4) + " B", event.t);
                out << paint(kCyan, arrow(send.node, event.node, field(event, 1))) << "\n";
                out << std::string(kIndent - 2, ' ') << paint(kCyan, event.node + " · " + field(event, 0)) << "\n";
            } else {
                ++block;
                title(std::to_string(block) + ". " + field(event, 0), event.node + " starts", event.t);
                out << std::string(kIndent - 2, ' ') << paint(kCyan, event.node + " · " + field(event, 0)) << "\n";
            }
            blockNode = event.node;
            for (const Event* check : held[event.node]) {
                printCheck(*check);
            }
            held[event.node].clear();
        } else if (event.kind == "detail") {
            const std::string text = field(event, 0);
            printWrapped(prefix, text, text.rfind("M = {", 0) == 0 ? kBold : nullptr);
        } else if (event.kind == "check") {
            const Event* next = nullptr;
            for (size_t j = i + 1; j < events.size() && !next; ++j) {
                if (events[j].node == event.node && events[j].kind != "out") {
                    next = &events[j];
                }
            }
            if (field(event, 1) == "1" && next && next->kind == "step") {
                held[event.node].push_back(&event); // e.g. t_f, checked in dispatch: shown in its step
            } else {
                printCheck(event);
            }
        } else if (event.kind == "keep") {
            kept[{ field(event, 0), field(event, 2) }].push_back({ event.node, field(event, 1) });
            if (field(event, 0) == "CY_e" || (event.node != field(event, 2) && field(event, 0) == "K_g")) {
                continue; // shown in M already (the summary compares them)
            }
            printWrapped(prefix + paint(kYellow, "◆ "), field(event, 0) + " = " + field(event, 1), kYellow);
        } else if (event.kind == "send" && !received.count(i)) {
            // nobody here reacts to it (e.g. the Active_03 to the user)
            ++block;
            title(std::to_string(block) + ". " + field(event, 0),
                event.node + " → " + field(event, 1) + " · " + field(event, 3) + " · " + field(event, 4) + " B", event.t);
            out << paint(kCyan, arrow(event.node, field(event, 1), field(event, 0))) << "\n";
            blockNode = event.node;
        } else if (event.kind == "end") {
            const bool ok = field(event, 0) == "1";
            ends.push_back({ ok, event.node + ": " + field(event, 1) });
            out << std::string(kIndent - 2, ' ') << paint(ok ? kGreen : kRed, (ok ? "● " : "✘ ") + event.node + " · "
                + field(event, 1)) << "\n";
            if (!ok) {
                failures.push_back(event.node + ": " + field(event, 1));
            }
        } else if (event.kind == "out") {
            others.push_back(&event);
        }
    }

    // anything else the processes printed (setup, results, errors)
    if (!others.empty()) {
        out << "\n" << paint(kBold, rule("other output")) << "\n";
        for (const Event* other : others) {
            printWrapped("  " + paint(kDim, "· "), field(*other, 0), kDim);
        }
    }

    // summary
    out << "\n" << paint(kBold, rule("summary")) << "\n";
    out << "  values kept by more than one node\n";
    bool anyShared = false;
    for (const auto& value : kept) {
        if (value.second.size() < 2) {
            continue;
        }
        anyShared = true;
        std::set<std::string> distinct;
        std::string nodes;
        for (const auto& holder : value.second) {
            distinct.insert(holder.second);
            nodes += (nodes.empty() ? "" : " = ") + holder.first;
        }
        const bool same = distinct.size() == 1;
        char name[64];
        std::snprintf(name, sizeof(name), "%-5s for %-9s", value.first.first.c_str(), value.first.second.c_str());
        std::string line = std::string(name) + " " + nodes;
        line += std::string(line.size() < 46 ? 46 - line.size() : 1, ' ');
        out << "    " << paint(same ? kGreen : kRed, same ? "✔ " : "✘ ") << line
            << paint(kDim, same ? abbreviate(*distinct.begin()) : "DIFFERENT") << "\n";
        if (!same) {
            failures.push_back(value.first.first + " for " + value.first.second + " differs between " + nodes);
        }
    }
    if (!anyShared) {
        out << "    (none)\n";
    }
    out << "  validations: " << paint(kGreen, std::to_string(passed) + " passed") << ", "
        << paint(failures.empty() ? kGreen : kRed, std::to_string(failures.size()) + " failed") << "\n";
    for (const std::string& failure : failures) {
        printWrapped("    " + paint(kRed, "✘ "), failure, kRed);
    }
    for (const auto& end : ends) {
        out << "  " << paint(end.first ? kGreen : kRed, (end.first ? "● " : "✘ ") + end.second) << "\n";
    }
}
