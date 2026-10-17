#include "Trace.h"
#include "SimTime.h"
#include "Traits.h"
#include <initializer_list>
#include <iostream>

namespace trace
{

namespace
{

Mode gMode = Mode::Text;

void event(const char* kind, const std::string& node, std::initializer_list<std::string> fields)
{
    std::string line(1, kMark);
    line += std::to_string(SimTime::now().ns());
    line += kMark;
    line += kind;
    line += kMark;
    line += node;
    for (const std::string& field : fields) {
        line += kMark;
        line += field;
    }
    std::cout << line << std::endl;
}

void textLine(const std::string& node, const std::string& separator, const std::string& text)
{
    std::cout << "[t=" << simTime() << "] " << node << separator << text << std::endl;
}

} // namespace

void setMode(Mode mode)
{
    gMode = mode;
}

void step(const std::string& node, const std::string& step, const std::string& onType, const std::string& from,
    const std::string& vehicle)
{
    if (gMode == Mode::Events) {
        event("step", node, { step, onType, from, vehicle });
        return;
    }
    std::string text = step;
    if (!onType.empty()) {
        text += " (on " + onType + " from " + from + ", vehicle " + vehicle + ")";
    }
    textLine(node, " -> ", text);
}

void detail(const std::string& node, const std::string& text)
{
    if (gMode == Mode::Events) {
        event("detail", node, { text });
        return;
    }
    textLine(node, "    ", text);
}

void check(const std::string& node, bool ok, const std::string& text, bool beforeStep)
{
    if (gMode == Mode::Events) {
        event("check", node, { ok ? "1" : "0", beforeStep ? "1" : "0", text });
        return;
    }
    textLine(node, "    ", text);
}

void keep(const std::string& node, const std::string& name, const Bytes& value, const std::string& vehicle,
    bool echo)
{
    const std::string hex = toHex(value.data(), value.size());
    if (gMode == Mode::Events) {
        event("keep", node, { name, hex, vehicle });
        return;
    }
    if (echo) {
        textLine(node, "    ", name + " = " + hex + (vehicle == node ? " (kept)" : " (kept for " + vehicle + ")"));
    }
}

void send(const std::string& node, const std::string& type, const std::string& to, const std::string& vehicle,
    const std::string& channel, size_t bytes)
{
    if (gMode == Mode::Events) {
        event("send", node, { type, to, vehicle, channel, std::to_string(bytes) });
    }
}

void end(const std::string& node, const std::string& text, bool ok)
{
    if (gMode == Mode::Events) {
        event("end", node, { ok ? "1" : "0", text });
        return;
    }
    textLine(node, " -> ", text);
}

} // namespace trace
