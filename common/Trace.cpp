#include "Trace.h"
#include "SimTime.h"
#include "Traits.h"
#include <iostream>

namespace trace
{

namespace
{

void textLine(const std::string& node, const std::string& separator, const std::string& text)
{
    std::cout << "[t=" << simTime() << "] " << node << separator << text << std::endl;
}

} // namespace

void step(const std::string& node, const std::string& step, const std::string& onType, const std::string& from,
    const std::string& vehicle)
{
    std::string text = step;
    if (!onType.empty()) {
        text += " (on " + onType + " from " + from + ", vehicle " + vehicle + ")";
    }
    textLine(node, " -> ", text);
}

void detail(const std::string& node, const std::string& text)
{
    textLine(node, "    ", text);
}

void check(const std::string& node, bool ok, const std::string& text)
{
    textLine(node, ok ? "    ✔ " : "    ✘ ", text);
}

void keep(const std::string& node, const std::string& name, const Bytes& value, const std::string& vehicle)
{
    textLine(node, "    ", name + " = " + toHex(value.data(), value.size())
        + (vehicle == node ? " (kept)" : " (kept for " + vehicle + ")"));
}

void end(const std::string& node, const std::string& text)
{
    textLine(node, " -> ", text);
}

} // namespace trace
