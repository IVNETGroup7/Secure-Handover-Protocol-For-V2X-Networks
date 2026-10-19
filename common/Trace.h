#ifndef BOOTSTRAP_TRACE_H_
#define BOOTSTRAP_TRACE_H_

#include "Crypto.h"
#include <string>

namespace trace
{
void step(const std::string& node, const std::string& step, const std::string& onType = "",
    const std::string& from = "", const std::string& vehicle = "");

void detail(const std::string& node, const std::string& text);

void check(const std::string& node, bool ok, const std::string& text);

void keep(const std::string& node, const std::string& name, const Bytes& value, const std::string& vehicle);

void end(const std::string& node, const std::string& text);

} // namespace trace

#endif /* BOOTSTRAP_TRACE_H_ */
