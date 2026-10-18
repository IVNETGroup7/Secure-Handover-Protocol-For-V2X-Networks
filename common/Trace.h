#ifndef BOOTSTRAP_TRACE_H_
#define BOOTSTRAP_TRACE_H_

// What the nodes print while they run the protocol, one line each:
//   [t=<s>] node -> step (on <type> from <sender>, vehicle <v>)
//   [t=<s>] node    detail / ✔ check / ✘ check / name = value (kept)

#include "Crypto.h"
#include <string>

namespace trace
{

// "node" runs "step", triggered by a message of type "onType" from "from" ("" when nothing triggered it)
void step(const std::string& node, const std::string& step, const std::string& onType = "",
    const std::string& from = "", const std::string& vehicle = "");

// a line under the last step (e.g. a field of the message M)
void detail(const std::string& node, const std::string& text);

// a validation and its result
void check(const std::string& node, bool ok, const std::string& text);

// "node" keeps "value" as "name" for "vehicle"
void keep(const std::string& node, const std::string& name, const Bytes& value, const std::string& vehicle);

// the protocol ends for "node" ("vehicle ready", "Protocol ended", "aborted: ..."...)
void end(const std::string& node, const std::string& text);

} // namespace trace

#endif /* BOOTSTRAP_TRACE_H_ */
