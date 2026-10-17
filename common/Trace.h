#ifndef BOOTSTRAP_TRACE_H_
#define BOOTSTRAP_TRACE_H_

// What the nodes print while they run the protocol, as typed events:
//   Text    the usual lines ("[t=...] node -> step", "[t=...] node    detail"); the default
//   Events  one machine-readable line per event, which "bootstrap --view" collects from every process
//           and draws as a sequence diagram (TraceView.h)
//
// event line: kMark t (ns) kMark kind kMark node [kMark field]...   (no field holds kMark or a newline)

#include "Crypto.h"
#include <string>

namespace trace
{

enum class Mode { Text, Events };
void setMode(Mode);

constexpr char kMark = '\x1f';

// "node" runs "step", triggered by a message of type "onType" from "from" ("" when nothing triggered it)
void step(const std::string& node, const std::string& step, const std::string& onType = "",
    const std::string& from = "", const std::string& vehicle = "");

// a line under the last step (e.g. a field of the message M)
void detail(const std::string& node, const std::string& text);

// a validation and its result; "beforeStep": made before the step it belongs to runs (e.g. t_f, in dispatch)
void check(const std::string& node, bool ok, const std::string& text, bool beforeStep = false);

// "node" keeps "value" as "name" for "vehicle" (the view compares what each node kept);
// "echo" false: nothing in Text mode
void keep(const std::string& node, const std::string& name, const Bytes& value, const std::string& vehicle,
    bool echo = true);

// "node" sends a message of type "type" to "to" over "channel" ("radio" or "HTTPS"); nothing in Text mode
void send(const std::string& node, const std::string& type, const std::string& to, const std::string& vehicle,
    const std::string& channel, size_t bytes);

// the protocol ends for "node" ("vehicle ready", "Protocol ended"...), or it gave up (ok false)
void end(const std::string& node, const std::string& text, bool ok = true);

} // namespace trace

#endif /* BOOTSTRAP_TRACE_H_ */
