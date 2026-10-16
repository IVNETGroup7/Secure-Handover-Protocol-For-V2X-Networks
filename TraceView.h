#ifndef BOOTSTRAP_TRACEVIEW_H_
#define BOOTSTRAP_TRACEVIEW_H_

// "bootstrap --view": collects the output of every process (Trace.h, Events mode) and, at the end, draws the
// protocol as a sequence diagram ordered by the time of each event:
//   one block per message: the arrow sender -> receiver, then what the receiver read (the fields of M),
//   validated (ok / failed) and kept; then a summary that compares the values each node kept

#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

class TraceView
{
    public:
        explicit TraceView(bool color) : mColor(color) {}

        // one line of the output of "source" ("esa", "rsu[0]"...): a Trace event or any other line (e.g. an error)
        void line(const std::string& source, const std::string& text);

        void render(std::ostream&) const;

    private:
        struct Event
        {
            int64_t t;                          // ns (system clock: the same in every process)
            size_t order;                       // arrival order, for events with the same t
            std::string kind;                   // step, detail, check, keep, send, end; "out": any other line
            std::string node;
            std::vector<std::string> fields;    // see Trace.cpp
        };

        std::vector<Event> mEvents;
        bool mColor;
};

#endif /* BOOTSTRAP_TRACEVIEW_H_ */
