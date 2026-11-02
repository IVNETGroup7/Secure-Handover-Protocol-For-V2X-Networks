#include "tee_session.h"
#include "Trace.h"
#include "../ta/codec.h"
#include <atomic>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <stdexcept>

#ifdef USE_OPTEE
extern "C" {
#include <tee_client_api.h>
}
#else
#include "../ta/gateway_session.h"
#endif

namespace
{

std::atomic<uint64_t> gNextSessionId{ 1 };

// Render Secure World TA log lines using common/Trace.h (matching kCheckOk / kCheckFailed prefixes)
void emitTaLogs(const std::string& logs)
{
    if (logs.empty()) {
        return;
    }
    std::istringstream stream(logs);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty()) {
            continue;
        }
        bool handled = false;
        for (bool ok : { true, false }) {
            const std::string mark = ok ? kCheckOk : kCheckFailed;
            if (line.rfind(mark, 0) == 0) {
                trace::check("ta", ok, line.substr(mark.size()));
                handled = true;
                break;
            }
        }
        if (!handled) {
            trace::detail("ta", line);
        }
    }
}

#ifdef USE_OPTEE
constexpr size_t kLogBufferSize = 4096;
constexpr size_t kMaxBootstrapReply = 1500;
constexpr size_t kMaxFieldSize = 1024;

size_t itBufferFor(size_t otPacketSize)
{
    return otPacketSize * 4 / 3 + 2048;
}

void checkTeec(TEEC_Result res, uint32_t origin, const char* call)
{
    if (res != TEEC_SUCCESS) {
        char text[128];
        std::snprintf(text, sizeof(text), "%s failed: TEEC_Result 0x%08x (origin 0x%x)",
            call, static_cast<unsigned>(res), static_cast<unsigned>(origin));
        throw std::runtime_error(text);
    }
}

Bytes strBytes(const std::string& s)
{
    return Bytes(s.begin(), s.end());
}
#endif

} // namespace

struct TeeSession::Impl
{
#ifdef USE_OPTEE
    TEEC_Context ctx{};
    TEEC_Session sess{};
    bool open = false;
#else
    GatewayTaSession ta;
#endif
};

TeeSession::TeeSession(const std::string& storageId, bool freshState)
    : mImpl(std::make_unique<Impl>()), mSessionId(gNextSessionId.fetch_add(1)), mStorageId(storageId)
{
#ifdef USE_OPTEE
    const TEEC_UUID uuid = TA_GATEWAY_UUID;
    uint32_t origin = 0;
    checkTeec(TEEC_InitializeContext(nullptr, &mImpl->ctx), origin, "TEEC_InitializeContext");
    const TEEC_Result res = TEEC_OpenSession(&mImpl->ctx, &mImpl->sess, &uuid, TEEC_LOGIN_PUBLIC,
        nullptr, nullptr, &origin);
    if (res != TEEC_SUCCESS) {
        TEEC_FinalizeContext(&mImpl->ctx);
        checkTeec(res, origin, "TEEC_OpenSession");
    }
    mImpl->open = true;
#endif
    setStorageId(mStorageId, freshState);
}

TeeSession::~TeeSession()
{
#ifdef USE_OPTEE
    if (mImpl && mImpl->open) {
        TEEC_CloseSession(&mImpl->sess);
        TEEC_FinalizeContext(&mImpl->ctx);
        mImpl->open = false;
    }
#endif
}

int TeeSession::setStorageId(const std::string& storageId, bool deleteExisting)
{
    mStorageId = storageId;
#ifdef USE_OPTEE
    TEEC_Operation op{};
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = const_cast<char*>(mStorageId.data());
    op.params[0].tmpref.size = mStorageId.size();
    op.params[1].value.a = deleteExisting ? 1 : 0;
    uint32_t origin = 0;
    checkTeec(TEEC_InvokeCommand(&mImpl->sess, TA_GATEWAY_CMD_SET_STORAGE_ID, &op, &origin),
        origin, "TA_GATEWAY_CMD_SET_STORAGE_ID");
    return GW_OK;
#else
    mImpl->ta.setStorageId(mStorageId, deleteExisting);
    return GW_OK;
#endif
}

int TeeSession::initGateway(const Bytes& gwCert, const Bytes& esaPubKey, const Bytes& groupKey)
{
#ifdef USE_OPTEE
    Bytes in;
    wire::putField(in, gwCert);
    wire::putField(in, esaPubKey);
    wire::putField(in, groupKey);
    std::string logBuf(kLogBufferSize, '\0');

    TEEC_Operation op{};
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
    op.params[0].tmpref.buffer = in.data();
    op.params[0].tmpref.size = in.size();
    op.params[2].tmpref.buffer = logBuf.data();
    op.params[2].tmpref.size = logBuf.size();

    uint32_t origin = 0;
    checkTeec(TEEC_InvokeCommand(&mImpl->sess, TA_GATEWAY_CMD_INIT_GATEWAY, &op, &origin),
        origin, "TA_GATEWAY_CMD_INIT_GATEWAY");
    logBuf.resize(op.params[2].tmpref.size);
    emitTaLogs(logBuf);
    return static_cast<int>(op.params[1].value.a);
#else
    const int status = mImpl->ta.initGateway(gwCert, esaPubKey, groupKey);
    emitTaLogs(mImpl->ta.takeLogs());
    return status;
#endif
}

int TeeSession::initCloudSession(const std::string& cloudCertPem, const std::string& host, const std::string& gateway)
{
#ifdef USE_OPTEE
    Bytes in;
    wire::putField(in, strBytes(cloudCertPem));
    wire::putField(in, strBytes(host));
    wire::putField(in, strBytes(gateway));
    std::string logBuf(kLogBufferSize, '\0');

    TEEC_Operation op{};
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
    op.params[0].tmpref.buffer = in.data();
    op.params[0].tmpref.size = in.size();
    op.params[2].tmpref.buffer = logBuf.data();
    op.params[2].tmpref.size = logBuf.size();

    uint32_t origin = 0;
    checkTeec(TEEC_InvokeCommand(&mImpl->sess, TA_GATEWAY_CMD_INIT_CLOUD_SESSION, &op, &origin),
        origin, "TA_GATEWAY_CMD_INIT_CLOUD_SESSION");
    logBuf.resize(op.params[2].tmpref.size);
    emitTaLogs(logBuf);
    return static_cast<int>(op.params[1].value.a);
#else
    const int status = mImpl->ta.initCloudSession(cloudCertPem, host, gateway);
    emitTaLogs(mImpl->ta.takeLogs());
    return status;
#endif
}

int TeeSession::addActivationToken(const std::string& session, uint64_t t0, uint64_t tf, const Bytes& authD,
    const Bytes& authEg)
{
#ifdef USE_OPTEE
    Bytes in;
    wire::putField(in, strBytes(session));
    wire::putUint(in, t0, 8);
    wire::putUint(in, tf, 8);
    wire::putField(in, authD);
    wire::putField(in, authEg);
    std::string logBuf(kLogBufferSize, '\0');

    TEEC_Operation op{};
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
    op.params[0].tmpref.buffer = in.data();
    op.params[0].tmpref.size = in.size();
    op.params[2].tmpref.buffer = logBuf.data();
    op.params[2].tmpref.size = logBuf.size();

    uint32_t origin = 0;
    checkTeec(TEEC_InvokeCommand(&mImpl->sess, TA_GATEWAY_CMD_ADD_ACTIVATION_TOKEN, &op, &origin),
        origin, "TA_GATEWAY_CMD_ADD_ACTIVATION_TOKEN");
    logBuf.resize(op.params[2].tmpref.size);
    emitTaLogs(logBuf);
    return static_cast<int>(op.params[1].value.a);
#else
    const int status = mImpl->ta.addActivationToken(session, t0, tf, authD, authEg);
    emitTaLogs(mImpl->ta.takeLogs());
    return status;
#endif
}

int TeeSession::handleBootstrap(int msgType, const std::string& session, const Bytes& inPkt, uint64_t currentPtpTime,
    Bytes& outPkt, int& outType)
{
#ifdef USE_OPTEE
    Bytes in;
    wire::putUint(in, static_cast<uint64_t>(msgType), 4);
    wire::putUint(in, currentPtpTime, 8);
    wire::putField(in, strBytes(session));
    wire::putField(in, inPkt);
    outPkt.resize(kMaxBootstrapReply);
    std::string logBuf(kLogBufferSize, '\0');

    TEEC_Operation op{};
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT);
    op.params[0].tmpref.buffer = in.data();
    op.params[0].tmpref.size = in.size();
    op.params[1].tmpref.buffer = outPkt.data();
    op.params[1].tmpref.size = outPkt.size();
    op.params[3].tmpref.buffer = logBuf.data();
    op.params[3].tmpref.size = logBuf.size();

    uint32_t origin = 0;
    checkTeec(TEEC_InvokeCommand(&mImpl->sess, TA_GATEWAY_CMD_HANDLE_BOOTSTRAP, &op, &origin),
        origin, "TA_GATEWAY_CMD_HANDLE_BOOTSTRAP");
    logBuf.resize(op.params[3].tmpref.size);
    emitTaLogs(logBuf);
    const int status = static_cast<int>(op.params[2].value.a);
    outType = static_cast<int>(op.params[2].value.b);
    if (status == GW_OK) {
        outPkt.resize(op.params[1].tmpref.size);
    } else {
        outPkt.clear();
    }
    return status;
#else
    const int status = mImpl->ta.handleBootstrap(msgType, session, inPkt, currentPtpTime, outPkt, outType);
    emitTaLogs(mImpl->ta.takeLogs());
    return status;
#endif
}

int TeeSession::secureMarshalOtToIt(const Bytes& otPkt, uint64_t currentPtpTime, Bytes& outItPkt)
{
#ifdef USE_OPTEE
    Bytes in;
    wire::putUint(in, currentPtpTime, 8);
    in.insert(in.end(), otPkt.begin(), otPkt.end());
    outItPkt.resize(itBufferFor(otPkt.size()));
    std::string logBuf(kLogBufferSize, '\0');

    TEEC_Operation op{};
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT);
    op.params[0].tmpref.buffer = in.data();
    op.params[0].tmpref.size = in.size();
    op.params[1].tmpref.buffer = outItPkt.data();
    op.params[1].tmpref.size = outItPkt.size();
    op.params[3].tmpref.buffer = logBuf.data();
    op.params[3].tmpref.size = logBuf.size();

    uint32_t origin = 0;
    checkTeec(TEEC_InvokeCommand(&mImpl->sess, TA_GATEWAY_CMD_SECURE_MARSHAL_OT_TO_IT, &op, &origin),
        origin, "TA_GATEWAY_CMD_SECURE_MARSHAL_OT_TO_IT");
    logBuf.resize(op.params[3].tmpref.size);
    emitTaLogs(logBuf);
    const int status = static_cast<int>(op.params[2].value.a);
    if (status == GW_OK) {
        outItPkt.resize(op.params[1].tmpref.size);
    } else {
        outItPkt.clear();
    }
    return status;
#else
    const int status = mImpl->ta.secureMarshalOtToIt(otPkt, currentPtpTime, outItPkt);
    emitTaLogs(mImpl->ta.takeLogs());
    return status;
#endif
}

int TeeSession::triggerHandover(const std::string& session, uint64_t ti, Block& outTau, Bytes& outYv, Bytes& outAuthD)
{
#ifdef USE_OPTEE
    Bytes in;
    wire::putUint(in, ti, 8);
    wire::putField(in, strBytes(session));
    Bytes outBuf(kMaxFieldSize);
    std::string logBuf(kLogBufferSize, '\0');

    TEEC_Operation op{};
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT);
    op.params[0].tmpref.buffer = in.data();
    op.params[0].tmpref.size = in.size();
    op.params[1].tmpref.buffer = outBuf.data();
    op.params[1].tmpref.size = outBuf.size();
    op.params[3].tmpref.buffer = logBuf.data();
    op.params[3].tmpref.size = logBuf.size();

    uint32_t origin = 0;
    checkTeec(TEEC_InvokeCommand(&mImpl->sess, TA_GATEWAY_CMD_TRIGGER_HANDOVER, &op, &origin),
        origin, "TA_GATEWAY_CMD_TRIGGER_HANDOVER");
    logBuf.resize(op.params[3].tmpref.size);
    emitTaLogs(logBuf);
    const int status = static_cast<int>(op.params[2].value.a);
    if (status == GW_OK) {
        outBuf.resize(op.params[1].tmpref.size);
        wire::Reader r(outBuf);
        outTau = r.block();
        outYv = r.field();
        outAuthD = r.field();
    }
    return status;
#else
    const int status = mImpl->ta.triggerHandover(session, ti, outTau, outYv, outAuthD);
    emitTaLogs(mImpl->ta.takeLogs());
    return status;
#endif
}

int TeeSession::receiveForwardingNotice(const std::string& session, const Bytes& yv, const Block& tau,
    const Bytes& authD, Bytes& outYg)
{
#ifdef USE_OPTEE
    Bytes in;
    wire::putField(in, strBytes(session));
    in.insert(in.end(), tau.begin(), tau.end());
    wire::putField(in, yv);
    wire::putField(in, authD);
    outYg.resize(kMaxFieldSize);
    std::string logBuf(kLogBufferSize, '\0');

    TEEC_Operation op{};
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT);
    op.params[0].tmpref.buffer = in.data();
    op.params[0].tmpref.size = in.size();
    op.params[1].tmpref.buffer = outYg.data();
    op.params[1].tmpref.size = outYg.size();
    op.params[3].tmpref.buffer = logBuf.data();
    op.params[3].tmpref.size = logBuf.size();

    uint32_t origin = 0;
    checkTeec(TEEC_InvokeCommand(&mImpl->sess, TA_GATEWAY_CMD_RECEIVE_FORWARDING_NOTICE, &op, &origin),
        origin, "TA_GATEWAY_CMD_RECEIVE_FORWARDING_NOTICE");
    logBuf.resize(op.params[3].tmpref.size);
    emitTaLogs(logBuf);
    const int status = static_cast<int>(op.params[2].value.a);
    if (status == GW_OK) {
        outYg.resize(op.params[1].tmpref.size);
    } else {
        outYg.clear();
    }
    return status;
#else
    const int status = mImpl->ta.receiveForwardingNotice(session, yv, tau, authD, outYg);
    emitTaLogs(mImpl->ta.takeLogs());
    return status;
#endif
}

