// GlobalPlatform TEE Internal Core API entry points for the OP-TEE RSU Gateway Trusted Application.
// Compiled when building the Secure World `.ta` binary against OP-TEE (`__OPTEE_TA__`).

#ifdef __OPTEE_TA__

#include "gateway_session.h"
#include "codec.h"
#include <cstring>
#include <string>

extern "C" {
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
}

namespace
{

// Copy accumulated TA trace logs into a MEMREF_OUTPUT parameter buffer
void copyLogsToParam(GatewayTaSession* sess, uint32_t paramType, TEE_Param& param)
{
    const std::string logs = sess->takeLogs();
    if (paramType == TEE_PARAM_TYPE_MEMREF_OUTPUT || paramType == TEE_PARAM_TYPE_MEMREF_INOUT) {
        if (param.memref.buffer && param.memref.size > 0) {
            const size_t n = std::min<size_t>(logs.size(), param.memref.size - 1);
            std::memcpy(param.memref.buffer, logs.data(), n);
            static_cast<char*>(param.memref.buffer)[n] = '\0';
            param.memref.size = static_cast<uint32_t>(n);
        } else {
            param.memref.size = 0;
        }
    }
}

std::string toStr(const Bytes& b)
{
    return std::string(b.begin(), b.end());
}

} // namespace

extern "C" {

TEE_Result TA_CreateEntryPoint(void)
{
    IMSG("V2X RSU Gateway TA created");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    IMSG("V2X RSU Gateway TA destroyed");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void** sess_ctx)
{
    (void)param_types;
    (void)params;
    try {
        *sess_ctx = new GatewayTaSession();
        return TEE_SUCCESS;
    } catch (...) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
}

void TA_CloseSessionEntryPoint(void* sess_ctx)
{
    delete static_cast<GatewayTaSession*>(sess_ctx);
}

TEE_Result TA_InvokeCommandEntryPoint(void* sess_ctx, uint32_t cmd_id, uint32_t param_types, TEE_Param params[4])
{
    auto* sess = static_cast<GatewayTaSession*>(sess_ctx);
    if (!sess) {
        return TEE_ERROR_BAD_STATE;
    }

    const uint32_t t0 = TEE_PARAM_TYPE_GET(param_types, 0);
    const uint32_t t1 = TEE_PARAM_TYPE_GET(param_types, 1);
    const uint32_t t2 = TEE_PARAM_TYPE_GET(param_types, 2);
    const uint32_t t3 = TEE_PARAM_TYPE_GET(param_types, 3);

    try {
        switch (cmd_id) {
            case TA_GATEWAY_CMD_SET_STORAGE_ID: {
                if (t0 != TEE_PARAM_TYPE_MEMREF_INPUT || t1 != TEE_PARAM_TYPE_VALUE_INPUT) {
                    return TEE_ERROR_BAD_PARAMETERS;
                }
                const char* ptr = static_cast<const char*>(params[0].memref.buffer);
                const std::string storageId(ptr, ptr + params[0].memref.size);
                sess->setStorageId(storageId, params[1].value.a != 0);
                return TEE_SUCCESS;
            }

            case TA_GATEWAY_CMD_INIT_GATEWAY: {
                if (t0 != TEE_PARAM_TYPE_MEMREF_INPUT || t1 != TEE_PARAM_TYPE_VALUE_OUTPUT) {
                    return TEE_ERROR_BAD_PARAMETERS;
                }
                const auto* buf = static_cast<const uint8_t*>(params[0].memref.buffer);
                const Bytes in(buf, buf + params[0].memref.size);
                wire::Reader r(in);
                const Bytes gwCert = r.field();
                const Bytes esaPubKey = r.field();
                const Bytes groupKey = r.field();
                const int status = sess->initGateway(gwCert, esaPubKey, groupKey);
                params[1].value.a = static_cast<uint32_t>(status);
                copyLogsToParam(sess, t2, params[2]);
                return TEE_SUCCESS;
            }

            case TA_GATEWAY_CMD_INIT_CLOUD_SESSION: {
                if (t0 != TEE_PARAM_TYPE_MEMREF_INPUT || t1 != TEE_PARAM_TYPE_VALUE_OUTPUT) {
                    return TEE_ERROR_BAD_PARAMETERS;
                }
                const auto* buf = static_cast<const uint8_t*>(params[0].memref.buffer);
                const Bytes in(buf, buf + params[0].memref.size);
                wire::Reader r(in);
                const std::string pem = toStr(r.field());
                const std::string host = toStr(r.field());
                const std::string gw = toStr(r.field());
                const int status = sess->initCloudSession(pem, host, gw);
                params[1].value.a = static_cast<uint32_t>(status);
                copyLogsToParam(sess, t2, params[2]);
                return TEE_SUCCESS;
            }

            case TA_GATEWAY_CMD_ADD_ACTIVATION_TOKEN: {
                if (t0 != TEE_PARAM_TYPE_MEMREF_INPUT || t1 != TEE_PARAM_TYPE_VALUE_OUTPUT) {
                    return TEE_ERROR_BAD_PARAMETERS;
                }
                const auto* buf = static_cast<const uint8_t*>(params[0].memref.buffer);
                const Bytes in(buf, buf + params[0].memref.size);
                wire::Reader r(in);
                const std::string session = toStr(r.field());
                const uint64_t tStart = r.uint(8);
                const uint64_t tEnd = r.uint(8);
                const Bytes authD = r.field();
                const Bytes authEg = r.field();
                const int status = sess->addActivationToken(session, tStart, tEnd, authD, authEg);
                params[1].value.a = static_cast<uint32_t>(status);
                copyLogsToParam(sess, t2, params[2]);
                return TEE_SUCCESS;
            }

            case TA_GATEWAY_CMD_HANDLE_BOOTSTRAP: {
                if (t0 != TEE_PARAM_TYPE_MEMREF_INPUT || t1 != TEE_PARAM_TYPE_MEMREF_OUTPUT
                    || t2 != TEE_PARAM_TYPE_VALUE_OUTPUT) {
                    return TEE_ERROR_BAD_PARAMETERS;
                }
                const auto* buf = static_cast<const uint8_t*>(params[0].memref.buffer);
                const Bytes in(buf, buf + params[0].memref.size);
                wire::Reader r(in);
                const int msgType = static_cast<int>(r.uint(4));
                const uint64_t ptpTime = r.uint(8);
                const std::string session = toStr(r.field());
                const Bytes inPkt = r.field();

                Bytes outPkt;
                int outType = -1;
                int status = sess->handleBootstrap(msgType, session, inPkt, ptpTime, outPkt, outType);
                if (status == GW_OK) {
                    if (outPkt.size() > params[1].memref.size) {
                        status = GW_ERR_BUFFER;
                        params[1].memref.size = 0;
                    } else {
                        std::memcpy(params[1].memref.buffer, outPkt.data(), outPkt.size());
                        params[1].memref.size = static_cast<uint32_t>(outPkt.size());
                    }
                } else {
                    params[1].memref.size = 0;
                }
                params[2].value.a = static_cast<uint32_t>(status);
                params[2].value.b = static_cast<uint32_t>(outType);
                copyLogsToParam(sess, t3, params[3]);
                return TEE_SUCCESS;
            }

            case TA_GATEWAY_CMD_SECURE_MARSHAL_OT_TO_IT: {
                if (t0 != TEE_PARAM_TYPE_MEMREF_INPUT || t1 != TEE_PARAM_TYPE_MEMREF_OUTPUT
                    || t2 != TEE_PARAM_TYPE_VALUE_OUTPUT) {
                    return TEE_ERROR_BAD_PARAMETERS;
                }
                const auto* buf = static_cast<const uint8_t*>(params[0].memref.buffer);
                const size_t total = params[0].memref.size;
                if (total < 8) {
                    params[2].value.a = static_cast<uint32_t>(GW_ERR_ARGS);
                    return TEE_SUCCESS;
                }
                uint64_t ptpTime = 0;
                for (int i = 0; i < 8; ++i) {
                    ptpTime = (ptpTime << 8) | buf[i];
                }
                const Bytes otPkt(buf + 8, buf + total);

                Bytes outItPkt;
                int status = sess->secureMarshalOtToIt(otPkt, ptpTime, outItPkt);
                if (status == GW_OK) {
                    if (outItPkt.size() > params[1].memref.size) {
                        status = GW_ERR_BUFFER;
                        params[1].memref.size = 0;
                    } else {
                        std::memcpy(params[1].memref.buffer, outItPkt.data(), outItPkt.size());
                        params[1].memref.size = static_cast<uint32_t>(outItPkt.size());
                    }
                } else {
                    params[1].memref.size = 0;
                }
                params[2].value.a = static_cast<uint32_t>(status);
                copyLogsToParam(sess, t3, params[3]);
                return TEE_SUCCESS;
            }

            case TA_GATEWAY_CMD_TRIGGER_HANDOVER: {
                if (t0 != TEE_PARAM_TYPE_MEMREF_INPUT || t1 != TEE_PARAM_TYPE_MEMREF_OUTPUT
                    || t2 != TEE_PARAM_TYPE_VALUE_OUTPUT) {
                    return TEE_ERROR_BAD_PARAMETERS;
                }
                const auto* buf = static_cast<const uint8_t*>(params[0].memref.buffer);
                const Bytes in(buf, buf + params[0].memref.size);
                wire::Reader r(in);
                const uint64_t ti = r.uint(8);
                const std::string session = toStr(r.field());

                Block tau{};
                Bytes yv, authD;
                int status = sess->triggerHandover(session, ti, tau, yv, authD);
                if (status == GW_OK) {
                    Bytes out;
                    out.insert(out.end(), tau.begin(), tau.end());
                    wire::putField(out, yv);
                    wire::putField(out, authD);
                    if (out.size() > params[1].memref.size) {
                        status = GW_ERR_BUFFER;
                        params[1].memref.size = 0;
                    } else {
                        std::memcpy(params[1].memref.buffer, out.data(), out.size());
                        params[1].memref.size = static_cast<uint32_t>(out.size());
                    }
                } else {
                    params[1].memref.size = 0;
                }
                params[2].value.a = static_cast<uint32_t>(status);
                copyLogsToParam(sess, t3, params[3]);
                return TEE_SUCCESS;
            }

            case TA_GATEWAY_CMD_RECEIVE_FORWARDING_NOTICE: {
                if (t0 != TEE_PARAM_TYPE_MEMREF_INPUT || t1 != TEE_PARAM_TYPE_MEMREF_OUTPUT
                    || t2 != TEE_PARAM_TYPE_VALUE_OUTPUT) {
                    return TEE_ERROR_BAD_PARAMETERS;
                }
                const auto* buf = static_cast<const uint8_t*>(params[0].memref.buffer);
                const Bytes in(buf, buf + params[0].memref.size);
                wire::Reader r(in);
                const std::string session = toStr(r.field());
                const Block tau = r.block();
                const Bytes yv = r.field();
                const Bytes authD = r.field();

                Bytes yg;
                int status = sess->receiveForwardingNotice(session, yv, tau, authD, yg);
                if (status == GW_OK) {
                    if (yg.size() > params[1].memref.size) {
                        status = GW_ERR_BUFFER;
                        params[1].memref.size = 0;
                    } else {
                        std::memcpy(params[1].memref.buffer, yg.data(), yg.size());
                        params[1].memref.size = static_cast<uint32_t>(yg.size());
                    }
                } else {
                    params[1].memref.size = 0;
                }
                params[2].value.a = static_cast<uint32_t>(status);
                copyLogsToParam(sess, t3, params[3]);
                return TEE_SUCCESS;
            }

            default:
                return TEE_ERROR_BAD_PARAMETERS;
        }
    } catch (...) {
        return TEE_ERROR_GENERIC;
    }
}

} // extern "C"

#endif // __OPTEE_TA__

