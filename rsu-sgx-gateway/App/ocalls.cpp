// OCALLs of Enclave.edl: what the enclave asks the Non-Secure World to do

#include "ocalls.h"
#include "Enclave_u.h"
#include "Trace.h"
#include "gateway.h"
#include <cstdio>
#include <map>
#include <mutex>
#include <string>

namespace
{

std::mutex gMutex;
std::string gSealedStateFile = "gateway.sealed";                // the enclaves without their own
std::map<sgx_enclave_id_t, std::string> gSealedStateFiles;      // per enclave
thread_local sgx_enclave_id_t gCurrentEnclave = 0;              // EnclaveScope of this thread (0: none)

// the file of the enclave this thread is in an ECALL of
std::string sealedStateFile()
{
    std::lock_guard<std::mutex> lock(gMutex);
    const auto file = gSealedStateFiles.find(gCurrentEnclave);
    return file != gSealedStateFiles.end() ? file->second : gSealedStateFile;
}

} // namespace

void setSealedStatePath(const std::string& path)
{
    std::lock_guard<std::mutex> lock(gMutex);
    gSealedStateFile = path;
}

void setSealedStatePath(sgx_enclave_id_t eid, const std::string& path)
{
    std::lock_guard<std::mutex> lock(gMutex);
    gSealedStateFiles[eid] = path;
}

EnclaveScope::EnclaveScope(sgx_enclave_id_t eid) : mPrevious(gCurrentEnclave)
{
    gCurrentEnclave = eid;
}

EnclaveScope::~EnclaveScope()
{
    gCurrentEnclave = mPrevious;
}

// a line under the RSU's current step (common/Trace.h), from inside the enclave; kCheckOk / kCheckFailed: a validation
void ocall_print(const char* str)
{
    const std::string text = str;
    for (bool ok : { true, false }) {
        const std::string mark = ok ? kCheckOk : kCheckFailed;
        if (text.rfind(mark, 0) == 0) {
            trace::check("enclave", ok, text.substr(mark.size()));
            return;
        }
    }
    trace::detail("enclave", text);
}

// the blob is sealed by the enclave (sgx_seal_data): the App only stores bytes it cannot read
int ocall_save_sealed_state(const uint8_t* sealed_blob, size_t len)
{
    std::FILE* file = std::fopen(sealedStateFile().c_str(), "wb");
    if (!file) {
        return -1;
    }
    const size_t written = std::fwrite(sealed_blob, 1, len, file);
    std::fclose(file);
    return written == len ? static_cast<int>(len) : -1;
}

int ocall_load_sealed_state(uint8_t* sealed_blob, size_t max_len)
{
    std::FILE* file = std::fopen(sealedStateFile().c_str(), "rb");
    if (!file) {
        return 0; // nothing saved yet
    }
    const size_t read = std::fread(sealed_blob, 1, max_len, file);
    const bool tooLarge = std::fgetc(file) != EOF;
    std::fclose(file);
    return tooLarge ? -1 : static_cast<int>(read);
}
