// OCALLs of Enclave.edl: what the enclave asks the Non-Secure World to do

#include "Enclave_u.h"
#include "Trace.h"
#include "gateway.h"
#include "modes.h"
#include <cstdio>
#include <string>

namespace
{

std::string gSealedStateFile = "gateway.sealed";

} // namespace

void setSealedStatePath(const std::string& path)
{
    gSealedStateFile = path;
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
    std::FILE* file = std::fopen(gSealedStateFile.c_str(), "wb");
    if (!file) {
        return -1;
    }
    const size_t written = std::fwrite(sealed_blob, 1, len, file);
    std::fclose(file);
    return written == len ? static_cast<int>(len) : -1;
}

int ocall_load_sealed_state(uint8_t* sealed_blob, size_t max_len)
{
    std::FILE* file = std::fopen(gSealedStateFile.c_str(), "rb");
    if (!file) {
        return 0; // nothing saved yet
    }
    const size_t read = std::fread(sealed_blob, 1, max_len, file);
    const bool tooLarge = std::fgetc(file) != EOF;
    std::fclose(file);
    return tooLarge ? -1 : static_cast<int>(read);
}
