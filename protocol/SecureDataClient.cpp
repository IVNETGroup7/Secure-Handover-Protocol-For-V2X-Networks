#include "SecureDataClient.h"
#include "MessageType.h"
#include <stdexcept>

SmartData SecureDataClient::send(const Bytes& value, uint32_t location, uint32_t metadata)
{
    if (!mSession.isActivated()) {
        throw std::runtime_error(mSession.name() + ": Secure_Data before activation");
    }

    SmartData data;
    data.location = location;
    data.timing = static_cast<uint64_t>(mSession.localClock().ns());
    data.metadata = metadata;
    data.value = value;
    data.authD = mSession.traits().authD;

    const DataMessage sealed = sealSmartData(
        data, mSession.groupKey(), mSession.kDg(), mSession.localClock().ns());
    SecureDataPayload m;
    m.type = Secure_Data;
    m.cipherData = sealed.sealedData;
    m.authD = sealed.authD;
    m.otp = sealed.otp;
    mSession.send(Secure_Data, mSession.currentRsu(), 0, 0, "", pack(m));
    return data;
}

