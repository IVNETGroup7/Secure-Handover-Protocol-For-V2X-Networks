#ifndef PROTOCOL_BOOTSTRAPCLIENT_H_
#define PROTOCOL_BOOTSTRAPCLIENT_H_

// Initial vehicle-to-RSU secure bootstrap protocol (with ESA authorization and IEEE 1588 PTP sync).
// Covers strictly the first-time authentication flow:
//   Activation_Request -> PTP_Sync / PTP_Delay_Request / PTP_Delay_Response
//   -> ECDH_Request / ECDH_Response -> Auth_Request / Auth_Granted (SaveVehicle) -> Active_01.

#include "Crypto.h"
#include "SimTime.h"
#include "VehicleSession.h"
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

class ProtocolMsg;

struct BootstrapResult
{
    std::string vehicle;
    std::string rsu;
    Bytes kDg;      // K_dg: ECDH key shared by the vehicle and the initial RSU
    Bytes kG;       // K_g: group key (AES-128-GCM) of the initial RSU
    Bytes kDe;      // K_de: vehicle <-> ESA session key
    Bytes authD;    // Auth_d: vehicle identity authenticator carried by telemetry packets
};

using BootstrapCallback = std::function<void(const BootstrapResult&)>;
using BootstrapFailureCallback = std::function<void(const std::string& reason)>;

class BootstrapClient
{
    public:
        struct Config
        {
            Bytes gatewayPublicKey;     // CY_g: public key of the initial target RSU certificate
            bool autoStart = true;      // false = wait for explicit start()
        };

        BootstrapClient(VehicleSession& session, Config config);

        void trigger();
        void start(BootstrapCallback onCompleted = nullptr);
        void setFailureCallback(BootstrapFailureCallback onFailed) { mOnFailed = std::move(onFailed); }
        void handleMessage(const ProtocolMsg& msg);

    private:
        void activationRequest();
        void ptpDelayRequest(const ProtocolMsg& received);
        void ecdhRequest(const ProtocolMsg& received);
        void authRequest(const ProtocolMsg& received);
        void saveVehicle(const ProtocolMsg& received);
        void active01(const ProtocolMsg& received);

        bool withinWindow();
        void fail(const std::string& reason);
        void correctClock(simtime_t t1, simtime_t t2, simtime_t t3, simtime_t t4);

        void printStep(const char* step, const ProtocolMsg* received = nullptr) const;
        void printDetail(const std::string& text) const;
        void printCheck(bool ok, const std::string& text) const;
        void printKeep(const std::string& name, const Bytes& value) const;

        struct ActivationWindow
        {
            simtime_t t0;
            simtime_t tf;
        };

        VehicleSession& mSession;
        Config mConfig;
        BootstrapCallback mOnCompleted;
        BootstrapFailureCallback mOnFailed;
        bool mStarted = false;

        std::optional<ActivationWindow> mWindow;
        simtime_t mPtpT1;
        simtime_t mPtpT2;
        simtime_t mPtpT3;

        Bytes mPendingKdg;
        Block mOtpSent{};
        uint64_t mOtpSlot = 0;
        Bytes mEsaPublicKey;
        Bytes mAuthDe;
        Bytes mKde;
};

#endif /* PROTOCOL_BOOTSTRAPCLIENT_H_ */

