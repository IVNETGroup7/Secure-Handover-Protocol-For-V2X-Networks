#ifndef PROTOCOL_BOOTSTRAPCLIENT_H_
#define PROTOCOL_BOOTSTRAPCLIENT_H_

// Initial vehicle-to-RSU secure bootstrap protocol (Phase B & C on the OT side).
// Phase A (Activation_Request -> ESA -> Activation_Token) runs strictly out-of-band in the IT
// domain via HumanOperator; the vehicle never transmits UUID_d or SHA256(fw_d) over OT radio.
//
// OT message flow:
//   PTP -> PTP_Sync / PTP_Delay_Request / PTP_Delay_Response
//   -> ECDH_Request / ECDH_Response -> Auth_Request / Auth_Granted (SaveVehicle) -> Active_01.

#include "Crypto.h"
#include "SimTime.h"
#include "VehicleSession.h"
#include <cstdint>
#include <functional>
#include <string>

class ProtocolMsg;

struct BootstrapResult
{
    std::string vehicle;
    std::string rsu;
    Bytes kDg;          // K_dg: ECDH key shared by the vehicle and the initial RSU
    Bytes kG;           // K_g: group key (AES-128-GCM) of the initial RSU
    Bytes kDe;          // K_de: vehicle <-> ESA session key (bound to Active_01's fresh OTP_dt)
    Bytes authD;        // Auth_d: vehicle identity authenticator carried by telemetry packets
    Block authReqOtp{}; // Step 6 OTP_dt sent in Auth_Request
    Block activeOtp{};  // Step 10 fresh OTP_dt generated for Active_01 (distinct from authReqOtp)
};

using BootstrapCallback = std::function<void(const BootstrapResult&)>;
using BootstrapFailureCallback = std::function<void(const std::string& reason)>;

class BootstrapClient
{
    public:
        struct Config
        {
            std::string targetRsu = "rsu[0]";   // Link-layer address of initial OT gateway (untrusted until Auth_eg)
            bool autoStart = true;              // false = wait for explicit start()
        };

        BootstrapClient(VehicleSession& session, Config config);

        void trigger();
        void start(BootstrapCallback onCompleted = nullptr);
        void setFailureCallback(BootstrapFailureCallback onFailed) { mOnFailed = std::move(onFailed); }
        void handleMessage(const ProtocolMsg& msg);

    private:
        void ptpRequest();
        void ptpDelayRequest(const ProtocolMsg& received);
        void ecdhRequest(const ProtocolMsg& received);
        void authRequest(const ProtocolMsg& received);
        void saveVehicle(const ProtocolMsg& received);
        void active01(const ProtocolMsg& received);

        void fail(const std::string& reason);
        void correctClock(simtime_t t1, simtime_t t2, simtime_t t3, simtime_t t4);

        void printStep(const char* step, const ProtocolMsg* received = nullptr) const;
        void printDetail(const std::string& text) const;
        void printCheck(bool ok, const std::string& text) const;
        void printKeep(const std::string& name, const Bytes& value) const;

        VehicleSession& mSession;
        Config mConfig;
        BootstrapCallback mOnCompleted;
        BootstrapFailureCallback mOnFailed;
        bool mStarted = false;

        simtime_t mPtpT1;
        simtime_t mPtpT2;
        simtime_t mPtpT3;

        Bytes mPendingKdg;
        Block mAuthReqOtp{};
        Block mActiveOtp{};
        uint64_t mOtpSlot = 0;
        Bytes mEsaPublicKey;
        Bytes mAuthDe;
        Bytes mKde;
};

#endif /* PROTOCOL_BOOTSTRAPCLIENT_H_ */
