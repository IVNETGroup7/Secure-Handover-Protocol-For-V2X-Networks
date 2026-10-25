#ifndef BOOTSTRAP_BOOTSTRAPTYPE_H_
#define BOOTSTRAP_BOOTSTRAPTYPE_H_

// Types of the bootstrap messages (BootstrapMsg.type). No dependencies: also used by the SGX gateway
// (rsu-sgx-gateway), inside the enclave

enum BootstrapType
{
    // Bootstrap handshake wire messages
    Activation_Request = 0,
    Activation_Token = 2,
    ECDH_Request = 4,
    ECDH_Response = 5,
    Auth_Request = 6,
    Auth_Granted = 8,
    Active_01 = 10,
    Active_02 = 11,
    Active_03 = 12,

    // PTP time synchronization wire messages
    PTP_Sync = 13,
    PTP_Delay_Request = 14,
    PTP_Delay_Response = 15,

    // Handover / Secrecy Forwarding wire messages
    Forwarding_Notice = 16,
    Handover_Command = 17,
    Forwarding_Request = 18,
    Forwarding_Granted = 19,

    // Internal milestones / trace markers (never transmitted as packet types on the wire)
    HTTPS_Session = 1,
    PTP = 3,
    Save_RSU = 7,
    Save_Vehicle = 9,
};

// Internal trace and state milestones
enum class TraceMilestone
{
    HttpsEstablished,
    PtpCompleted,
    RsuSessionBound,
    VehicleActivated,
    HandoverNoticeReceived,
    HandoverCompleted
};

#endif /* BOOTSTRAP_BOOTSTRAPTYPE_H_ */
