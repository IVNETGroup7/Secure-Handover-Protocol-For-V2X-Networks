#ifndef BOOTSTRAP_BOOTSTRAPTYPE_H_
#define BOOTSTRAP_BOOTSTRAPTYPE_H_

// Types of the bootstrap messages (BootstrapMsg.type). No dependencies: also used by the SGX gateway
// (rsu-sgx-gateway), inside the enclave

enum BootstrapType
{
    Activation_Request = 0,
    HTTPS_Session = 1,
    Activation_Token = 2,
    PTP = 3,
    ECDH_Request = 4,
    ECDH_Response = 5,
    Auth_Request = 6,
    Save_RSU = 7,
    Auth_Granted = 8,
    Save_Vehicle = 9,
    Active_01 = 10,
    Active_02 = 11,
    Active_03 = 12,
    PTP_Sync = 13,
    PTP_Delay_Request = 14,
    PTP_Delay_Response = 15,
    Forwarding_Notice = 16,
    Handover_Command = 17,
    Forwarding_Request = 18,
    Forwarding_Granted = 19,
};

#endif /* BOOTSTRAP_BOOTSTRAPTYPE_H_ */
