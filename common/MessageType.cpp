#include "MessageType.h"

const char* messageTypeName(int type)
{
    static const char* names[] = {
        "Activation_Request",
        "HTTPS_Session",
        "Activation_Token",
        "PTP",
        "ECDH_Request",
        "ECDH_Response",
        "Auth_Request",
        "Save_RSU",
        "Auth_Granted",
        "Save_Vehicle",
        "Active_01",
        "Active_02",
        "Active_03",
        "PTP_Sync",
        "PTP_Delay_Request",
        "PTP_Delay_Response",
        "Forwarding_Notice",
        "Handover_Command",
        "Forwarding_Request",
        "Forwarding_Granted",
        "Secure_Data",
        "Handover_Predict",
    };
    return (type >= 0 && type < static_cast<int>(sizeof(names) / sizeof(names[0]))) ? names[type] : "?";
}

