#include "MessageType.h"

const char* messageTypeName(int type)
{
    switch (type) {
        case Activation_Request:  return "Activation_Request";
        case Activation_Token:    return "Activation_Token";
        case PTP:                 return "PTP";
        case ECDH_Request:        return "ECDH_Request";
        case ECDH_Response:       return "ECDH_Response";
        case Auth_Request:        return "Auth_Request";
        case Auth_Granted:        return "Auth_Granted";
        case Active_01:           return "Active_01";
        case Active_02:           return "Active_02";
        case Active_03:           return "Active_03";
        case PTP_Sync:            return "PTP_Sync";
        case PTP_Delay_Request:   return "PTP_Delay_Request";
        case PTP_Delay_Response:  return "PTP_Delay_Response";
        case Forwarding_Notice:   return "Forwarding_Notice";
        case Forwarding_Request:  return "Forwarding_Request";
        case Forwarding_Granted:  return "Forwarding_Granted";
        case Secure_Data:         return "Secure_Data";
        case Handover_Predict:    return "Handover_Predict";
        default:                  return "?";
    }
}

