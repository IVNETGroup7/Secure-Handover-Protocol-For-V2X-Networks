#ifndef COMMON_MESSAGETYPE_H_
#define COMMON_MESSAGETYPE_H_

// Message types exchanged across the V2X protocol stack:
//   - Initial Bootstrap (Vehicle <-> first RSU <-> ESA)
//   - Handover / Secrecy Forwarding (RSU <-> RSU <-> Vehicle)
//   - Authenticated Telemetry / OT Data Plane (Vehicle -> RSU TA -> Cloud)

enum MessageType
{
    // Initial Bootstrap (RSU <-> Vehicle <-> ESA)
    Activation_Request  = 0,
    Activation_Token    = 2,
    PTP                 = 3,
    ECDH_Request        = 4,
    ECDH_Response       = 5,
    Auth_Request        = 6,
    Auth_Granted        = 8,
    Active_01           = 10,
    Active_02           = 11,
    Active_03           = 12,
    PTP_Sync            = 13,
    PTP_Delay_Request   = 14,
    PTP_Delay_Response  = 15,

    // Secrecy Forwarding Handover (RSU <-> RSU <-> Vehicle, no ESA)
    Forwarding_Notice   = 16,
    Forwarding_Request  = 18,
    Forwarding_Granted  = 19,
    Handover_Predict    = 21,

    // Authenticated Data Plane (OT -> RSU TA -> Cloud IT)
    Secure_Data         = 20,
};

const char* messageTypeName(int type);

inline bool isBootstrapClientMessage(int type)
{
    return type == PTP_Sync
        || type == PTP_Delay_Response
        || type == ECDH_Response
        || type == Auth_Granted;
}

inline bool isHandoverClientMessage(int type)
{
    return type == Forwarding_Granted;
}

#endif /* COMMON_MESSAGETYPE_H_ */

