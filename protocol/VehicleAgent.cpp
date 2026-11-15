#include "VehicleAgent.h"
#include "MessageType.h"
#include "ProtocolMsg.h"
#include <iostream>

VehicleAgent::VehicleAgent(const Config& config) :
    mSession(config.name, config.seed, config.clockOffset),
    mBootstrap(mSession, BootstrapClient::Config{ config.gatewayPublicKey, config.autoStart }),
    mHandover(mSession, config.deferHandover),
    mData(mSession)
{
}

void VehicleAgent::setTransport(VehicleSession::Transport transport)
{
    mSession.setTransport(std::move(transport));
}

void VehicleAgent::indicate(const ProtocolMsg& msg)
{
    if (msg.getDestination() != mSession.name()) {
        return;
    }
    mSession.recordReceived();

    const int type = msg.getType();
    if (isBootstrapClientMessage(type)) {
        mBootstrap.handleMessage(msg);
    } else if (isHandoverClientMessage(type)) {
        mHandover.handleMessage(msg);
    } else {
        std::cerr << mSession.name() << ": unexpected message type "
                  << messageTypeName(type) << std::endl;
    }
}

