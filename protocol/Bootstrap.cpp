#include "Bootstrap.h"
#include "BootstrapService.h"

void initBootstrap(BootstrapService& service, BootstrapCallback onCompleted)
{
    service.start(std::move(onCompleted));
}
