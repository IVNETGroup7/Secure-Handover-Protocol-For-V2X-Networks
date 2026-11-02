# tee_v2x_handover: the Secrecy Forwarding over ITS-G5 with the OP-TEE gateway as the RSUs (2 RSUs, 1 vehicle, a
# 1 km highway). Not a project of its own: a part of Artery's build, which setup_artery.sh registers at the end of
# Artery's scenarios/CMakeLists.txt:
#   add_subdirectory(<this folder> ${CMAKE_BINARY_DIR}/scenarios/tee_v2x_handover)
# Targets
#   tee_v2x_protocol        the repository's code for the simulation: common/, protocol/, net/ and the OP-TEE
#                           gateway (PacketManager, TeeSession, GatewayTaSession), with WITH_OMNETPP (common/SimTime.h)
#   tee_v2x                 the Artery feature (src/): BackhaulBroker, TeeRsuService, VehicleTeeService
#   run_tee_v2x_handover    runs scenario/omnetpp.ini (cmake --build <build> --target run_tee_v2x_handover)

get_filename_component(TEE_V2X_DIR ${CMAKE_CURRENT_SOURCE_DIR} REALPATH)
get_filename_component(TEE_V2X_REPO ${TEE_V2X_DIR}/.. REALPATH)
set(TEE_V2X_GATEWAY ${TEE_V2X_REPO}/rsu-optee-gateway)

find_package(OpenSSL 3 REQUIRED)

file(GLOB _tee_v2x_sources ${TEE_V2X_REPO}/common/*.cpp ${TEE_V2X_REPO}/protocol/*.cpp ${TEE_V2X_REPO}/net/*.cpp)
add_library(tee_v2x_protocol STATIC ${_tee_v2x_sources}
    ${TEE_V2X_GATEWAY}/host/packet_manager.cpp
    ${TEE_V2X_GATEWAY}/host/tee_session.cpp
    ${TEE_V2X_GATEWAY}/host/benchmark.cpp
    ${TEE_V2X_GATEWAY}/ta/codec.cpp
    ${TEE_V2X_GATEWAY}/ta/crypto_tee.cpp
    ${TEE_V2X_GATEWAY}/ta/gateway_session.cpp)
set_target_properties(tee_v2x_protocol PROPERTIES
    POSITION_INDEPENDENT_CODE ON    # linked into the shared library of the feature
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON)
target_compile_definitions(tee_v2x_protocol PUBLIC WITH_OMNETPP)
target_include_directories(tee_v2x_protocol PUBLIC
    ${TEE_V2X_REPO}/common ${TEE_V2X_REPO}/protocol ${TEE_V2X_REPO}/net
    ${TEE_V2X_GATEWAY}/include ${TEE_V2X_GATEWAY}/host ${TEE_V2X_GATEWAY}/ta)
target_link_libraries(tee_v2x_protocol PUBLIC
    OmnetPP::header OpenSSL::SSL OpenSSL::Crypto)

add_subdirectory(src)

set(SIMU5G_NED_DIR "" CACHE PATH "Path to Simu5G src/ directory")
if (NOT SIMU5G_NED_DIR AND EXISTS "${TEE_V2X_DIR}/deps/simu5g/src")
    set(SIMU5G_NED_DIR "${TEE_V2X_DIR}/deps/simu5g/src")
endif()

set(_tee_v2x_ned_folders ${TEE_V2X_DIR}/scenario)
if (SIMU5G_NED_DIR)
    list(APPEND _tee_v2x_ned_folders ${SIMU5G_NED_DIR})
endif()

add_opp_run(tee_v2x_handover
    WORKING_DIRECTORY ${TEE_V2X_DIR}/scenario
    NED_FOLDERS ${_tee_v2x_ned_folders})
