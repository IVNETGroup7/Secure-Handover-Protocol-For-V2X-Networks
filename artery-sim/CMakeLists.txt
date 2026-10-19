# tee_v2x_handover: the Secrecy Forwarding over ITS-G5 with the SGX gateway as the RSUs (2 RSUs, 1 vehicle, a
# 1 km highway). Not a project of its own: a part of Artery's build, which setup_artery.sh registers at the end of
# Artery's scenarios/CMakeLists.txt:
#   add_subdirectory(<this folder> ${CMAKE_BINARY_DIR}/scenarios/tee_v2x_handover)
# Targets
#   tee_v2x_enclave         make -C ../rsu-sgx-gateway: enclave.signed.so and the untrusted bridge App/Enclave_u.c
#   tee_v2x_protocol        the repository's code for the simulation: common/, protocol/, net/ and the gateway's
#                           Non-Secure World (PacketManager, OCALLs), with WITH_OMNETPP (common/SimTime.h)
#   tee_v2x                 the Artery feature (src/): BackhaulBroker, TeeRsuService, VehicleTeeService
#   run_tee_v2x_handover    runs scenario/omnetpp.ini (cmake --build <build> --target run_tee_v2x_handover)
# Needs the Intel SGX SDK and SGX-SSL on this machine (setup_artery.sh --install-sgx); without them the scenario is
# skipped and the rest of Artery builds as usual.

get_filename_component(TEE_V2X_DIR ${CMAKE_CURRENT_SOURCE_DIR} REALPATH)
get_filename_component(TEE_V2X_REPO ${TEE_V2X_DIR}/.. REALPATH)
set(TEE_V2X_GATEWAY ${TEE_V2X_REPO}/rsu-sgx-gateway)

if(DEFINED ENV{SGX_SDK})
    set(_tee_v2x_sgx_sdk $ENV{SGX_SDK})
else()
    set(_tee_v2x_sgx_sdk /opt/intel/sgxsdk)
endif()
set(SGX_SDK ${_tee_v2x_sgx_sdk} CACHE PATH "Intel SGX SDK (tee_v2x_handover)")
set(SGXSSL /opt/intel/sgxssl CACHE PATH "Intel SGX-SSL (tee_v2x_handover)")
set(SGX_MODE SIM CACHE STRING "SGX mode of the enclave and of the untrusted runtime: SIM or HW")

if(NOT EXISTS ${SGX_SDK}/include/sgx_urts.h OR NOT EXISTS ${SGXSSL}/lib64/libsgx_usgxssl.a)
    message(WARNING "tee_v2x_handover skipped: no Intel SGX SDK at ${SGX_SDK} or no SGX-SSL at ${SGXSSL} "
        "(artery-sim/setup_artery.sh --install-sgx installs both)")
    return()
endif()

find_package(OpenSSL 3 REQUIRED)
find_program(TEE_V2X_MAKE make)
if(NOT TEE_V2X_MAKE)
    message(FATAL_ERROR "tee_v2x_handover: no make (the SGX gateway builds with its own Makefile)")
endif()
if(SGX_MODE STREQUAL "HW")
    set(_tee_v2x_sgx_suffix "")
else()
    set(_tee_v2x_sgx_suffix "_sim")
endif()

# the enclave and the generated bridge, by the gateway's own Makefile (it runs every build and does nothing when
# they are up to date)
add_custom_target(tee_v2x_enclave
    COMMAND ${TEE_V2X_MAKE} -C ${TEE_V2X_GATEWAY} SGX_SDK=${SGX_SDK} SGXSSL=${SGXSSL} SGX_MODE=${SGX_MODE} all
    BYPRODUCTS ${TEE_V2X_GATEWAY}/App/Enclave_u.c ${TEE_V2X_GATEWAY}/App/Enclave_u.h
        ${TEE_V2X_GATEWAY}/enclave.signed.so
    COMMENT "SGX gateway: enclave.signed.so and App/Enclave_u.c (make -C rsu-sgx-gateway)"
    VERBATIM)

file(GLOB _tee_v2x_sources ${TEE_V2X_REPO}/common/*.cpp ${TEE_V2X_REPO}/protocol/*.cpp ${TEE_V2X_REPO}/net/*.cpp)
add_library(tee_v2x_protocol STATIC ${_tee_v2x_sources}
    ${TEE_V2X_GATEWAY}/App/packet_manager.cpp
    ${TEE_V2X_GATEWAY}/App/ocalls.cpp
    ${TEE_V2X_GATEWAY}/App/benchmark.cpp
    ${TEE_V2X_GATEWAY}/App/Enclave_u.c)
add_dependencies(tee_v2x_protocol tee_v2x_enclave)
set_target_properties(tee_v2x_protocol PROPERTIES
    POSITION_INDEPENDENT_CODE ON    # linked into the shared library of the feature
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON)
target_compile_definitions(tee_v2x_protocol PUBLIC WITH_OMNETPP)
target_include_directories(tee_v2x_protocol PUBLIC
    ${TEE_V2X_REPO}/common ${TEE_V2X_REPO}/protocol ${TEE_V2X_REPO}/net
    ${TEE_V2X_GATEWAY}/App ${TEE_V2X_GATEWAY}/Enclave ${SGX_SDK}/include)
target_link_libraries(tee_v2x_protocol PUBLIC
    OmnetPP::header OpenSSL::SSL OpenSSL::Crypto
    ${SGX_SDK}/lib64/libsgx_urts${_tee_v2x_sgx_suffix}.so
    ${SGX_SDK}/lib64/libsgx_uae_service${_tee_v2x_sgx_suffix}.so
    ${SGXSSL}/lib64/libsgx_usgxssl.a)

add_subdirectory(src)

add_opp_run(tee_v2x_handover
    WORKING_DIRECTORY ${TEE_V2X_DIR}/scenario
    NED_FOLDERS ${TEE_V2X_DIR}/scenario)
