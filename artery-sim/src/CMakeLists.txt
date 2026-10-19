# the Artery feature of tee_v2x_handover (../CMakeLists.txt): its modules; this folder is their NED folder
add_artery_feature(tee_v2x BackhaulBroker.cc TeeRsuService.cc VehicleTeeService.cc)
set_target_properties(tee_v2x PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    NED_FOLDERS ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(tee_v2x PRIVATE tee_v2x_protocol)
# the repository's symbols (BootstrapService, ExternalSecurityAgent, sha256...) stay inside this library: another
# Artery feature may define the same names (e.g. a port of the bootstrap); the SGX runtime is found by path
target_link_options(tee_v2x PRIVATE -Wl,--exclude-libs,ALL -Wl,-rpath,${SGX_SDK}/sdk_libs)
