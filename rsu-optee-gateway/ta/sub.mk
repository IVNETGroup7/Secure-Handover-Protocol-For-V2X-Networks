global-incdirs-y += .
global-incdirs-y += ../include
global-incdirs-y += ../../common

cppflags-y += -std=c++17 -D__OPTEE_TA__

srcs-y += ta_entry.cpp
srcs-y += gateway_session.cpp
srcs-y += crypto_tee.cpp
srcs-y += codec.cpp
srcs-y += ../../common/SmartData.cpp

