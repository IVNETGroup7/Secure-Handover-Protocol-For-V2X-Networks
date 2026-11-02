CFG_TEE_TA_LOG_LEVEL ?= 2

# Trusted Application UUID: 9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718
BINARY = 9a4c5e10-6b2f-4d8e-a1b2-c3d4e5f60718

# Include paths for shared TA header and common V2X headers
CPPFLAGS += -I../include -I../../common -D__OPTEE_TA__

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
	@echo 'Note: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk not found, skipping TA clean'
	@rm -f *.o *.d *.ta *.elf *.dmp *.map
endif

