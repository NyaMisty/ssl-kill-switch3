ARCHS := arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SSLKillSwitch2
SSLKillSwitch2_FILES = SSLKillSwitch/SSLKillSwitch.m
SSLKillSwitch2_CFLAGS = -fobjc-arc
SSLKillSwitch2_CFLAGS += -ISSLKillSwitch/fishhook

SSLKillSwitch2_FRAMEWORKS = Security

ifndef FISHHOOK

ifndef ROOTLESS
$(info Build as a ROOTFUL Substrate Tweak)
PACKAGE_BUILDNAME := rootful
else # ROOTLESS
$(info Build as a ROOTLESS Substrate Tweak)
THEOS_PACKAGE_SCHEME=rootless
PACKAGE_BUILDNAME := rootless
endif # ROOTLESS

ifneq ($(findstring DEBUG,$(THEOS_SCHEMA)),)
PACKAGE_BUILDNAME := $(PACKAGE_BUILDNAME)debug
endif

SSLKillSwitch2_CFLAGS += -DSUBSTRATE_BUILD

else  # FISHHOOK

$(info Build as a FishHook Tweak)
SSLKillSwitch2_FILES += SSLKillSwitch/fishhook/fishhook.c
# avoid linking Substrate
SSLKillSwitch2_LOGOS_DEFAULT_GENERATOR = internal

endif # FISHHOOK

include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/aggregate.mk


after-install::
	# Respring the device
	install.exec "killall -9 SpringBoard"
