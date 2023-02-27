TARGET := macosx:clang:latest
ARCHS := x86_64

include $(THEOS)/makefiles/common.mk

TOOL_NAME = SSLKillSwitchTest
SSLKillSwitchTest_FILES = SSLKillSwitchTests.m
SSLKillSwitchTest_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tool.mk
