LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := stealth
LOCAL_SRC_FILES := stealth_ultimate.cpp
# Link to system libstdc++ so we can use the new operator and basic C++.
# This is the upstream-recommended configuration for Zygisk modules that
# do not need a full STL runtime, and produces a .so with no dependency on
# libc++_shared.so (which is absent in zygote).
LOCAL_LDLIBS    := -llog -lstdc++
include $(BUILD_SHARED_LIBRARY)
