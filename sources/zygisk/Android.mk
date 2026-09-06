LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := stealth
LOCAL_SRC_FILES := stealth_ultimate.cpp
# No STL runtime needed: the code uses only C library functions (calloc/free/
# memcpy/snprintf). The C++ code is limited to zygisk.hpp templates that inline.
# This produces a .so depending only on libc/libdl/libm/liblog — all present
# in zygote, so android_dlopen_ext succeeds and Magisk accepts the module.
LOCAL_LDLIBS    := -llog
include $(BUILD_SHARED_LIBRARY)
