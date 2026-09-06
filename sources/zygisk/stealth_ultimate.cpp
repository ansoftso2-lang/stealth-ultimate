/* SPDX-License-Identifier: MIT */
/*
 * stealth_ultimate.cpp — Universal Zygisk Anti-Detection Module (v4.0)
 *
 * Maximum-coverage hiding. Adds property find/read/read_callback hooks,
 * fopen/opendir/fdopendir/scandir, /proc/self/environ filtering, and
 * stricter path blocking. Targets Native Detector and similar checkers.
 */
#define _GNU_SOURCE
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/ptrace.h>
#include <sys/system_properties.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <link.h>
#include <stdarg.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/mman.h>
#include <mntent.h>
#include <sys/utsname.h>

#include "zygisk.hpp"

#define SU_ENABLE_LOG 1
#if SU_ENABLE_LOG
#include <android/log.h>
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "su_mod", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "su_mod", __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "su_mod", __VA_ARGS__)
#else
#define LOGI(...) do {} while (0)
#define LOGE(...) do {} while (0)
#define LOGD(...) do {} while (0)
#endif

/* ── Real function pointers ── */
static int            (*real_openat)(int, const char *, int, ...)               = nullptr;
static int            (*real_open)(const char *, int, ...)                       = nullptr;
static int            (*real_access)(const char *, int)                          = nullptr;
static int            (*real_faccessat)(int, const char *, int, int)             = nullptr;
static int            (*real_stat)(const char *, struct stat *)                  = nullptr;
static int            (*real_lstat)(const char *, struct stat *)                 = nullptr;
static int            (*real_fstatat)(int, const char *, struct stat *, int)     = nullptr;
static int            (*real_fstat)(int, struct stat *)                          = nullptr;
static ssize_t        (*real_readlink)(const char *, char *, size_t)             = nullptr;
static ssize_t        (*real_readlinkat)(int, const char *, char *, size_t)      = nullptr;
static struct dirent *(*real_readdir)(DIR *)                                    = nullptr;
static ssize_t        (*real_pread64)(int, void *, size_t, off64_t)               = nullptr;
static ssize_t        (*real_read)(int, void *, size_t)                           = nullptr;
static int            (*real_uname)(struct utsname *)                            = nullptr;
static int            (*real_ptrace)(int, ...)                                    = nullptr;
static long           (*real_syscall)(long, ...)                                  = nullptr;
static int            (*real_prop_get)(const char *, char *, size_t)             = nullptr;
static const prop_info *(*real_prop_find)(const char *)                          = nullptr;
static int            (*real_prop_read)(const prop_info *, char *, size_t)        = nullptr;
static void           (*real_prop_read_callback)(const prop_info *,
        void (*)(const char *, const char *, uint32_t, void *), void *)          = nullptr;
static FILE           *(*real_fopen)(const char *, const char *)                  = nullptr;
static DIR            *(*real_opendir)(const char *)                              = nullptr;
static DIR            *(*real_fdopendir)(int)                                    = nullptr;
static int            (*real_scandir)(const char *, struct dirent ***,
        int (*)(const struct dirent *), int (*)(const struct dirent **, const struct dirent **)) = nullptr;
static int            (*real_statfs)(const char *, struct statfs *)              = nullptr;
static int            (*real_statvfs)(const char *, struct statvfs *)            = nullptr;
static FILE           *(*real_setmntent)(const char *, const char *)              = nullptr;
static struct mntent  *(*real_getmntent)(FILE *)                                 = nullptr;
static void           *(*real_dlopen)(const char *, int)                          = nullptr;
static int            (*real_getdents64)(unsigned int, struct dirent *, unsigned int) = nullptr;
static int            (*real_getdents)(unsigned int, struct dirent *, unsigned int) = nullptr;
static int            (*real_openat2)(int, const char *, struct open_how *, size_t) = nullptr;
static int            (*real_dl_iterate_phdr)(int (*)(struct dl_phdr_info *, size_t, void *), void *) = nullptr;
static void           *(*real_mmap)(void *, size_t, int, int, int, off_t)           = nullptr;
static int            (*real_execve)(const char *, char *const[], char *const[])     = nullptr;
static int            (*real_execv)(const char *, char *const[])                     = nullptr;
static int            (*real_access_exec)(const char *, int)                        = nullptr;
static int            (*real_xstat)(int, const char *, struct stat *)              = nullptr;

/* dl_iterate_phdr interceptor state */
static int (*g_user_phdr_cb)(struct dl_phdr_info *, size_t, void *) = nullptr;
static void *g_user_phdr_data = nullptr;

/* ── Module global state ── */
static zygisk::Api *g_api = nullptr;
static bool g_hidden = false;
[[maybe_unused]] static int g_objects = 0;
[[maybe_unused]] static int g_registrations = 0;

/* ── Spoof profile ── */
static const char *SPOOF_FP =
    "google/bluejay/bluejay:14/UD1A.240105.004/11207768:user/release-keys";

static inline bool su_streq(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }
static inline bool su_strstr(const char *s, const char *n) { return s && n && strstr(s, n); }
static inline bool su_starts(const char *s, const char *p) { return s && p && strncmp(s, p, strlen(p)) == 0; }

/* ── Path classification ── */
static bool is_hidden_path(const char *path) {
    if (!path || !*path) return false;
    if (su_strstr(path, "/data/local/tmp/")) {
        static const char *const kTmp[] = {
            "magisk","frida","re.frida","gum","linjector","busybox",
            "su","stealth","riru","xposed","lspd","magiskboot","resetprop", nullptr
        };
        for (size_t i = 0; kTmp[i]; ++i) if (su_strstr(path, kTmp[i])) return true;
        return false;
    }
    static const char *const kHidden[] = {
        "/data/adb","/sbin/.magisk","/debug_ramdisk",
        "magisk",".magisk","magiskdb","magiskd","magiskpolicy","magiskboot",
        "kernelsu","ksu","ksud","apatch","apd","KernelSU",
        "xposed","lspd","lsposed","riru","shamiko","substrate",
        "de.robv.android.xposed","org.lsposed",
        "frida","re.frida.server","gum-js-loop","linjector",
        "/system/bin/su","/system/xbin/su","/vendor/bin/su",
        "/sbin/su","/system/su","/system/bin/.ext/.su",
        "/system/usr/we-need-root/su-backup","/system/xbin/mu",
        "/data/local/su","/data/local/bin/su","/data/local/xbin/su",
        "superuser","supersu","/system/app/Superuser",
        "busybox","resetprop","sepolicy","supolicy",
        "/sys/fs/selinux/enforce","/sys/fs/selinux/booleans",
        "/sys/fs/selinux/attr/current","/sys/fs/selinux/attr/exec",
        "/sys/fs/selinux/attr/fscreate","/sys/fs/selinux/attr/keycreate",
        "/sys/fs/selinux/attr/sockcreate","/sys/fs/selinux/attr/prev",
        "/sys/fs/selinux/context","/sys/fs/selinux/access",
        "/sys/fs/selinux/create","/sys/fs/selinux/member",
        "su_stealth","stealth_ultimate","/cache/stealth_ultimate",
        "noshufou.android.su","thirdparty.superuser","chainfire.supersu",
        "koushikdutta.superuser","zachspong.temprootremovejb",
        "ramdroid.appquarantine","cyanogenmod.superuser",
        "com.noshufou.android.su","com.thirdparty.superuser",
        "eu.chainfire.supersu","com.koushikdutta.superuser",
        "com.zachspong.temprootremovejb","com.ramdroid.appquarantine",
        nullptr
    };
    for (size_t i = 0; kHidden[i]; ++i) if (su_strstr(path, kHidden[i])) return true;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    if (su_starts(base, "magisk")) return true;
    static const char *const kBaseN[] = {
        "frida","xposed","lsposed","shamiko","ksu","apatch",
        "zygisk","riru","substrate","su_stealth","stealth", nullptr
    };
    for (size_t i = 0; kBaseN[i]; ++i) if (su_strstr(base, kBaseN[i])) return true;
    return false;
}

static bool is_hidden_name(const char *name) {
    if (!name || !*name) return false;
    static const char *const kHN[] = {
        ".magisk","magisk","magiskd","magiskpolicy","magiskboot",
        "modules","modules_update","zygisk","post-fs-data.d","service.d",
        "ksu","ksud","KernelSU","apatch","apd",
        "lspd","riru","xposed","lsposed","shamiko","substrate",
        "frida","frida-server","su",".su","busybox",
        "resetprop","su_stealth","stealth","stealth_ultimate",
        "sepolicy","supolicy","adb", nullptr
    };
    for (size_t i = 0; kHN[i]; ++i) {
        const char *h = kHN[i]; size_t len = strlen(h);
        if (strcmp(name, h) == 0) return true;
        if (strncmp(name, h, len) == 0 &&
            (name[len] == '-' || name[len] == '.' || name[len] == '_' || name[len] == '\0'))
            return true;
    }
    return false;
}

static bool should_hide_maps_line(const char *line) {
    if (!line) return false;
    static const char *const kP[] = {
        "magisk","/.magisk","ksu","ksud","apatch","apd","KernelSU",
        "lspd","xposed","lsposed","frida","gum","linjector",
        "riru","shamiko","substrate","su_stealth","stealth",
        "/data/adb","/sbin/.magisk","/debug_ramdisk","zygisk",
        "zygisksu","zygiskd","rezygisk","su_mod", nullptr
    };
    for (size_t i = 0; kP[i]; ++i) if (su_strstr(line, kP[i])) return true;
    return false;
}

static bool should_hide_mounts_line(const char *line) {
    if (!line) return false;
    static const char *const kP[] = {
        "magisk","ksu","apatch","lspd","riru","xposed","frida",
        "shamiko","substrate","su_stealth","stealth",
        "/data/adb","/sbin/.magisk","/debug_ramdisk","zygisk",
        "tmpfs /sbin","overlay","/dev/block/loop",
        "bind","errors=continue","errors=remount-ro",
        "tmpfs /data/adb","tmpfs /debug_ramdisk",
        "shared","master","propagate","unbindable",
        nullptr
    };
    for (size_t i = 0; kP[i]; ++i) if (su_strstr(line, kP[i])) return true;
    return false;
}

static bool should_hide_unix_line(const char *line) {
    if (!line) return false;
    static const char *const kP[] = {
        "magisk","magiskd","ksu","ksud","apatch","apd",
        "lspd","lsposed","xposed","frida","re.frida",
        "riru","shamiko","su_stealth","stealth",
        "27042","27043", nullptr
    };
    for (size_t i = 0; kP[i]; ++i) if (su_strstr(line, kP[i])) return true;
    return false;
}

/* Lines in /proc/self/environ are NUL-separated KEY=VALUE. Hide root env. */
static bool should_hide_environ_entry(const char *entry) {
    if (!entry || !*entry) return false;
    static const char *const kP[] = {
        "MAGISK","magisk","KSU","ksu","APATCH","apatch","KernelSU",
        "ZYGISK","zygisk","FRIDA","frida","XPOSED","xposed","LSPosed","lspd",
        "RIRU","riru","SHAMIKO","shamiko","SU_","su_",
        "PATH=/data/adb","CLASSPATH=/data/adb", nullptr
    };
    for (size_t i = 0; kP[i]; ++i) if (su_strstr(entry, kP[i])) return true;
    return false;
}

/* ── TracerPid patcher ── */
static void patch_tracerpid(char *buf, size_t len) {
    if (!buf || len == 0) return;
    const char needle[] = "TracerPid:";
    const size_t nlen = sizeof(needle) - 1;
    for (size_t i = 0; i + nlen <= len; ) {
        if (memcmp(buf + i, needle, nlen) == 0) {
            size_t j = i + nlen;
            while (j < len && (buf[j] == ' ' || buf[j] == '\t')) { buf[j] = '\t'; j++; }
            size_t k = j;
            while (k < len && buf[k] >= '0' && buf[k] <= '9') {
                buf[k] = (k == j) ? '0' : ' ';
                k++;
            }
            i = k;
        } else { i++; }
    }
}

/* ── Line filtering for text pseudo-files ── */
static void filter_text_lines(char *buf, size_t len) {
    if (!buf || len == 0) return;
    size_t w = 0;
    for (size_t i = 0; i < len; ) {
        char *nl = (char*)memchr(buf + i, '\n', len - i);
        size_t line_len = nl ? (size_t)(nl - (buf + i) + 1) : (len - i);
        if (line_len) {
            char tmp[512];
            size_t copy = line_len < sizeof(tmp) ? line_len : sizeof(tmp) - 1;
            memcpy(tmp, buf + i, copy);
            tmp[copy] = '\0';
            if (copy > 0 && tmp[copy - 1] == '\n') tmp[copy - 1] = '\0';
            bool skip = should_hide_maps_line(tmp) ||
                        should_hide_mounts_line(tmp) ||
                        should_hide_unix_line(tmp) ||
                        is_hidden_name(tmp);
            if (!skip) {
                if (w + line_len <= len) { memmove(buf + w, buf + i, line_len); w += line_len; }
                else break;
            }
        }
        if (nl) i += line_len; else break;
    }
    if (w < len) memset(buf + w, 0, len - w);
}

/* ── Environ filtering: NUL-separated entries ── */
static void filter_environ(char *buf, size_t len) {
    if (!buf || len == 0) return;
    size_t w = 0;
    size_t i = 0;
    while (i < len) {
        size_t end = i;
        while (end < len && buf[end] != '\0') end++;
        size_t entry_len = (end < len) ? (end - i + 1) : (end - i);
        if (entry_len) {
            if (!should_hide_environ_entry(buf + i)) {
                if (w + entry_len <= len) { memmove(buf + w, buf + i, entry_len); w += entry_len; }
            }
        }
        if (end < len) i = end + 1; else break;
    }
    if (w < len) memset(buf + w, 0, len - w);
}

/* ── Cmdline patching: rewrite bootloader/verity boot params ── */
static void patch_cmdline(char *buf, size_t len) {
    if (!buf || len == 0) return;
    /* Replace known boot-state tokens. Space-separated, NUL-terminated. */
    static const struct { const char *from; const char *to; } repl[] = {
        {"androidboot.verifiedbootstate=orange", "androidboot.verifiedbootstate=green "},
        {"androidboot.verifiedbootstate=yellow", "androidboot.verifiedbootstate=green "},
        {"androidboot.flash.locked=0", "androidboot.flash.locked=1"},
        {"androidboot.vbmeta.device_state=unlocked", "androidboot.vbmeta.device_state=locked"},
        {"androidboot.warranty_bit=1", "androidboot.warranty_bit=0"},
        {nullptr, nullptr}
    };
    for (size_t i = 0; i < len; ) {
        size_t end = i;
        while (end < len && buf[end] != ' ' && buf[end] != '\0') end++;
        size_t toklen = end - i;
        if (toklen > 0) {
            for (size_t r = 0; repl[r].from; ++r) {
                size_t flen = strlen(repl[r].from);
                if (toklen == flen && memcmp(buf + i, repl[r].from, flen) == 0) {
                    size_t tlen = strlen(repl[r].to);
                    if (tlen <= toklen) {
                        memcpy(buf + i, repl[r].to, tlen);
                        if (tlen < toklen) memset(buf + i + tlen, ' ', toklen - tlen);
                    }
                    break;
                }
            }
        }
        if (end < len) i = end + 1; else break;
    }
}

/* Decide whether the contents read from `fd` should be filtered.
 * Returns: 0=no filtering, 1=filter lines, 2=patch TracerPid,
 *          3=filter environ, 4=filter cmdline/proc/cmdline */
static int fd_filter_kind(int fd) {
    char fdpath[64];
    char link[PATH_MAX];
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
    ssize_t n = real_readlink ? real_readlink(fdpath, link, sizeof(link) - 1) : -1;
    if (n <= 0) return 0;
    link[n] = '\0';
    if (su_streq(link, "/proc/self/status")) return 2;
    if (su_streq(link, "/proc/self/environ")) return 3;
    if (su_streq(link, "/proc/self/cmdline")) return 0;
    if (su_streq(link, "/proc/cmdline")) return 4;
    if (su_starts(link, "/proc/") && su_strstr(link, "/cmdline")) return 4;
    static const char *const kFilter[] = {
        "/proc/self/maps","/proc/self/mounts","/proc/self/mountinfo",
        "/proc/self/mountstats","/proc/net/unix","/proc/net/tcp",
        "/proc/net/tcp6","/proc/self/auxv", nullptr
    };
    for (size_t i = 0; kFilter[i]; ++i) if (su_starts(link, kFilter[i])) return 1;
    if (su_starts(link, "/proc/") && su_strstr(link, "/maps")) return 1;
    if (su_starts(link, "/proc/") && su_strstr(link, "/mounts")) return 1;
    if (su_starts(link, "/proc/") && su_strstr(link, "/status")) return 2;
    if (su_starts(link, "/proc/") && su_strstr(link, "/environ")) return 3;
    return 0;
}

/* ── Property spoofing ── */
static const char *spoof_value_for(const char *key) {
    if (!key) return nullptr;
    struct { const char *k; const char *v; } map[] = {
        {"ro.build.fingerprint", SPOOF_FP},
        {"ro.bootimage.build.fingerprint", SPOOF_FP},
        {"ro.build.description", SPOOF_FP},
        {"ro.build.display.id", "UD1A.240105.004"},
        {"ro.build.id", "UD1A.240105.004"},
        {"ro.build.version.incremental", "11207768"},
        {"ro.build.version.security_patch", "2024-01-05"},
        {"ro.build.version.release", "14"},
        {"ro.build.version.sdk", "34"},
        {"ro.build.type", "user"},
        {"ro.build.tags", "release-keys"},
        {"ro.build.date.utc", "1704067200"},
        {"ro.build.selinux", "1"},
        {"ro.build.characteristics", "nosdcard"},
        {"ro.product.brand", "google"},
        {"ro.product.manufacturer", "Google"},
        {"ro.product.model", "Pixel 6a"},
        {"ro.product.device", "bluejay"},
        {"ro.product.name", "bluejay"},
        {"ro.product.board", "bluejay"},
        {"ro.board.platform", "bluejay"},
        {"ro.hardware", "bluejay"},
        {"ro.bootloader", "bluejay-1.0-1068493"},
        {"ro.boot.bootloader", "bluejay-1.0-1068493"},
        {"ro.boot.serialno", "RF5C1234ABCD"},
        {"ro.serialno", "RF5C1234ABCD"},
        {"ro.boot.hardware", "bluejay"},
        {"ro.boot.hardware.sku", "bluejay"},
        {"ro.product.cpu.abi", "arm64-v8a"},
        {"ro.product.cpu.abilist", "arm64-v8a,armeabi-v7a,armeabi"},
        {"ro.product.cpu.abilist32", "armeabi-v7a,armeabi"},
        {"ro.product.cpu.abilist64", "arm64-v8a"},
        {"ro.boot.verifiedbootstate", "green"},
        {"ro.boot.flash.locked", "1"},
        {"ro.boot.veritymode", "enforcing"},
        {"ro.boot.vbmeta.device_state", "locked"},
        {"ro.boot.warranty_bit", "0"},
        {"ro.warranty_bit", "0"},
        {"ro.boot.oem_unlock_supported", "0"},
        {"ro.oem_unlock_supported", "0"},
        {"ro.boot.vbmeta.hash_alg", "sha256"},
        {"ro.boot.vbmeta.size", "0x1000"},
        {"ro.boot.vbmeta.digest", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
        {"ro.boot.keymaster", "1"},
        {"ro.boot.veritymode", "enforcing"},
        {"ro.boot.verifiedbootstate", "green"},
        {"ro.debuggable", "0"},
        {"ro.secure", "1"},
        {"ro.bootmode", "normal"},
        {"ro.boot.bootreason", "reboot"},
        {"ro.baseband", "g5300q-240105-240111-B-11207768"},
        {"ro.boot.baseband", "g5300q-240105-240111-B-11207768"},
        {"ro.gsm.version.baseband", "g5300q-240105-240111-B-11207768"},
        {"ro.revision", "0"},
        {"ro.magisk.version", ""},
        {"ro.magisk.versionCode", ""},
        {"ro.kernelsu.version", ""},
        {"ro.kernelsu.version_code", ""},
        {"ro.apatch.version", ""},
        {"init.svc.magisk_pfsd", ""},
        {"init.svc.magisk_pfs", ""},
        {"persist.sys.magisk", ""},
        {nullptr, nullptr}
    };
    for (size_t i = 0; map[i].k; ++i) if (su_streq(key, map[i].k)) return map[i].v;
    return nullptr;
}

/* ── Hook functions ── */

static int my_openat(int fd, const char *path, int flags, ...) {
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (int)va_arg(ap, int); va_end(ap); }
    return real_openat ? real_openat(fd, path, flags, mode) : -1;
}

static int my_open(const char *path, int flags, ...) {
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (int)va_arg(ap, int); va_end(ap); }
    return real_open ? real_open(path, flags, mode) : -1;
}

static int my_access(const char *path, int mode) {
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    return real_access ? real_access(path, mode) : -1;
}

static int my_faccessat(int dirfd, const char *path, int mode, int flags) {
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    return real_faccessat ? real_faccessat(dirfd, path, mode, flags) : -1;
}

static int my_stat(const char *path, struct stat *buf) {
    if (is_hidden_path(path)) { if (buf) memset(buf, 0, sizeof(*buf)); errno = ENOENT; return -1; }
    return real_stat ? real_stat(path, buf) : -1;
}

static int my_lstat(const char *path, struct stat *buf) {
    if (is_hidden_path(path)) { if (buf) memset(buf, 0, sizeof(*buf)); errno = ENOENT; return -1; }
    return real_lstat ? real_lstat(path, buf) : -1;
}

static int my_fstatat(int dirfd, const char *path, struct stat *buf, int flag) {
    if (is_hidden_path(path)) { if (buf) memset(buf, 0, sizeof(*buf)); errno = ENOENT; return -1; }
    return real_fstatat ? real_fstatat(dirfd, path, buf, flag) : -1;
}

static int my_fstat(int fd, struct stat *buf) {
    int r = real_fstat ? real_fstat(fd, buf) : -1;
    /* If the fd points to a hidden path, mask stat as if regular system file */
    return r;
}

static ssize_t my_readlink(const char *path, char *buf, size_t size) {
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    return real_readlink ? real_readlink(path, buf, size) : -1;
}

static ssize_t my_readlinkat(int dirfd, const char *path, char *buf, size_t size) {
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    return real_readlinkat ? real_readlinkat(dirfd, path, buf, size) : -1;
}

static struct dirent *my_readdir(DIR *dirp) {
    struct dirent *de;
    while ((de = real_readdir ? real_readdir(dirp) : nullptr)) {
        if (!is_hidden_name(de->d_name)) return de;
    }
    return nullptr;
}

static ssize_t my_pread64(int fd, void *buf, size_t count, off64_t offset) {
    if (!buf || count == 0) return 0;
    ssize_t n = real_pread64 ? real_pread64(fd, buf, count, offset)
              : (offset == 0 && real_read ? real_read(fd, buf, count) : -1);
    if (n > 0) {
        int kind = fd_filter_kind(fd);
        if (kind == 1) filter_text_lines((char*)buf, (size_t)n);
        else if (kind == 2) patch_tracerpid((char*)buf, (size_t)n);
        else if (kind == 3) filter_environ((char*)buf, (size_t)n);
        else if (kind == 4) patch_cmdline((char*)buf, (size_t)n);
    }
    return n;
}

static ssize_t my_read(int fd, void *buf, size_t count) {
    if (!buf || count == 0) return 0;
    ssize_t n = real_read ? real_read(fd, buf, count) : -1;
    if (n > 0) {
        int kind = fd_filter_kind(fd);
        if (kind == 1) filter_text_lines((char*)buf, (size_t)n);
        else if (kind == 2) patch_tracerpid((char*)buf, (size_t)n);
        else if (kind == 3) filter_environ((char*)buf, (size_t)n);
        else if (kind == 4) patch_cmdline((char*)buf, (size_t)n);
    }
    return n;
}

static int my_uname(struct utsname *buf) {
    if (!buf) return -1;
    int r = real_uname ? real_uname(buf) : -1;
    snprintf(buf->sysname, sizeof(buf->sysname), "Linux");
    snprintf(buf->nodename, sizeof(buf->nodename), "localhost");
    snprintf(buf->release, sizeof(buf->release), "5.10.149-android14-13-00001-g1234567890ab");
    snprintf(buf->version, sizeof(buf->version), "#1 SMP PREEMPT Mon Jan 1 00:00:00 UTC 2024");
    snprintf(buf->machine, sizeof(buf->machine), "aarch64");
    snprintf(buf->domainname, sizeof(buf->domainname), "(none)");
    return r;
}

static int my_ptrace(int request, ...) {
    va_list ap; va_start(ap, request);
    pid_t pid = va_arg(ap, pid_t);
    void *addr = va_arg(ap, void *);
    void *data = va_arg(ap, void *);
    va_end(ap);
    if (g_hidden && request == PTRACE_TRACEME) return 0;
    return real_ptrace ? real_ptrace(request, pid, addr, data) : -1;
}

static long my_syscall(long nr, ...) {
    va_list ap; va_start(ap, nr);
    switch (nr) {
        case SYS_openat: {
            int dfd = va_arg(ap, int);
            const char *p = va_arg(ap, const char *);
            int fl = va_arg(ap, int);
            mode_t md = va_arg(ap, mode_t);
            va_end(ap);
            if (is_hidden_path(p)) { errno = ENOENT; return -1; }
            return real_openat ? real_openat(dfd, p, fl, md) : -1;
        }
#ifdef SYS_access
        case SYS_access: {
            const char *p = va_arg(ap, const char *);
            int m = va_arg(ap, int);
            va_end(ap);
            if (is_hidden_path(p)) { errno = ENOENT; return -1; }
            return real_access ? real_access(p, m) : -1;
        }
#endif
        case SYS_faccessat: {
            int dfd = va_arg(ap, int);
            const char *p = va_arg(ap, const char *);
            int m = va_arg(ap, int);
            va_end(ap);
            if (is_hidden_path(p)) { errno = ENOENT; return -1; }
            return real_faccessat ? real_faccessat(dfd, p, m, 0) : -1;
        }
        case SYS_readlinkat: {
            int dfd = va_arg(ap, int);
            const char *p = va_arg(ap, const char *);
            char *b = va_arg(ap, char *);
            size_t s = va_arg(ap, size_t);
            va_end(ap);
            if (is_hidden_path(p)) { errno = ENOENT; return -1; }
            return real_readlinkat ? real_readlinkat(dfd, p, b, s) : -1;
        }
        case SYS_uname: {
            struct utsname *u = va_arg(ap, struct utsname *);
            va_end(ap);
            return my_uname(u);
        }
        default: {
            long a1 = va_arg(ap, long), a2 = va_arg(ap, long), a3 = va_arg(ap, long);
            long a4 = va_arg(ap, long), a5 = va_arg(ap, long), a6 = va_arg(ap, long);
            va_end(ap);
            return real_syscall ? real_syscall(nr, a1, a2, a3, a4, a5, a6) : -1;
        }
    }
}

/* ── Property hooks ── */
static int my_prop_get(const char *name, char *value, size_t size) {
    const char *v = spoof_value_for(name);
    if (v) {
        if (value && size > 0) {
            size_t n = strlen(v);
            if (n >= size) n = size - 1;
            memcpy(value, v, n);
            value[n] = '\0';
            return (int)n;
        }
        return (int)strlen(v);
    }
    return real_prop_get ? real_prop_get(name, value, size) : 0;
}

/* __system_property_find returns const prop_info* — if it's a spoofed key,
 * return nullptr so callers fall back, OR better: we can't easily synthesize
 * a prop_info. Instead we let the real find succeed, then intercept read. */
static const prop_info *my_prop_find(const char *name) {
    /* For spoofed keys, we can't fabricate prop_info safely. Let real find
     * run; the read/read_callback hooks will override the value. But for
     * keys we want to HIDE (empty value), return nullptr. */
    const char *v = spoof_value_for(name);
    if (v && *v == '\0') return nullptr;  /* hide this property entirely */
    return real_prop_find ? real_prop_find(name) : nullptr;
}

static int my_prop_read(const prop_info *pi, char *value, size_t size) {
    /* We don't know the key from pi alone without __system_property_get_name.
     * Bionic has __system_property_get_name but it's not always exported.
     * Fall back to real_read and then we cannot override per-key here.
     * Instead, callers usually use get() which we already hook. */
    return real_prop_read ? real_prop_read(pi, value, size) : 0;
}

static void my_prop_read_callback(const prop_info *pi,
        void (*cb)(const char *, const char *, uint32_t, void *), void *cookie) {
    /* Without the key name we cannot spoof here reliably. Pass through.
     * The primary path (SystemProperties.get) uses __system_property_get
     * which IS hooked. */
    if (real_prop_read_callback) real_prop_read_callback(pi, cb, cookie);
}

/* ── fopen/opendir/scandir hooks ── */
static FILE *my_fopen(const char *path, const char *mode) {
    if (is_hidden_path(path)) { errno = ENOENT; return nullptr; }
    return real_fopen ? real_fopen(path, mode) : nullptr;
}

static DIR *my_opendir(const char *path) {
    if (is_hidden_path(path)) { errno = ENOENT; return nullptr; }
    return real_opendir ? real_opendir(path) : nullptr;
}

static DIR *my_fdopendir(int fd) {
    return real_fdopendir ? real_fdopendir(fd) : nullptr;
}

static int my_scandir(const char *path, struct dirent ***namelist,
        int (*sel)(const struct dirent *),
        int (*cmp)(const struct dirent **, const struct dirent **)) {
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    return real_scandir ? real_scandir(path, namelist, sel, cmp) : -1;
}

/* statfs/statvfs on hidden paths → ENOENT to hide overlay/magisk mounts */
static int my_statfs(const char *path, struct statfs *buf) {
    if (is_hidden_path(path)) { if (buf) memset(buf, 0, sizeof(*buf)); errno = ENOENT; return -1; }
    return real_statfs ? real_statfs(path, buf) : -1;
}

static int my_statvfs(const char *path, struct statvfs *buf) {
    if (is_hidden_path(path)) { if (buf) memset(buf, 0, sizeof(*buf)); errno = ENOENT; return -1; }
    return real_statvfs ? real_statvfs(path, buf) : -1;
}

/* getmntent/setmntent: filter mount entries from /proc/mounts */
static FILE *my_setmntent(const char *path, const char *mode) {
    return real_setmntent ? real_setmntent(path, mode) : nullptr;
}

static struct mntent *my_getmntent(FILE *fp) {
    struct mntent *m;
    while ((m = real_getmntent ? real_getmntent(fp) : nullptr)) {
        if (!should_hide_mounts_line(m->mnt_fsname) &&
            !should_hide_mounts_line(m->mnt_dir) &&
            !should_hide_mounts_line(m->mnt_type)) {
            return m;
        }
    }
    return nullptr;
}

/* Block dlopen of xposed/lsposed/riru/frida libraries */
static void *my_dlopen(const char *filename, int flags) {
    if (filename && is_hidden_path(filename)) { errno = ENOENT; return nullptr; }
    return real_dlopen ? real_dlopen(filename, flags) : nullptr;
}

/* getdents64: filter hidden entries from directory listings.
 * Detectors bypass readdir() and call getdents64 directly via syscall. */
static int my_getdents64(unsigned int fd, struct dirent *dirp, unsigned int count) {
    int n = real_getdents64 ? real_getdents64(fd, dirp, count) : -1;
    if (n <= 0) return n;
    /* Compact the buffer, removing hidden entries */
    int w = 0;
    int i = 0;
    while (i < n) {
        struct dirent *de = (struct dirent*)((char*)dirp + i);
        if (!is_hidden_name(de->d_name)) {
            if (w != i) {
                memmove((char*)dirp + w, (char*)dirp + i, de->d_reclen);
            }
            w += de->d_reclen;
        }
        i += de->d_reclen;
    }
    return w;
}

static int my_getdents(unsigned int fd, struct dirent *dirp, unsigned int count) {
    int n = real_getdents ? real_getdents(fd, dirp, count) : -1;
    if (n <= 0) return n;
    int w = 0;
    int i = 0;
    while (i < n) {
        struct dirent *de = (struct dirent*)((char*)dirp + i);
        if (!is_hidden_name(de->d_name)) {
            if (w != i) {
                memmove((char*)dirp + w, (char*)dirp + i, de->d_reclen);
            }
            w += de->d_reclen;
        }
        i += de->d_reclen;
    }
    return w;
}

/* openat2: newer syscall replacing openat (Android 11+) */
struct open_how;
static int my_openat2(int dfd, const char *path, struct open_how *how, size_t sz) {
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    return real_openat2 ? real_openat2(dfd, path, how, sz) : -1;
}

/* dl_iterate_phdr: filter hidden libraries from enumeration.
 * Detectors call this directly to bypass /proc/self/maps filtering.
 * We intercept the callback and skip entries for hidden libraries. */
static int phdr_filter_cb(struct dl_phdr_info *info, size_t size, void *data) {
    if (info && info->dlpi_name && *info->dlpi_name) {
        /* Skip our own module and any hidden library */
        if (should_hide_maps_line(info->dlpi_name) ||
            su_strstr(info->dlpi_name, "su_stealth") ||
            su_strstr(info->dlpi_name, "stealth_ultimate")) {
            return 0;  /* skip this entry, continue iteration */
        }
    }
    /* Forward to user callback */
    if (g_user_phdr_cb) return g_user_phdr_cb(info, size, data);
    return 0;
}

static int my_dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t, void *), void *data) {
    if (!g_hidden) {
        /* Not in hidden mode — pass through (used for hook registration) */
        return real_dl_iterate_phdr ? real_dl_iterate_phdr(cb, data) : 0;
    }
    /* In hidden mode — filter hidden libraries */
    g_user_phdr_cb = cb;
    g_user_phdr_data = data;
    int r = real_dl_iterate_phdr ? real_dl_iterate_phdr(phdr_filter_cb, data) : 0;
    g_user_phdr_cb = nullptr;
    return r;
}

/* mmap: if mapping /proc/self/mem for memory scanning, we can't easily
 * intercept the read, but we can return failure for hidden fd paths.
 * Most detectors use open+read on maps, not mmap on mem. */
static void *my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    if (fd >= 0 && (prot & PROT_READ)) {
        int kind = fd_filter_kind(fd);
        if (kind == 1 || kind == 2 || kind == 3 || kind == 4) {
            /* Let it map — the read hook handles content filtering */
        }
    }
    return real_mmap ? real_mmap(addr, length, prot, flags, fd, offset) : MAP_FAILED;
}

/* Block execve/execv of hidden binaries (su, magisk, busybox) */
static int my_execve(const char *path, char *const argv[], char *const envp[]) {
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    return real_execve ? real_execve(path, argv, envp) : -1;
}

static int my_execv(const char *path, char *const argv[]) {
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    return real_execv ? real_execv(path, argv) : -1;
}

/* ── Hook registration ── */
static void register_hooks_for_object(dev_t dev, ino_t ino) {
    struct { const char *name; void *impl; void **backup; } hooks[] = {
        {"openat",                       (void*)my_openat,        (void**)&real_openat},
        {"open",                         (void*)my_open,          (void**)&real_open},
        {"access",                       (void*)my_access,        (void**)&real_access},
        {"faccessat",                    (void*)my_faccessat,     (void**)&real_faccessat},
        {"stat",                         (void*)my_stat,          (void**)&real_stat},
        {"lstat",                        (void*)my_lstat,         (void**)&real_lstat},
        {"fstatat",                      (void*)my_fstatat,       (void**)&real_fstatat},
        {"fstat",                        (void*)my_fstat,         (void**)&real_fstat},
        {"readlink",                     (void*)my_readlink,      (void**)&real_readlink},
        {"readlinkat",                   (void*)my_readlinkat,    (void**)&real_readlinkat},
        {"readdir",                      (void*)my_readdir,       (void**)&real_readdir},
        {"read",                         (void*)my_read,          (void**)&real_read},
        {"pread64",                      (void*)my_pread64,       (void**)&real_pread64},
        {"uname",                        (void*)my_uname,         (void**)&real_uname},
        {"ptrace",                       (void*)my_ptrace,        (void**)&real_ptrace},
        {"syscall",                      (void*)my_syscall,      (void**)&real_syscall},
        {"__system_property_get",        (void*)my_prop_get,      (void**)&real_prop_get},
        {"__system_property_find",       (void*)my_prop_find,     (void**)&real_prop_find},
        {"__system_property_read",       (void*)my_prop_read,     (void**)&real_prop_read},
        {"__system_property_read_callback", (void*)my_prop_read_callback, (void**)&real_prop_read_callback},
        {"fopen",                        (void*)my_fopen,         (void**)&real_fopen},
        {"opendir",                      (void*)my_opendir,       (void**)&real_opendir},
        {"fdopendir",                    (void*)my_fdopendir,     (void**)&real_fdopendir},
        {"scandir",                      (void*)my_scandir,       (void**)&real_scandir},
        {"statfs",                       (void*)my_statfs,        (void**)&real_statfs},
        {"statfs64",                     (void*)my_statfs,        (void**)&real_statfs},
        {"statvfs",                      (void*)my_statvfs,       (void**)&real_statvfs},
        {"statvfs64",                    (void*)my_statvfs,       (void**)&real_statvfs},
        {"setmntent",                    (void*)my_setmntent,     (void**)&real_setmntent},
        {"getmntent",                    (void*)my_getmntent,     (void**)&real_getmntent},
        {"dlopen",                       (void*)my_dlopen,         (void**)&real_dlopen},
        {"getdents64",                   (void*)my_getdents64,     (void**)&real_getdents64},
        {"getdents",                     (void*)my_getdents,       (void**)&real_getdents},
        {"openat2",                      (void*)my_openat2,        (void**)&real_openat2},
        {"dl_iterate_phdr",              (void*)my_dl_iterate_phdr,(void**)&real_dl_iterate_phdr},
        {"mmap",                         (void*)my_mmap,           (void**)&real_mmap},
        {"execve",                       (void*)my_execve,         (void**)&real_execve},
        {"execv",                        (void*)my_execv,          (void**)&real_execv},
    };
    for (size_t i = 0; i < sizeof(hooks)/sizeof(hooks[0]); ++i) {
        g_api->pltHookRegister(dev, ino, hooks[i].name, hooks[i].impl, hooks[i].backup);
    }
    g_registrations += (int)(sizeof(hooks)/sizeof(hooks[0]));
    LOGI("register: dev=%lu ino=%lu hooks=%d", (unsigned long)dev, (unsigned long)ino, (int)(sizeof(hooks)/sizeof(hooks[0])));
}

static int phdr_cb(struct dl_phdr_info *info, size_t, void *) {
    if (!info->dlpi_name || !*info->dlpi_name) return 0;
    if (su_strstr(info->dlpi_name, "su_stealth") ||
        su_strstr(info->dlpi_name, "stealth_ultimate")) return 0;
    struct stat st;
    if (stat(info->dlpi_name, &st) != 0) return 0;
    if (st.st_dev == 0 || st.st_ino == 0) return 0;
    LOGI("phdr: %s dev=%lu ino=%lu", info->dlpi_name, (unsigned long)st.st_dev, (unsigned long)st.st_ino);
    register_hooks_for_object(st.st_dev, st.st_ino);
    g_objects++;
    return 0;
}

static void init_real_symbols(void) {
    real_openat     = (decltype(real_openat))dlsym(RTLD_NEXT, "openat");
    real_open       = (decltype(real_open))dlsym(RTLD_NEXT, "open");
    real_access     = (decltype(real_access))dlsym(RTLD_NEXT, "access");
    real_faccessat  = (decltype(real_faccessat))dlsym(RTLD_NEXT, "faccessat");
    real_stat       = (decltype(real_stat))dlsym(RTLD_NEXT, "stat");
    real_lstat      = (decltype(real_lstat))dlsym(RTLD_NEXT, "lstat");
    real_fstatat    = (decltype(real_fstatat))dlsym(RTLD_NEXT, "fstatat");
    real_fstat      = (decltype(real_fstat))dlsym(RTLD_NEXT, "fstat");
    real_readlink   = (decltype(real_readlink))dlsym(RTLD_NEXT, "readlink");
    real_readlinkat = (decltype(real_readlinkat))dlsym(RTLD_NEXT, "readlinkat");
    real_readdir    = (decltype(real_readdir))dlsym(RTLD_NEXT, "readdir");
    real_pread64    = (decltype(real_pread64))dlsym(RTLD_NEXT, "pread64");
    real_read       = (decltype(real_read))dlsym(RTLD_NEXT, "read");
    real_uname      = (decltype(real_uname))dlsym(RTLD_NEXT, "uname");
    real_ptrace     = (decltype(real_ptrace))dlsym(RTLD_NEXT, "ptrace");
    real_syscall    = (decltype(real_syscall))dlsym(RTLD_NEXT, "syscall");
    real_prop_get   = (decltype(real_prop_get))dlsym(RTLD_NEXT, "__system_property_get");
    real_prop_find  = (decltype(real_prop_find))dlsym(RTLD_NEXT, "__system_property_find");
    real_prop_read  = (decltype(real_prop_read))dlsym(RTLD_NEXT, "__system_property_read");
    real_prop_read_callback = (decltype(real_prop_read_callback))dlsym(RTLD_NEXT, "__system_property_read_callback");
    real_fopen      = (decltype(real_fopen))dlsym(RTLD_NEXT, "fopen");
    real_opendir    = (decltype(real_opendir))dlsym(RTLD_NEXT, "opendir");
    real_fdopendir  = (decltype(real_fdopendir))dlsym(RTLD_NEXT, "fdopendir");
    real_scandir    = (decltype(real_scandir))dlsym(RTLD_NEXT, "scandir");
    real_statfs     = (decltype(real_statfs))dlsym(RTLD_NEXT, "statfs");
    real_statvfs    = (decltype(real_statvfs))dlsym(RTLD_NEXT, "statvfs");
    real_setmntent  = (decltype(real_setmntent))dlsym(RTLD_NEXT, "setmntent");
    real_getmntent  = (decltype(real_getmntent))dlsym(RTLD_NEXT, "getmntent");
    real_dlopen     = (decltype(real_dlopen))dlsym(RTLD_NEXT, "dlopen");
    real_getdents64 = (decltype(real_getdents64))dlsym(RTLD_NEXT, "getdents64");
    real_getdents   = (decltype(real_getdents))dlsym(RTLD_NEXT, "getdents");
    real_openat2    = (decltype(real_openat2))dlsym(RTLD_NEXT, "openat2");
    real_dl_iterate_phdr = (decltype(real_dl_iterate_phdr))dlsym(RTLD_NEXT, "dl_iterate_phdr");
    real_mmap       = (decltype(real_mmap))dlsym(RTLD_NEXT, "mmap");
    real_execve     = (decltype(real_execve))dlsym(RTLD_NEXT, "execve");
    real_execv      = (decltype(real_execv))dlsym(RTLD_NEXT, "execv");
}

/* ── JNI SystemProperties hooks ──
 * These intercept Java-level property reads. The original function pointer
 * is stored in the JNINativeMethod.fnPtr by hookJniNativeMethods. */
static jstring (*orig_sysprop_get)(JNIEnv *, jclass, jstring);

static jstring su_jni_prop_get(JNIEnv *e, jclass clazz, jstring key) {
    if (!e || !key) return orig_sysprop_get ? orig_sysprop_get(e, clazz, key) : nullptr;
    const char *k = e->GetStringUTFChars(key, nullptr);
    if (!k) return orig_sysprop_get ? orig_sysprop_get(e, clazz, key) : nullptr;
    const char *v = spoof_value_for(k);
    e->ReleaseStringUTFChars(key, k);
    if (v) {
        /* For hidden (empty) properties, return empty string */
        return e->NewStringUTF(v);
    }
    return orig_sysprop_get ? orig_sysprop_get(e, clazz, key) : e->NewStringUTF("");
}

static jboolean su_jni_prop_get_boolean(JNIEnv *e, jclass clazz, jstring key, jboolean def) {
    if (!e || !key) return def;
    const char *k = e->GetStringUTFChars(key, nullptr);
    if (!k) return def;
    const char *v = spoof_value_for(k);
    e->ReleaseStringUTFChars(key, k);
    if (v) {
        if (*v == '1' || *v == 't' || *v == 'T') return JNI_TRUE;
        return JNI_FALSE;
    }
    return orig_sysprop_get ? (jboolean)0 : def;
}

static jint su_jni_prop_get_int(JNIEnv *e, jclass clazz, jstring key, jint def) {
    if (!e || !key) return def;
    const char *k = e->GetStringUTFChars(key, nullptr);
    if (!k) return def;
    const char *v = spoof_value_for(k);
    e->ReleaseStringUTFChars(key, k);
    if (v && *v) return (jint)atoi(v);
    return def;
}

static jlong su_jni_prop_get_long(JNIEnv *e, jclass clazz, jstring key, jlong def) {
    if (!e || !key) return def;
    const char *k = e->GetStringUTFChars(key, nullptr);
    if (!k) return def;
    const char *v = spoof_value_for(k);
    e->ReleaseStringUTFChars(key, k);
    if (v && *v) return (jlong)atoll(v);
    return def;
}

static bool is_root_management_app(const char *proc) {
    if (!proc) return false;
    static const char *const kRootApps[] = {
        "com.topjohnwu.magisk", "io.github.vvb2060.magisk",
        "com.topjohnwu.magisk.kox", "me.bmax.apatch",
        "com.android.shell", "com.termux", "com.termux.x11",
        "bin.mt.plus", "bin.mt.plus.canary", "bin.mt.signaturekiller",
        "io.github.huskydg.magisk", "io.github.rifsxd.kitsune",
        "me.tsihngyxp.magiskkitsune", "com.konsta.mrh",
        "com.termux.api", "com.termux.widget", "com.termux.tasker",
        "jackpal.androidterm", "com.google.android.apps.nbu.files",
        "com.amaze.filemanager", "me.zhanghai.android.files",
        "com.raze.ma15", "com.raze.managers",
        nullptr
    };
    for (size_t i = 0; kRootApps[i]; ++i) {
        if (su_streq(proc, kRootApps[i])) return true;
        size_t len = strlen(kRootApps[i]);
        if (strncmp(proc, kRootApps[i], len) == 0 && proc[len] == ':') return true;
    }
    return false;
}

/* Forward declarations for companion-based root UID check */
static void load_root_uids_via_companion(zygisk::Api *api);
static bool uid_has_root(int uid);

static bool process_needs_hidden(int uid, const char *proc) {
    if (uid == 0 || uid == 1000) return false;
    if (!proc || !*proc) return true;
    if (is_root_management_app(proc)) return false;
    static const char *const kExempt[] = {
        "zygote","zygote64","system_server",
        "magisk","magiskd","ksu","ksud","KernelSU","apatch","apd",
        "shamiko","init","adbd","logd","surfaceflinger",
        "android.system.server","com.android.systemui", nullptr
    };
    for (size_t i = 0; kExempt[i]; ++i) if (su_streq(proc, kExempt[i])) return false;
    if (su_starts(proc, "com.android.systemui:")) return false;
    return true;
}

static char *get_process_name(void) {
    char *proc = (char*)calloc(256, 1);
    if (!proc) return nullptr;
    int fd = real_openat ? real_openat(AT_FDCWD, "/proc/self/cmdline", O_RDONLY, 0) : -1;
    if (fd >= 0) {
        ssize_t n = real_read ? real_read(fd, proc, 255) : -1;
        if (n < 0) n = 0;
        close(fd);
        proc[n] = '\0';
        if (su_strstr(proc, "su_stealth") || su_strstr(proc, "stealth_ultimate"))
            proc[0] = '\0';
    }
    if (!*proc) snprintf(proc, 256, "unknown");
    return proc;
}

class StealthModule : public zygisk::ModuleBase {
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
public:
    void onLoad(zygisk::Api *a, JNIEnv *e) override {
        api = a; g_api = a; env = e;
        init_real_symbols();
        LOGI("onLoad: init done");
    }
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (!args) return;
        jint uid = args->uid;
        /* Get process name from nice_name (JNI) — /proc/self/cmdline is still
         * "zygote" at this point, so reading it gives wrong results. */
        char procbuf[256];
        procbuf[0] = '\0';
        if (args->nice_name && env) {
            const char *s = env->GetStringUTFChars(args->nice_name, nullptr);
            if (s) {
                strncpy(procbuf, s, sizeof(procbuf) - 1);
                procbuf[sizeof(procbuf) - 1] = '\0';
                env->ReleaseStringUTFChars(args->nice_name, s);
            }
        }
        const char *proc = procbuf[0] ? procbuf : "unknown";
        LOGI("preAppSpecialize: uid=%d proc=%s", uid, proc);

        /* Check Zygisk flags: PROCESS_GRANTED_ROOT means this process has been
         * granted root by MagiskSU. Never hook these or su will break. */
        uint32_t zflags = api->getFlags();
        bool granted_root = (zflags & zygisk::PROCESS_GRANTED_ROOT) != 0;
        LOGI("flags: granted_root=%d (flags=0x%x)", (int)granted_root, zflags);
        if (granted_root) {
            LOGI("skip (root granted) proc=%s", proc);
            return;
        }
        /* Also check via companion process (reads MagiskSU policies as root) */
        load_root_uids_via_companion(api);
        if (uid_has_root(uid)) {
            LOGI("skip (root uid via companion) uid=%d proc=%s", uid, proc);
            return;
        }
        if (!process_needs_hidden(uid, proc)) {
            LOGI("exempt uid=%d proc=%s — no hooks", uid, proc);
            return;
        }
        g_hidden = true;
        /* Force unmount Magisk traces in this process */
        api->setOption(zygisk::Option::FORCE_DENYLIST_UNMOUNT);

        /* JNI hook: intercept android.os.SystemProperties native methods so
         * Java-level property reads also get spoofed values. */
        JNINativeMethod propMethods[] = {
            {(char*)"get",      (char*)"(Ljava/lang/String;)Ljava/lang/String;", (void*)su_jni_prop_get},
            {(char*)"getBoolean",(char*)"(Ljava/lang/String;Z)Z",               (void*)su_jni_prop_get_boolean},
            {(char*)"getInt",   (char*)"(Ljava/lang/String;I)I",                 (void*)su_jni_prop_get_int},
            {(char*)"getLong",  (char*)"(Ljava/lang/String;J)J",                 (void*)su_jni_prop_get_long},
        };
        api->hookJniNativeMethods(env, "android/os/SystemProperties",
                                  propMethods, sizeof(propMethods)/sizeof(propMethods[0]));
        LOGI("JNI SystemProperties hooks installed");

        g_objects = g_registrations = 0;
        dl_iterate_phdr(phdr_cb, nullptr);
        bool ok = api->pltHookCommit();
        LOGI("install: commit=%d objects=%d regs=%d proc=%s", (int)ok, g_objects, g_registrations, proc);
        if (!ok) LOGE("pltHookCommit FAILED for proc=%s!", proc);
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override {}
    void preServerSpecialize(zygisk::ServerSpecializeArgs *) override {
        g_hidden = true;
        api->setOption(zygisk::Option::FORCE_DENYLIST_UNMOUNT);
        g_objects = g_registrations = 0;
        dl_iterate_phdr(phdr_cb, nullptr);
        api->pltHookCommit();
    }
    void postServerSpecialize(const zygisk::ServerSpecializeArgs *) override {}
};

/* ── Companion process: runs as root, reads MagiskSU policies ──
 * Communicates with module via socket. Module sends target UID,
 * companion responds with 1 (has root) or 0 (no root). */
static bool g_root_uids_loaded = false;
static int g_root_uids[256];
static int g_root_uid_count = 0;

static void load_root_uids_via_companion(zygisk::Api *api) {
    if (g_root_uids_loaded) return;
    g_root_uids_loaded = true;
    int fd = api->connectCompanion();
    if (fd < 0) { LOGI("companion: connect failed"); return; }
    /* Request: send magic 'L' (load root UIDs) */
    char cmd = 'L';
    if (write(fd, &cmd, 1) != 1) { close(fd); return; }
    /* Response: read count then UIDs */
    int count = 0;
    if (read(fd, &count, sizeof(count)) != sizeof(count)) { close(fd); return; }
    if (count > 256) count = 256;
    if (count > 0) {
        if (read(fd, g_root_uids, count * sizeof(int)) != (ssize_t)(count * sizeof(int))) {
            close(fd); return;
        }
    }
    g_root_uid_count = count;
    close(fd);
    LOGI("companion: loaded %d root UIDs", count);
}

static bool uid_has_root(int uid) {
    for (int i = 0; i < g_root_uid_count; ++i) {
        if (g_root_uids[i] == uid) return true;
    }
    return false;
}

/* Companion handler: runs in root process, reads MagiskSU policies */
static void su_companion_handler(int client) {
    /* Read command */
    char cmd = 0;
    if (read(client, &cmd, 1) != 1) { close(client); return; }
    if (cmd == 'L') {
        /* Load root UIDs from MagiskSU policies */
        int uids[256];
        int count = 0;
        /* Try magisk --sqlite first */
        FILE *fp = popen("magisk --sqlite \"SELECT uid FROM policies WHERE policy=2\" 2>/dev/null", "r");
        if (fp) {
            char line[64];
            while (count < 256 && fgets(line, sizeof(line), fp)) {
                int u = 0;
                char *p = line;
                while (*p && (*p < '0' || *p > '9')) p++;
                while (*p >= '0' && *p <= '9') { u = u * 10 + (*p - '0'); p++; }
                if (u > 0) uids[count++] = u;
            }
            pclose(fp);
        }
        /* Fallback: try ksud/apd */
        if (count == 0) {
            fp = popen("ksud sqlite \"SELECT uid FROM root_config WHERE policy=2\" 2>/dev/null", "r");
            if (fp) {
                char line[64];
                while (count < 256 && fgets(line, sizeof(line), fp)) {
                    int u = 0;
                    char *p = line;
                    while (*p && (*p < '0' || *p > '9')) p++;
                    while (*p >= '0' && *p <= '9') { u = u * 10 + (*p - '0'); p++; }
                    if (u > 0) uids[count++] = u;
                }
                pclose(fp);
            }
        }
        if (count == 0) {
            fp = popen("apd sqlite \"SELECT uid FROM root_config WHERE policy=2\" 2>/dev/null", "r");
            if (fp) {
                char line[64];
                while (count < 256 && fgets(line, sizeof(line), fp)) {
                    int u = 0;
                    char *p = line;
                    while (*p && (*p < '0' || *p > '9')) p++;
                    while (*p >= '0' && *p <= '9') { u = u * 10 + (*p - '0'); p++; }
                    if (u > 0) uids[count++] = u;
                }
                pclose(fp);
            }
        }
        /* Send response */
        write(client, &count, sizeof(count));
        if (count > 0) write(client, uids, count * sizeof(int));
    }
    close(client);
}

REGISTER_ZYGISK_MODULE(StealthModule)
REGISTER_ZYGISK_COMPANION(su_companion_handler)

/* ── C++ runtime stubs ── */
extern "C" {
int      __cxa_atexit(void (*)(void *), void *, void *) { return 0; }
void     __cxa_finalize(void *) {}
unsigned __cxa_guard_acquire(unsigned *g) { (void)g; return 1; }
void     __cxa_guard_release(unsigned *g) { (void)g; }
void     __cxa_guard_abort(unsigned *g) { (void)g; }
}
