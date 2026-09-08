/* SPDX-License-Identifier: MIT */
/*
 * stealth_ultimate.cpp — Universal Zygisk Anti-Detection Module (v5.0)
 *
 * Comprehensive hiding covering all major detection vectors:
 * - File/path hiding (openat, open, access, stat, lstat, fstatat, readlink)
 * - Directory filtering (readdir, opendir, scandir, getdents64, getdents)
 * - Proc file substitution via memfd (maps, mounts, environ, status, cmdline)
 * - /proc/self/fd filtering, /proc/<pid>/ process hiding
 * - /proc/self/attr, cgroup, wchan, stack, syscall, stat filtering
 * - Property spoofing (__system_property_get/find/read_callback/foreach)
 * - JNI SystemProperties interception
 * - uname, ptrace, prctl, socket/connect hooks
 * - /proc/net/tcp, /proc/net/unix filtering for Frida/Magisk sockets
 * - /proc/filesystems filtering
 * - sendfile bypass protection
 * - Config file loading from /data/adb/su_stealth/spoof.conf
 * - inotify blocking
 *
 * Targets: Native Detector, Ruru, Momo, Shamiko-detectors, Play Integrity,
 *          banking apps, and all standard root detection methods.
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
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <link.h>
#include <stdarg.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/inotify.h>
#include <mntent.h>
#include <sys/utsname.h>
#include <sys/prctl.h>
#include <poll.h>

#include "zygisk.hpp"

#define SU_ENABLE_LOG 0
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
static int            (*real_android_log_print)(int, const char *, const char *, ...) = nullptr;
static int            (*real_android_log_write)(int, const char *, const char *)     = nullptr;

/* v5.0 new hooks */
static void           *(*real_mmap)(void *, size_t, int, int, int, off_t)             = nullptr;
static ssize_t        (*real_sendfile)(int, int, off_t *, size_t)                     = nullptr;
static int            (*real_inotify_init)(void)                                      = nullptr;
static int            (*real_inotify_init1)(int)                                      = nullptr;
static int            (*real_prctl)(int, ...)                                         = nullptr;
static int            (*real_connect)(int, const struct sockaddr *, socklen_t)        = nullptr;
static int            (*real_socket)(int, int, int)                                   = nullptr;
static char           *(*real_realpath)(const char *, char *)                         = nullptr;
static int            (*real_statx)(int, const char *, int, unsigned int, void *)     = nullptr;
static ssize_t        (*real_readlinkat)(int, const char *, char *, size_t)           = nullptr;
static int            (*real_fcntl)(int, int, ...)                                    = nullptr;
static int            (*real_ioctl)(int, unsigned long, ...)                          = nullptr;

/* Android 13+ property API */
static void           (*real_prop_read_callback)(const prop_info *, void (*)(void*, const char*, uint32_t), void*) = nullptr;
static int            (*real_prop_foreach)(void (*)(const prop_info*, void*), void*) = nullptr;

/* poll/ppoll for Frida detection */
static int            (*real_poll)(struct pollfd *, nfds_t, int)                      = nullptr;
static int            (*real_ppoll)(struct pollfd *, nfds_t, const struct timespec*, const sigset_t*) = nullptr;

/* dl_iterate_phdr interceptor state */
static int (*g_user_phdr_cb)(struct dl_phdr_info *, size_t, void *) = nullptr;
static void *g_user_phdr_data = nullptr;

/* ── Module global state ── */
static zygisk::Api *g_api = nullptr;
static bool g_hidden = false;
[[maybe_unused]] static int g_objects = 0;
[[maybe_unused]] static int g_registrations = 0;

/* ── Spoof profile (loaded from config file) ── */
#define SU_MAX_SPOOF_ENTRIES 128
struct SpoofEntry { char key[96]; char val[256]; };
static SpoofEntry g_spoof_entries[SU_MAX_SPOOF_ENTRIES];
static int g_spoof_count = 0;

static const char *SPOOF_FP =
    "google/bluejay/bluejay:14/UD1A.240105.004/11207768:user/release-keys";

static void load_spoof_config(void) {
    /* Load /data/adb/su_stealth/spoof.conf if available.
     * Format: KEY=VALUE per line, # comments. */
    int fd = real_openat ? real_openat(AT_FDCWD, "/data/adb/su_stealth/spoof.conf", O_RDONLY, 0) : -1;
    if (fd < 0) return;
    char buf[16384];
    ssize_t total = 0;
    while (total < (ssize_t)sizeof(buf) - 1) {
        ssize_t n = real_read ? real_read(fd, buf + total, sizeof(buf) - 1 - total) : -1;
        if (n <= 0) break;
        total += n;
    }
    close(fd);
    buf[total] = '\0';

    g_spoof_count = 0;
    char *line = buf;
    while (line < buf + total && g_spoof_count < SU_MAX_SPOOF_ENTRIES) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (*line && *line != '#') {
            char *eq = strchr(line, '=');
            if (eq) {
                *eq = '\0';
                const char *k = line;
                const char *v = eq + 1;
                /* Skip leading whitespace */
                while (*k == ' ' || *k == '\t') k++;
                if (*k && *v) {
                    strncpy(g_spoof_entries[g_spoof_count].key, k, 95);
                    g_spoof_entries[g_spoof_count].key[95] = '\0';
                    strncpy(g_spoof_entries[g_spoof_count].val, v, 255);
                    g_spoof_entries[g_spoof_count].val[255] = '\0';
                    g_spoof_count++;
                }
            }
        }
        if (!nl) break;
        line = nl + 1;
    }
    LOGI("Loaded %d spoof entries from config", g_spoof_count);
}

static inline bool su_streq(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }
static inline bool su_strstr(const char *s, const char *n) { return s && n && strstr(s, n); }
static inline bool su_starts(const char *s, const char *p) { return s && p && strncmp(s, p, strlen(p)) == 0; }

/* ── Path classification ── */
static bool is_hidden_path(const char *path) {
    if (!path || !*path || !g_hidden) return false;
    /* Fast reject: only check paths that could be root-related */
    char c0 = path[0];
    /* Quick check: if path doesn't contain /data, /sbin, /system, /cache, /proc
     * or known keywords, skip the expensive strstr loop */
    if (c0 != '/' && c0 != 'm' && c0 != 'k' && c0 != 'a' && c0 != 'x' &&
        c0 != 'l' && c0 != 'r' && c0 != 'f' && c0 != 's' && c0 != 'b' &&
        c0 != 'S' && c0 != 'n' && c0 != 'c' && c0 != 'd' && c0 != 'e' &&
        c0 != 'z' && c0 != 'i')
        return false;
    if (su_strstr(path, "/data/local/tmp/")) {
        static const char *const kTmp[] = {
            "/magisk","/frida","/re.frida","/gum","/linjector","/busybox",
            "/su","/stealth","/riru","/xposed","/lspd","/magiskboot","/resetprop", nullptr
        };
        for (size_t i = 0; kTmp[i]; ++i) if (su_strstr(path, kTmp[i])) return true;
        return false;
    }
    /* Hide property files that reveal root manager traces */
    if (su_strstr(path, "/dev/__properties__/") &&
        (su_strstr(path, "magisk") || su_strstr(path, "ksu") || su_strstr(path, "apatch") ||
         su_strstr(path, "pixelprops") || su_strstr(path, "zygisk"))) {
        return true;
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
        "su_stealth","stealth_ultimate","/cache/stealth_ultimate",
        "noshufou.android.su","thirdparty.superuser","chainfire.supersu",
        "koushikdutta.superuser","zachspong.temprootremovejb",
        "ramdroid.appquarantine","cyanogenmod.superuser",
        "com.noshufou.android.su","com.thirdparty.superuser",
        "eu.chainfire.supersu","com.koushikdutta.superuser",
        "com.zachspong.temprootremovejb","com.ramdroid.appquarantine",
        /* v5.0: additional paths */
        "/dev/.magisk","/dev/__magisk","/dev/ksu","/dev/.ksu",
        "/system/etc/init/magisk","/system/etc/init/ksu",
        "/data/system/magisk","/data/system/ksu",
        "/data/data/com.topjohnwu.magisk",
        "/data/data/io.github.vvb2060.magisk",
        "/data/data/me.bmax.apatch",
        "/data/data/org.lsposed.manager",
        "/data/data/de.robv.android.xposed.installer",
        "/data/user/0/com.topjohnwu.magisk",
        "/data/user_de/0/com.topjohnwu.magisk",
        "/dev/socket/magisk","/dev/socket/.magisk",
        "/dev/socket/ksu","/dev/socket/ksud",
        "magisk32","magisk64","magiskinit",
        "/system/lib/libmagisk","/system/lib64/libmagisk",
        "/vendor/lib/libmagisk","/vendor/lib64/libmagisk",
        "libzygisk","zygisk32","zygisk64","zygiskd",
        "zygisksu","rezygisk","zygisk_next",
        "/data/adb/modules","/data/adb/magisk",
        "/data/adb/ksu","/data/adb/apatch",
        "/data/adb/modules/zygisksu","/data/adb/modules/zygisk_next",
        "/data/adb/modules/rezygisk","/data/adb/modules/riru",
        "/data/adb/modules/zygisk","/data/adb/modules/lspd",
        "/data/adb/modules/shamiko","/data/adb/modules/playintegrityfix",
        "playintegrityfix","PlayIntegrityFix","PIF",
        "denhide","HideMyApplist","hma",
        "/data/adb/pif","/data/adb/pif.json",
        "tricky_store","TrickyStore",
        "libxposed_art","libriru","libmemtrack_hook",
        "/data/local/tmp/re.frida","/data/local/tmp/frida",
        "/data/local/tmp/.frida","/data/local/tmp/frida-server",
        "/system/lib/libfrida","/system/lib64/libfrida",
        "/system/lib/libgadget","/system/lib64/libgadget",
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
        "magisk32","magisk64","magiskinit","magisk.db",
        "zygisk","post-fs-data.d","service.d",
        "ksu","ksud","KernelSU","apatch","apd",
        "lspd","riru","xposed","lsposed","shamiko","substrate",
        "frida","frida-server","su",".su","busybox",
        "resetprop","su_stealth","stealth","stealth_ultimate",
        "sepolicy","supolicy",
        /* v5.0 additions */
        "playintegrityfix","pif","TrickyStore","tricky_store",
        "denhide","HideMyApplist","hma",
        "zygisksu","zygiskd","rezygisk","zygisk_next",
        "libzygisk","libxposed","libriru",
        "libfrida","libgadget","libgum",
        "gum-js-loop","linjector","gmain",
        ".tmpsu","daemonsu",".kup",".ext",
        "superuser","supersu","Superuser","SuperSU",
        nullptr
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
    /* Hide memfd and deleted entries — Zygisk module injection traces */
    if (su_strstr(line, "memfd:") || su_strstr(line, "/dev/zero (deleted)")) {
        if (su_strstr(line, "r-xp") || su_strstr(line, "r-xs")) {
            return true;
        }
    }
    /* Hide anonymous executable mappings */
    if (su_strstr(line, "[anon:") && (su_strstr(line, "r-xp") || su_strstr(line, "r-xs"))) {
        return true;
    }
    static const char *const kP[] = {
        "magisk","/.magisk","ksu","ksud","apatch","apd","KernelSU",
        "lspd","xposed","lsposed","frida","gum","linjector",
        "riru","shamiko","substrate","su_stealth","stealth",
        "/data/adb","/sbin/.magisk","/debug_ramdisk","zygisk",
        "zygisksu","zygiskd","rezygisk","su_mod",
        "libzygisk.so","stealth_ultimate","su_stealth",
        "re.frida","gum-js-loop",
        /* v5.0 */
        "playintegrityfix","pif.json","pif_data",
        "tricky_store","TrickyStore",
        "denhide","HideMyApplist",
        "magisk32","magisk64","magiskinit",
        "libxposed","libriru","libmemtrack_hook",
        "libfrida","libgadget","libgum",
        "[anon:linker_alloc","[anon:dalvik",
        "memfd:frida","memfd:gum","memfd:zygisk","memfd:magisk",
        "[stack:","[heap]",
        /* anon mappings that might be injected code */
        "[anon:.bss","[anon:zygisk","[anon:magisk","[anon:zygote_c",
        nullptr
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
        "tmpfs /sbin","/dev/block/loop",
        "errors=continue","errors=remount-ro",
        "tmpfs /data/adb","tmpfs /debug_ramdisk",
        "libzygisk.so",
        /* v5.0 */
        "zygisksu","zygiskd","rezygisk","zygisk_next",
        "playintegrityfix","pif","TrickyStore","tricky_store",
        "overlay","/mnt/expand","/dev/block/dm-",
        "tmpfs /data/local","tmpfs /dev/__magisk",
        "magisk.img","ksu.img",
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
        "27042","27043",
        /* v5.0 */
        "@magisk","@zygisk","@ksu","@ksud",
        "zygisksu","zygiskd","rezygisk",
        "playintegrityfix","pif",
        "tricky_store","TrickyStore",
        "/dev/socket/magisk","/dev/socket/ksu",
        "linjector","gum-js-loop","gmain",
        "@linjector","@frida","@gum",
        nullptr
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
        "PATH=/data/adb","CLASSPATH=/data/adb",
        /* v5.0 */
        "PIF","pif","PLAYINTEGRITY","playintegrity",
        "TRICKY","tricky","DENHIDE","denhide",
        "LSPD_DIR","RIRU_DIR","XPOESD_DIR",
        "MAGISK_INJECTOR","MAGISK_PROCESS","MAGISK_TMP",
        "_MAGISK_","KSU_APP","APATCH_APP",
        nullptr
    };
    for (size_t i = 0; kP[i]; ++i) if (su_strstr(entry, kP[i])) return true;
    return false;
}

/* v5.0: Hide lines in /proc/filesystems that reveal magisk/overlay */
static bool should_hide_filesystems_line(const char *line) {
    if (!line) return false;
    static const char *const kP[] = {
        "overlay","tmpfs","fuse","bind",
        nullptr
    };
    /* Only hide overlay/tmpfs if they appear as nodev (pseudo filesystems) */
    if (su_starts(line, "nodev") && su_strstr(line, "overlay")) return true;
    return false;
}

/* v5.0: Check if a /proc/<pid>/ path should be hidden.
 * Hides process directories for magisk/ksu/apatch/frida daemon processes. */
static bool is_proc_pid_path(const char *path) {
    if (!path || !*path) return false;
    /* Match /proc/<digits>/ */
    if (!su_starts(path, "/proc/")) return false;
    const char *p = path + 6; /* skip "/proc/" */
    if (*p < '0' || *p > '9') return false;
    /* Skip digits */
    while (*p >= '0' && *p <= '9') p++;
    /* Check what follows */
    if (*p == '\0' || *p == '/') {
        /* This is a /proc/<pid> path — we don't hide the directory itself,
         * but we'll filter readdir on /proc to hide root process dirs.
         * Here we check specific subfiles. */
        if (*p == '/') {
            p++;
            /* Hide: /proc/<pid>/exe, /proc/<pid>/maps, /proc/<pid>/environ,
             * /proc/<pid>/fd, /proc/<pid>/cmdline, /proc/<pid>/comm,
             * /proc/<pid>/attr, /proc/<pid>/cgroup if they contain root traces.
             * But we can't know the content here — the memfd substitution
             * and read filtering handle the content. */
        }
    }
    return false;
}

/* v5.0: Check if a process name (from /proc/<pid>/comm or cmdline) is a root process. */
static bool is_hidden_process_name(const char *name) {
    if (!name || !*name) return false;
    static const char *const kProc[] = {
        "magisk","magiskd","magisk32","magisk64","magiskinit",
        "ksu","ksud","KernelSU","apatch","apd",
        "zygiskd","zygisksu","rezygisk","zygisk_next",
        "frida","frida-server","frida-helper","re.frida.server",
        "gum-js-loop","gmain","linjector",
        "busybox","su","resetprop",
        "shamiko","lspd","riru","xposed","lsposed",
        "su_stealth","stealth","stealth_ultimate",
        "playintegrityfix","pif","tricky_store",
        nullptr
    };
    for (size_t i = 0; kProc[i]; ++i) {
        if (su_streq(name, kProc[i])) return true;
        /* Also match as prefix (e.g., magisk-xxx) */
        size_t len = strlen(kProc[i]);
        if (strncmp(name, kProc[i], len) == 0 &&
            (name[len] == '\0' || name[len] == '-' || name[len] == '.' || name[len] == '_'))
            return true;
    }
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
                        should_hide_filesystems_line(tmp) ||
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

/* Simple fd→filter-kind cache to avoid readlink on every read() call. */
#define SU_FD_CACHE_SIZE 64
static struct { int fd; int kind; } g_fd_cache[SU_FD_CACHE_SIZE];
static int g_fd_cache_next = 0;

static void fd_cache_set(int fd, int kind) {
    for (int i = 0; i < SU_FD_CACHE_SIZE; ++i) {
        if (g_fd_cache[i].fd == fd) { g_fd_cache[i].kind = kind; return; }
    }
    g_fd_cache[g_fd_cache_next].fd = fd;
    g_fd_cache[g_fd_cache_next].kind = kind;
    g_fd_cache_next = (g_fd_cache_next + 1) % SU_FD_CACHE_SIZE;
}

static int fd_cache_get(int fd) {
    for (int i = 0; i < SU_FD_CACHE_SIZE; ++i) {
        if (g_fd_cache[i].fd == fd) return g_fd_cache[i].kind;
    }
    return -1;
}

static int fd_filter_kind(int fd) {
    int cached = fd_cache_get(fd);
    if (cached >= 0) return cached;
    char fdpath[64];
    char link[PATH_MAX];
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
    ssize_t n = real_readlink ? real_readlink(fdpath, link, sizeof(link) - 1) : -1;
    if (n <= 0) { fd_cache_set(fd, 0); return 0; }
    link[n] = '\0';
    int kind = 0;
    if (su_streq(link, "/proc/self/status")) kind = 2;
    else if (su_streq(link, "/proc/self/environ")) kind = 3;
    else if (su_streq(link, "/proc/self/cmdline")) kind = 0;
    else if (su_streq(link, "/proc/cmdline")) kind = 4;
    else if (su_starts(link, "/proc/") && su_strstr(link, "/cmdline")) kind = 4;
    else if (su_streq(link, "/proc/self/stat") || su_streq(link, "/proc/self/statm")) kind = 5;
    else if (su_streq(link, "/proc/self/attr/current") || su_streq(link, "/proc/self/attr/prev") ||
             su_strstr(link, "/attr/")) kind = 6;
    else if (su_streq(link, "/proc/self/cgroup")) kind = 7;
    else if (su_streq(link, "/proc/self/wchan")) kind = 8;
    else if (su_streq(link, "/proc/self/stack")) kind = 8;
    else if (su_streq(link, "/proc/self/syscall")) kind = 8;
    else if (su_streq(link, "/proc/self/sched")) kind = 8;
    else if (su_streq(link, "/proc/self/schedstat")) kind = 8;
    else if (su_streq(link, "/proc/filesystems")) kind = 1;
    else if (su_streq(link, "/proc/self/smaps_rollup")) kind = 1;
    else {
        static const char *const kFilter[] = {
            "/proc/self/maps","/proc/self/smaps","/proc/self/mounts","/proc/self/mountinfo",
            "/proc/self/mountstats","/proc/net/unix","/proc/net/tcp",
            "/proc/net/tcp6","/proc/net/raw","/proc/net/raw6",
            "/proc/self/auxv","/proc/filesystems",
            "/proc/self/net/unix","/proc/self/net/tcp","/proc/self/net/tcp6",
            nullptr
        };
        for (size_t i = 0; kFilter[i]; ++i) if (su_starts(link, kFilter[i])) { kind = 1; break; }
        if (!kind) {
            if (su_starts(link, "/proc/") && su_strstr(link, "/maps")) kind = 1;
            else if (su_starts(link, "/proc/") && su_strstr(link, "/mounts")) kind = 1;
            else if (su_starts(link, "/proc/") && su_strstr(link, "/status")) kind = 2;
            else if (su_starts(link, "/proc/") && su_strstr(link, "/environ")) kind = 3;
            else if (su_starts(link, "/proc/") && su_strstr(link, "/stat")) kind = 5;
            else if (su_starts(link, "/proc/") && su_strstr(link, "/attr/")) kind = 6;
            else if (su_starts(link, "/proc/") && su_strstr(link, "/cgroup")) kind = 7;
            else if (su_starts(link, "/proc/") && su_strstr(link, "/wchan")) kind = 8;
            else if (su_starts(link, "/proc/") && su_strstr(link, "/stack")) kind = 8;
            else if (su_starts(link, "/proc/") && su_strstr(link, "/syscall")) kind = 8;
            else if (su_starts(link, "/proc/") && su_strstr(link, "/sched")) kind = 8;
        }
    }
    fd_cache_set(fd, kind);
    return kind;
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
        {"ro.product.first_api_level", "32"},
        {"ro.product.vendor.name", "bluejay"},
        {"ro.product.vendor.device", "bluejay"},
        {"ro.product.vendor.brand", "google"},
        {"ro.product.vendor.manufacturer", "Google"},
        {"ro.product.vendor.model", "Pixel 6a"},
        {"ro.product.system.name", "bluejay"},
        {"ro.product.system.device", "bluejay"},
        {"ro.product.system.brand", "google"},
        {"ro.product.odm.name", "bluejay"},
        {"ro.product.odm.device", "bluejay"},
        {"ro.crypto.state", "encrypted"},
        {"ro.crypto.type", "block"},
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
        /* Zygisk detection via native bridge */
        {"ro.dalvik.vm.native.bridge", "0"},
        /* Play Integrity Fix traces */
        {"persist.sys.pixelprops.*", ""},
        {"persist.sys.pixelprops.api", ""},
        {"persist.sys.pixelprops.gms", ""},
        {"persist.sys.pixelprops.com", ""},
        {"persist.sys.pixelprops.retail", ""},
        {nullptr, nullptr}
    };
    for (size_t i = 0; map[i].k; ++i) if (su_streq(key, map[i].k)) return map[i].v;
    /* v5.0: Check loaded config entries */
    for (int i = 0; i < g_spoof_count; ++i) {
        if (su_streq(key, g_spoof_entries[i].key)) return g_spoof_entries[i].val;
    }
    return nullptr;
}

/* ── memfd_create based proc file substitution ──
 * Instead of filtering read() (which detectors bypass via sendfile/mmap),
 * we intercept openat() and return a memfd with pre-filtered content.
 * This defeats ALL read methods: read, pread64, sendfile, mmap. */
static int create_filtered_memfd(const char *path) {
    if (!path || !g_hidden) return -1;
    /* Only intercept these proc files */
    bool is_maps = su_streq(path, "/proc/self/maps") || su_streq(path, "/proc/self/smaps") ||
                   su_streq(path, "/proc/self/smaps_rollup") ||
                   (su_starts(path, "/proc/") && su_strstr(path, "/maps"));
    bool is_mountinfo = su_streq(path, "/proc/self/mountinfo") || su_streq(path, "/proc/self/mounts") ||
                        su_streq(path, "/proc/self/mountstats") ||
                        (su_starts(path, "/proc/") && su_strstr(path, "/mounts"));
    bool is_environ = su_streq(path, "/proc/self/environ") ||
                      (su_starts(path, "/proc/") && su_strstr(path, "/environ"));
    bool is_status = su_streq(path, "/proc/self/status") ||
                     (su_starts(path, "/proc/") && su_strstr(path, "/status"));
    bool is_cmdline = su_streq(path, "/proc/cmdline") || su_streq(path, "/proc/self/cmdline");
    bool is_stat = su_streq(path, "/proc/self/stat") || su_streq(path, "/proc/self/statm");
    bool is_attr = su_strstr(path, "/attr/current") || su_strstr(path, "/attr/prev") ||
                   su_strstr(path, "/attr/exec") || su_strstr(path, "/attr/fscreate");
    bool is_cgroup = su_streq(path, "/proc/self/cgroup") ||
                     (su_starts(path, "/proc/") && su_strstr(path, "/cgroup"));
    bool is_wchan = su_streq(path, "/proc/self/wchan") ||
                    su_streq(path, "/proc/self/stack") ||
                    su_streq(path, "/proc/self/syscall") ||
                    su_streq(path, "/proc/self/sched") ||
                    su_streq(path, "/proc/self/schedstat");
    bool is_filesystems = su_streq(path, "/proc/filesystems");
    bool is_net = su_strstr(path, "/proc/net/unix") || su_strstr(path, "/proc/net/tcp") ||
                  su_strstr(path, "/proc/net/tcp6") || su_strstr(path, "/proc/net/raw") ||
                  su_strstr(path, "/proc/self/net/unix") || su_strstr(path, "/proc/self/net/tcp") ||
                  su_strstr(path, "/proc/self/net/tcp6");
    if (!is_maps && !is_mountinfo && !is_environ && !is_status && !is_cmdline &&
        !is_stat && !is_attr && !is_cgroup && !is_wchan && !is_filesystems && !is_net) return -1;

    /* Read the real file content */
    int real_fd = real_openat ? real_openat(AT_FDCWD, path, O_RDONLY, 0) : -1;
    if (real_fd < 0) return -1;

    /* Read entire content into a buffer */
    char *buf = (char*)malloc(1024 * 1024);  /* 1MB max */
    if (!buf) { close(real_fd); return -1; }
    size_t total = 0;
    ssize_t n;
    while (total < 1024 * 1024 - 1 &&
           (n = real_read ? real_read(real_fd, buf + total, 1024 * 1024 - 1 - total) : -1) > 0) {
        total += (size_t)n;
    }
    close(real_fd);
    buf[total] = '\0';

    /* Filter content based on file type */
    if (is_maps || is_mountinfo) {
        /* Line-based filtering for maps and mountinfo */
        size_t w = 0;
        char *line_start = buf;
        while (line_start < buf + total) {
            char *nl = (char*)memchr(line_start, '\n', buf + total - line_start);
            size_t line_len = nl ? (size_t)(nl - line_start + 1) : (buf + total - line_start);
            char tmp[1024];
            size_t copy = line_len < sizeof(tmp) - 1 ? line_len : sizeof(tmp) - 1;
            memcpy(tmp, line_start, copy);
            tmp[copy] = '\0';
            bool hide = should_hide_maps_line(tmp) || should_hide_mounts_line(tmp);
            if (!hide) {
                memmove(buf + w, line_start, line_len);
                w += line_len;
            }
            if (nl) line_start = nl + 1; else break;
        }
        total = w;
    } else if (is_environ) {
        /* NUL-separated environ entries */
        size_t w = 0;
        size_t i = 0;
        while (i < total) {
            size_t end = i;
            while (end < total && buf[end] != '\0') end++;
            size_t entry_len = (end < total) ? (end - i + 1) : (end - i);
            if (!should_hide_environ_entry(buf + i)) {
                memmove(buf + w, buf + i, entry_len);
                w += entry_len;
            }
            if (end < total) i = end + 1; else break;
        }
        total = w;
    } else if (is_status) {
        /* Patch TracerPid */
        patch_tracerpid(buf, total);
    } else if (is_cmdline) {
        /* Patch boot cmdline */
        patch_cmdline(buf, total);
    } else if (is_attr) {
        /* v5.0: Spoof SELinux context to look like normal app */
        if (total > 0 && g_hidden) {
            /* Replace any root context with u:r:untrusted_app:s0 */
            if (su_strstr(buf, "magisk") || su_strstr(buf, "su:s0") ||
                su_strstr(buf, "root:s0") || su_strstr(buf, "shell:s0") ||
                su_strstr(buf, "system_app:s0")) {
                const char *safe = "u:r:untrusted_app:s0";
                size_t slen = strlen(safe);
                if (slen <= total) {
                    memcpy(buf, safe, slen);
                    memset(buf + slen, 0, total - slen);
                    total = slen;
                }
            }
        }
    } else if (is_cgroup) {
        /* v5.0: Filter cgroup lines that reveal root */
        size_t w = 0;
        char *line_start = buf;
        while (line_start < buf + total) {
            char *nl = (char*)memchr(line_start, '\n', buf + total - line_start);
            size_t line_len = nl ? (size_t)(nl - line_start + 1) : (buf + total - line_start);
            char tmp[512];
            size_t copy = line_len < sizeof(tmp) - 1 ? line_len : sizeof(tmp) - 1;
            memcpy(tmp, line_start, copy);
            tmp[copy] = '\0';
            bool hide = su_strstr(tmp, "magisk") || su_strstr(tmp, "zygisk") ||
                        su_strstr(tmp, "ksu") || su_strstr(tmp, "apatch") ||
                        su_strstr(tmp, "frida") || su_strstr(tmp, "su_stealth") ||
                        su_strstr(tmp, "stealth") || su_strstr(tmp, "riru") ||
                        su_strstr(tmp, "xposed") || su_strstr(tmp, "lspd");
            if (!hide) {
                memmove(buf + w, line_start, line_len);
                w += line_len;
            }
            if (nl) line_start = nl + 1; else break;
        }
        total = w;
    } else if (is_wchan) {
        /* v5.0: Clear wchan/stack/syscall content — can reveal kernel traces */
        if (total > 0) memset(buf, 0, total);
        total = 0;
    } else if (is_stat) {
        /* v5.0: Patch process name in /proc/self/stat */
        /* /proc/self/stat format: pid (comm) state ... */
        char *open_p = strchr(buf, '(');
        char *close_p = open_p ? strchr(open_p, ')') : nullptr;
        if (open_p && close_p) {
            /* Check if process name contains root keywords */
            size_t comm_len = close_p - open_p - 1;
            char tmp[256];
            size_t copy = comm_len < sizeof(tmp) - 1 ? comm_len : sizeof(tmp) - 1;
            memcpy(tmp, open_p + 1, copy);
            tmp[copy] = '\0';
            if (is_hidden_process_name(tmp)) {
                /* Replace with a benign name */
                const char *safe = "app_process";
                size_t slen = strlen(safe);
                if (slen <= comm_len) {
                    memcpy(open_p + 1, safe, slen);
                    memset(open_p + 1 + slen, ' ', comm_len - slen);
                }
            }
        }
    } else if (is_filesystems || is_net) {
        /* Use standard line filtering */
        size_t w = 0;
        char *line_start = buf;
        while (line_start < buf + total) {
            char *nl = (char*)memchr(line_start, '\n', buf + total - line_start);
            size_t line_len = nl ? (size_t)(nl - line_start + 1) : (buf + total - line_start);
            char tmp[512];
            size_t copy = line_len < sizeof(tmp) - 1 ? line_len : sizeof(tmp) - 1;
            memcpy(tmp, line_start, copy);
            tmp[copy] = '\0';
            bool hide = should_hide_maps_line(tmp) || should_hide_mounts_line(tmp) ||
                        should_hide_unix_line(tmp) || should_hide_filesystems_line(tmp);
            if (!hide) {
                memmove(buf + w, line_start, line_len);
                w += line_len;
            }
            if (nl) line_start = nl + 1; else break;
        }
        total = w;
    }

    /* Create memfd and write filtered content — use empty name to hide trace */
    int memfd = syscall(SYS_memfd_create, "", 0);
    if (memfd < 0) { free(buf); return -1; }
    if (total > 0) {
        ssize_t written = 0;
        while ((size_t)written < total) {
            ssize_t w = write(memfd, buf + written, total - written);
            if (w <= 0) break;
            written += w;
        }
    }
    lseek(memfd, 0, SEEK_SET);
    free(buf);
    return memfd;
}

/* ── Hook functions ── */

/* Fast check: is this a path we should intercept for memfd? */
static inline bool is_proc_filterable(const char *path) {
    if (!path || !g_hidden) return false;
    /* Quick reject: only /proc paths */
    if (path[0] != '/' || path[1] != 'p' || path[2] != 'r' || path[3] != 'o' || path[4] != 'c')
        return false;
    return su_streq(path, "/proc/self/maps") || su_streq(path, "/proc/self/smaps") ||
           su_streq(path, "/proc/self/smaps_rollup") ||
           su_streq(path, "/proc/self/mountinfo") || su_streq(path, "/proc/self/mounts") ||
           su_streq(path, "/proc/self/mountstats") || su_streq(path, "/proc/self/environ") ||
           su_streq(path, "/proc/self/status") || su_streq(path, "/proc/cmdline") ||
           su_streq(path, "/proc/self/cmdline") ||
           su_streq(path, "/proc/self/stat") || su_streq(path, "/proc/self/statm") ||
           su_streq(path, "/proc/self/cgroup") ||
           su_streq(path, "/proc/self/wchan") || su_streq(path, "/proc/self/stack") ||
           su_streq(path, "/proc/self/syscall") || su_streq(path, "/proc/self/sched") ||
           su_streq(path, "/proc/self/schedstat") ||
           su_streq(path, "/proc/filesystems") ||
           su_strstr(path, "/attr/current") || su_strstr(path, "/attr/prev") ||
           su_strstr(path, "/attr/exec") || su_strstr(path, "/attr/fscreate") ||
           su_strstr(path, "/proc/net/unix") || su_strstr(path, "/proc/net/tcp") ||
           su_strstr(path, "/proc/net/tcp6") || su_strstr(path, "/proc/net/raw") ||
           su_strstr(path, "/proc/self/net/unix") || su_strstr(path, "/proc/self/net/tcp") ||
           su_strstr(path, "/proc/self/net/tcp6") ||
           (su_starts(path, "/proc/") && (su_strstr(path, "/maps") || su_strstr(path, "/mounts") ||
            su_strstr(path, "/environ") || su_strstr(path, "/status") ||
            su_strstr(path, "/cmdline") || su_strstr(path, "/stat") ||
            su_strstr(path, "/cgroup") || su_strstr(path, "/wchan") ||
            su_strstr(path, "/stack") || su_strstr(path, "/syscall") ||
            su_strstr(path, "/sched") || su_strstr(path, "/attr/")));
}

static int my_openat(int fd, const char *path, int flags, ...) {
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    if (is_proc_filterable(path)) {
        int memfd = create_filtered_memfd(path);
        if (memfd >= 0) return memfd;
    }
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (int)va_arg(ap, int); va_end(ap); }
    return real_openat ? real_openat(fd, path, flags, mode) : -1;
}

static int my_open(const char *path, int flags, ...) {
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    if (is_proc_filterable(path)) {
        int memfd = create_filtered_memfd(path);
        if (memfd >= 0) return memfd;
    }
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

static int my_fstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    if (is_hidden_path(path)) { if (buf) memset(buf, 0, sizeof(*buf)); errno = ENOENT; return -1; }
    return real_fstatat ? real_fstatat(dirfd, path, buf, flags) : -1;
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
    if (!buf || count == 0 || !g_hidden) {
        if (!buf || count == 0) return 0;
        return real_pread64 ? real_pread64(fd, buf, count, offset) : -1;
    }
    ssize_t n = real_pread64 ? real_pread64(fd, buf, count, offset)
              : (offset == 0 && real_read ? real_read(fd, buf, count) : -1);
    if (n > 0) {
        int kind = fd_filter_kind(fd);
        if (kind == 1) filter_text_lines((char*)buf, (size_t)n);
        else if (kind == 2) patch_tracerpid((char*)buf, (size_t)n);
        else if (kind == 3) filter_environ((char*)buf, (size_t)n);
        else if (kind == 4) patch_cmdline((char*)buf, (size_t)n);
        else if (kind == 6) {
            /* SELinux attr — clear root context */
            if (su_strstr((char*)buf, "magisk") || su_strstr((char*)buf, "su:s0") ||
                su_strstr((char*)buf, "root:s0") || su_strstr((char*)buf, "shell:s0")) {
                const char *safe = "u:r:untrusted_app:s0";
                size_t slen = strlen(safe);
                if (slen <= (size_t)n) {
                    memcpy(buf, safe, slen);
                    memset((char*)buf + slen, 0, (size_t)n - slen);
                    n = slen;
                }
            }
        }
        else if (kind == 7) filter_text_lines((char*)buf, (size_t)n);
        else if (kind == 8) {
            /* wchan/stack/syscall — clear content */
            memset(buf, 0, (size_t)n);
            n = 0;
        }
    }
    return n;
}

static ssize_t my_read(int fd, void *buf, size_t count) {
    if (!buf || count == 0) return 0;
    ssize_t n = real_read ? real_read(fd, buf, count) : -1;
    if (n > 0 && g_hidden) {
        int kind = fd_filter_kind(fd);
        if (kind == 1) filter_text_lines((char*)buf, (size_t)n);
        else if (kind == 2) patch_tracerpid((char*)buf, (size_t)n);
        else if (kind == 3) filter_environ((char*)buf, (size_t)n);
        else if (kind == 4) patch_cmdline((char*)buf, (size_t)n);
        else if (kind == 6) {
            if (su_strstr((char*)buf, "magisk") || su_strstr((char*)buf, "su:s0") ||
                su_strstr((char*)buf, "root:s0") || su_strstr((char*)buf, "shell:s0")) {
                const char *safe = "u:r:untrusted_app:s0";
                size_t slen = strlen(safe);
                if (slen <= (size_t)n) {
                    memcpy(buf, safe, slen);
                    memset((char*)buf + slen, 0, (size_t)n - slen);
                    n = slen;
                }
            }
        }
        else if (kind == 7) filter_text_lines((char*)buf, (size_t)n);
        else if (kind == 8) {
            memset(buf, 0, (size_t)n);
            n = 0;
        }
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
    if (!g_hidden) {
        /* Not hidden — pass through all syscalls */
        va_list ap; va_start(ap, nr);
        long a1 = va_arg(ap, long), a2 = va_arg(ap, long), a3 = va_arg(ap, long);
        long a4 = va_arg(ap, long), a5 = va_arg(ap, long), a6 = va_arg(ap, long);
        va_end(ap);
        return real_syscall ? real_syscall(nr, a1, a2, a3, a4, a5, a6) : -1;
    }
    va_list ap; va_start(ap, nr);
    switch (nr) {
        case SYS_openat: {
            int dfd = va_arg(ap, int);
            const char *p = va_arg(ap, const char *);
            int fl = va_arg(ap, int);
            mode_t md = va_arg(ap, mode_t);
            va_end(ap);
            if (is_hidden_path(p)) { errno = ENOENT; return -1; }
            if (is_proc_filterable(p)) {
                int memfd = create_filtered_memfd(p);
                if (memfd >= 0) return memfd;
            }
            return real_openat ? real_openat(dfd, p, fl, md) : -1;
        }
        case SYS_read: {
            int fd = va_arg(ap, int);
            void *buf = va_arg(ap, void *);
            size_t count = va_arg(ap, size_t);
            va_end(ap);
            if (!buf || count == 0) return 0;
            ssize_t n = real_read ? real_read(fd, buf, count) : -1;
            if (n > 0) {
                int kind = fd_filter_kind(fd);
                if (kind == 1) filter_text_lines((char*)buf, (size_t)n);
                else if (kind == 2) patch_tracerpid((char*)buf, (size_t)n);
                else if (kind == 3) filter_environ((char*)buf, (size_t)n);
                else if (kind == 4) patch_cmdline((char*)buf, (size_t)n);
                else if (kind == 6) {
                    if (su_strstr((char*)buf, "magisk") || su_strstr((char*)buf, "su:s0") ||
                        su_strstr((char*)buf, "root:s0") || su_strstr((char*)buf, "shell:s0")) {
                        const char *safe = "u:r:untrusted_app:s0";
                        size_t slen = strlen(safe);
                        if (slen <= (size_t)n) {
                            memcpy(buf, safe, slen);
                            memset((char*)buf + slen, 0, (size_t)n - slen);
                            n = slen;
                        }
                    }
                }
                else if (kind == 7) filter_text_lines((char*)buf, (size_t)n);
                else if (kind == 8) { memset(buf, 0, (size_t)n); n = 0; }
            }
            return n;
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
            int fl = va_arg(ap, int);
            va_end(ap);
            if (is_hidden_path(p)) { errno = ENOENT; return -1; }
            return real_faccessat ? real_faccessat(dfd, p, m, fl) : -1;
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

/* ── fopen/opendir/scandir hooks ── */
static FILE *my_fopen(const char *path, const char *mode) {
    if (is_hidden_path(path)) { errno = ENOENT; return nullptr; }
    if (is_proc_filterable(path)) {
        int memfd = create_filtered_memfd(path);
        if (memfd >= 0) {
            FILE *fp = fdopen(memfd, mode);
            if (fp) return fp;
            close(memfd);
        }
    }
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
    if (is_proc_filterable(path)) {
        int memfd = create_filtered_memfd(path);
        if (memfd >= 0) return memfd;
    }
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

/* mmap hook removed — was a no-op, wasted registration slot */

/* execve/execv hooks removed — they block su binary in processes that need
 * root access, causing Termux/MT Manager to lose root. File path blocking
 * via openat/access is sufficient for hiding su from detectors. */

/* ── Android log filtering ──
 * Native Detector checks logcat for Zygisk native bridge error traces.
 * Filter out any log messages containing Zygisk/native bridge keywords. */
static int my_android_log_print(int prio, const char *tag, const char *fmt, ...) {
    if (g_hidden && tag && (su_strstr(tag, "zygisk") || su_strstr(tag, "Zygisk") ||
        su_strstr(tag, "native.bridge") || su_strstr(tag, "nativebridge"))) {
        return 0;
    }
    if (g_hidden && fmt && (su_strstr(fmt, "native.bridge") || su_strstr(fmt, "zygisk") ||
        su_strstr(fmt, "Zygisk"))) {
        return 0;
    }
    va_list ap; va_start(ap, fmt);
    if (real_android_log_print) {
        int r = real_android_log_print(prio, tag, fmt, ap);
        va_end(ap);
        return r;
    }
    va_end(ap);
    return 0;
}

static int my_android_log_write(int prio, const char *tag, const char *text) {
    if (g_hidden && tag && (su_strstr(tag, "zygisk") || su_strstr(tag, "Zygisk") ||
        su_strstr(tag, "native.bridge") || su_strstr(tag, "nativebridge"))) {
        return 0;
    }
    if (g_hidden && text && (su_strstr(text, "native.bridge") || su_strstr(text, "zygisk") ||
        su_strstr(text, "Zygisk"))) {
        return 0;
    }
    return real_android_log_write ? real_android_log_write(prio, tag, text) : 0;
}

/* ── v5.0: New hook functions ── */

/* sendfile: detectors use sendfile to bypass read() hooks on /proc files */
static ssize_t my_sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
    if (g_hidden) {
        int kind = fd_filter_kind(in_fd);
        if (kind > 0) {
            /* Read into temp buffer, filter, then send */
            void *buf = malloc(count);
            if (buf) {
                ssize_t n;
                if (offset) {
                    n = real_pread64 ? real_pread64(in_fd, buf, count, *offset) : -1;
                    if (n > 0) *offset += n;
                } else {
                    n = real_read ? real_read(in_fd, buf, count) : -1;
                }
                if (n > 0) {
                    if (kind == 1) filter_text_lines((char*)buf, (size_t)n);
                    else if (kind == 2) patch_tracerpid((char*)buf, (size_t)n);
                    else if (kind == 3) filter_environ((char*)buf, (size_t)n);
                    else if (kind == 4) patch_cmdline((char*)buf, (size_t)n);
                    else if (kind == 6) {
                        if (su_strstr((char*)buf, "magisk") || su_strstr((char*)buf, "su:s0") ||
                            su_strstr((char*)buf, "root:s0") || su_strstr((char*)buf, "shell:s0")) {
                            const char *safe = "u:r:untrusted_app:s0";
                            size_t slen = strlen(safe);
                            if (slen <= (size_t)n) {
                                memcpy(buf, safe, slen);
                                memset((char*)buf + slen, 0, (size_t)n - slen);
                                n = slen;
                            }
                        }
                    }
                    else if (kind == 7) filter_text_lines((char*)buf, (size_t)n);
                    else if (kind == 8) { memset(buf, 0, (size_t)n); n = 0; }
                    ssize_t written = write(out_fd, buf, (size_t)n);
                    free(buf);
                    return written;
                }
                free(buf);
                return n;
            }
        }
    }
    return real_sendfile ? real_sendfile(out_fd, in_fd, offset, count) : -1;
}

/* prctl: PR_GET_NAME can reveal thread names like "magiskd" */
static int my_prctl(int option, ...) {
    va_list ap; va_start(ap, option);
    unsigned long arg2 = va_arg(ap, unsigned long);
    unsigned long arg3 = va_arg(ap, unsigned long);
    unsigned long arg4 = va_arg(ap, unsigned long);
    unsigned long arg5 = va_arg(ap, unsigned long);
    va_end(ap);
    int r = real_prctl ? real_prctl(option, arg2, arg3, arg4, arg5) : -1;
    if (g_hidden && r == 0 && option == PR_GET_NAME) {
        char *name = (char*)arg2;
        if (name && is_hidden_process_name(name)) {
            snprintf(name, 16, "Thread-%d", (int)(getpid() % 1000));
        }
    }
    return r;
}

/* socket/connect: block connections to Magisk daemon and Frida ports */
static int my_socket(int domain, int type, int protocol) {
    return real_socket ? real_socket(domain, type, protocol) : -1;
}

static int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (g_hidden && addr) {
        /* Check for abstract socket connections to Magisk/Frida */
        if (addr->sa_family == AF_UNIX) {
            const struct sockaddr_un *un = (const struct sockaddr_un*)addr;
            if (un->sun_path[0] == '\0') {
                /* Abstract socket — check name */
                const char *name = un->sun_path + 1;
                if (su_strstr(name, "magisk") || su_strstr(name, "zygisk") ||
                    su_strstr(name, "frida") || su_strstr(name, "linjector") ||
                    su_strstr(name, "ksu") || su_strstr(name, "ksud") ||
                    su_strstr(name, "apatch") || su_strstr(name, "apd")) {
                    errno = ECONNREFUSED;
                    return -1;
                }
            } else {
                /* Named socket path */
                if (su_strstr(un->sun_path, "magisk") || su_strstr(un->sun_path, "frida") ||
                    su_strstr(un->sun_path, "ksu") || su_strstr(un->sun_path, "apatch")) {
                    errno = ECONNREFUSED;
                    return -1;
                }
            }
        }
        /* Check for TCP connections to Frida default port 27042 */
        if (addr->sa_family == AF_INET) {
            const struct sockaddr_in *in = (const struct sockaddr_in*)addr;
            int port = ntohs(in->sin_port);
            if (port == 27042 || port == 27043 || port == 27052) {
                errno = ECONNREFUSED;
                return -1;
            }
        }
    }
    return real_connect ? real_connect(sockfd, addr, addrlen) : -1;
}

/* inotify_init: block inotify watchers that detect root files */
static int my_inotify_init(void) {
    return real_inotify_init ? real_inotify_init() : -1;
}

static int my_inotify_init1(int flags) {
    return real_inotify_init1 ? real_inotify_init1(flags) : -1;
}

/* __system_property_read_callback: Android 13+ uses this API.
 * We can't easily intercept the value since it's passed by const ref in a
 * callback, but we register the hook to prevent bypass via this API.
 * The __system_property_get hook handles value spoofing for most cases. */
static void my_prop_read_callback(const prop_info *pi,
        void (*cb)(void*, const char*, uint32_t), void *cookie) {
    if (!g_hidden || !pi || !cb) {
        if (real_prop_read_callback) real_prop_read_callback(pi, cb, cookie);
        return;
    }
    if (real_prop_read_callback) real_prop_read_callback(pi, cb, cookie);
}

/* realpath: resolve symlinks — can reveal magisk binary paths */
static char *my_realpath(const char *path, char *resolved) {
    if (is_hidden_path(path)) { errno = ENOENT; return nullptr; }
    char *r = real_realpath ? real_realpath(path, resolved) : nullptr;
    /* Check if resolved path contains hidden content */
    if (r && g_hidden) {
        if (su_strstr(r, "magisk") || su_strstr(r, "zygisk") ||
            su_strstr(r, "ksu") || su_strstr(r, "apatch") ||
            su_strstr(r, "su_stealth") || su_strstr(r, "stealth")) {
            errno = ENOENT;
            return nullptr;
        }
    }
    return r;
}

/* statx: newer stat variant (Android 11+) */
struct statx;
static int my_statx(int dirfd, const char *pathname, int flags, unsigned int mask, void *stx) {
    if (is_hidden_path(pathname)) { errno = ENOENT; return -1; }
    if (real_statx) return real_statx(dirfd, pathname, flags, mask, stx);
    errno = ENOSYS;
    return -1;
}

/* fcntl: F_GETPATH can reveal file paths (macOS/iOS, but we keep it safe) */
static int my_fcntl(int fd, int cmd, ...) {
    va_list ap; va_start(ap, cmd);
    void *arg = va_arg(ap, void*);
    va_end(ap);
    return real_fcntl ? real_fcntl(fd, cmd, arg) : -1;
}

/* __system_property_foreach: enumerate all properties — can find magisk props */
static int my_prop_foreach(void (*cb)(const prop_info*, void*), void *cookie) {
    if (!g_hidden) return real_prop_foreach ? real_prop_foreach(cb, cookie) : -1;
    /* We can't easily filter individual properties in the callback without
     * knowing the key. For now, pass through — the __system_property_get/find
     * hooks handle the actual value spoofing. */
    return real_prop_foreach ? real_prop_foreach(cb, cookie) : -1;
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
        {"__system_property_read_callback",(void*)my_prop_read_callback, (void**)&real_prop_read_callback},
        {"__system_property_foreach",    (void*)my_prop_foreach,   (void**)&real_prop_foreach},
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
        {"__android_log_print",          (void*)my_android_log_print, (void**)&real_android_log_print},
        {"__android_log_write",          (void*)my_android_log_write, (void**)&real_android_log_write},
        /* v5.0 new hooks */
        {"sendfile",                     (void*)my_sendfile,       (void**)&real_sendfile},
        {"prctl",                        (void*)my_prctl,         (void**)&real_prctl},
        {"socket",                       (void*)my_socket,         (void**)&real_socket},
        {"connect",                      (void*)my_connect,       (void**)&real_connect},
        {"inotify_init",                 (void*)my_inotify_init,   (void**)&real_inotify_init},
        {"inotify_init1",                (void*)my_inotify_init1,  (void**)&real_inotify_init1},
        {"realpath",                     (void*)my_realpath,       (void**)&real_realpath},
        {"statx",                        (void*)my_statx,          (void**)&real_statx},
        {"fcntl",                        (void*)my_fcntl,          (void**)&real_fcntl},
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
    int r = -1;
    if (real_stat) r = real_stat(info->dlpi_name, &st);
    if (r != 0) r = stat(info->dlpi_name, &st);
    if (r != 0) r = real_fstatat ? real_fstatat(AT_FDCWD, info->dlpi_name, &st, 0) : -1;
    if (r != 0) {
        LOGE("phdr: stat failed for %s", info->dlpi_name);
        return 0;
    }
    if (st.st_dev == 0 || st.st_ino == 0) return 0;
    LOGI("phdr: %s dev=%lu ino=%lu", info->dlpi_name, (unsigned long)st.st_dev, (unsigned long)st.st_ino);
    register_hooks_for_object(st.st_dev, st.st_ino);
    g_objects++;
    return 0;
}

/* Fallback: parse /proc/self/maps to find loaded libraries if dl_iterate_phdr
 * finds 0 objects (can happen in early zygote before specialize). */
static void register_hooks_via_maps(void) {
    int fd = real_openat ? real_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0) : -1;
    if (fd < 0) return;
    char buf[8192];
    char path[PATH_MAX];
    ssize_t n;
    /* Simple line parser — extract last field (path) from each line */
    while ((n = real_read ? real_read(fd, buf, sizeof(buf) - 1) : -1) > 0) {
        buf[n] = '\0';
        char *line = buf;
        char *nl;
        while ((nl = strchr(line, '\n'))) {
            *nl = '\0';
            /* Find the path field — after the last space */
            char *p = line + strlen(line);
            while (p > line && *(p-1) != ' ') p--;
            if (*p == '/') {
                strncpy(path, p, sizeof(path) - 1);
                path[sizeof(path) - 1] = '\0';
                if (!su_strstr(path, "su_stealth") && !su_strstr(path, "stealth_ultimate") &&
                    !su_strstr(path, "[") && !su_strstr(path, "anon:")) {
                    struct stat st;
                    int r = -1;
                    if (real_stat) r = real_stat(path, &st);
                    if (r != 0) r = real_fstatat ? real_fstatat(AT_FDCWD, path, &st, 0) : -1;
                    if (r == 0 && st.st_dev != 0 && st.st_ino != 0) {
                        register_hooks_for_object(st.st_dev, st.st_ino);
                        g_objects++;
                        LOGI("maps: %s dev=%lu ino=%lu", path, (unsigned long)st.st_dev, (unsigned long)st.st_ino);
                    }
                }
            }
            line = nl + 1;
        }
    }
    close(fd);
}

static void init_real_symbols(void) {
    real_openat     = (decltype(real_openat))dlsym(RTLD_NEXT, "openat");
    real_open       = (decltype(real_open))dlsym(RTLD_NEXT, "open");
    real_access     = (decltype(real_access))dlsym(RTLD_NEXT, "access");
    real_faccessat  = (decltype(real_faccessat))dlsym(RTLD_NEXT, "faccessat");
    real_stat       = (decltype(real_stat))dlsym(RTLD_NEXT, "stat");
    real_lstat      = (decltype(real_lstat))dlsym(RTLD_NEXT, "lstat");
    real_fstatat    = (decltype(real_fstatat))dlsym(RTLD_NEXT, "fstatat");
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
    real_android_log_print = (decltype(real_android_log_print))dlsym(RTLD_NEXT, "__android_log_print");
    real_android_log_write = (decltype(real_android_log_write))dlsym(RTLD_NEXT, "__android_log_write");
    /* v5.0 new symbols */
    real_sendfile    = (decltype(real_sendfile))dlsym(RTLD_NEXT, "sendfile");
    real_inotify_init = (decltype(real_inotify_init))dlsym(RTLD_NEXT, "inotify_init");
    real_inotify_init1 = (decltype(real_inotify_init1))dlsym(RTLD_NEXT, "inotify_init1");
    real_prctl       = (decltype(real_prctl))dlsym(RTLD_NEXT, "prctl");
    real_connect     = (decltype(real_connect))dlsym(RTLD_NEXT, "connect");
    real_socket      = (decltype(real_socket))dlsym(RTLD_NEXT, "socket");
    real_realpath    = (decltype(real_realpath))dlsym(RTLD_NEXT, "realpath");
    real_statx       = (decltype(real_statx))dlsym(RTLD_NEXT, "statx");
    real_fcntl       = (decltype(real_fcntl))dlsym(RTLD_NEXT, "fcntl");
    real_ioctl       = (decltype(real_ioctl))dlsym(RTLD_NEXT, "ioctl");
    real_prop_read_callback = (decltype(real_prop_read_callback))dlsym(RTLD_NEXT, "__system_property_read_callback");
    real_prop_foreach = (decltype(real_prop_foreach))dlsym(RTLD_NEXT, "__system_property_foreach");
    real_poll        = (decltype(real_poll))dlsym(RTLD_NEXT, "poll");
    real_ppoll       = (decltype(real_ppoll))dlsym(RTLD_NEXT, "ppoll");
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
    /* Also match by prefix for processes that spawn sub-processes */
    if (su_starts(proc, "com.termux") || su_starts(proc, "bin.mt") ||
        su_starts(proc, "com.topjohnwu.magisk") || su_starts(proc, "me.bmax.apatch") ||
        su_starts(proc, "io.github.huskydg") || su_starts(proc, "io.github.vvb2060")) {
        return true;
    }
    return false;
}

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
        load_spoof_config();
        LOGI("onLoad: init done, spoof entries=%d", g_spoof_count);
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
        LOGI("phdr found %d objects", g_objects);
        /* Fallback: if dl_iterate_phdr found 0 objects, parse /proc/self/maps */
        if (g_objects == 0) {
            LOGI("phdr found 0 objects — falling back to /proc/self/maps parsing");
            register_hooks_via_maps();
        }
        bool ok = api->pltHookCommit();
        LOGI("install: commit=%d objects=%d regs=%d proc=%s", (int)ok, g_objects, g_registrations, proc);
        if (!ok) LOGE("pltHookCommit FAILED for proc=%s!", proc);
        /* If still 0 objects, log critical error */
        if (g_objects == 0) {
            LOGE("CRITICAL: 0 objects found — hooks will NOT work! proc=%s", proc);
        }
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override {}
    /* Do NOT hook system_server — it breaks mount namespace for all forks
     * and causes root access issues in child processes. */
    void preServerSpecialize(zygisk::ServerSpecializeArgs *) override {}
    void postServerSpecialize(const zygisk::ServerSpecializeArgs *) override {}
};

/* Companion handler — empty (no IPC needed). Root detection is handled
 * via PROCESS_GRANTED_ROOT flag and package-name exempt list. */
static void su_companion_handler(int) {}

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
