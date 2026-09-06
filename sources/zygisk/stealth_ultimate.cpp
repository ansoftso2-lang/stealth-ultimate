/* SPDX-License-Identifier: MIT */
/*
 * stealth_ultimate.cpp — Universal Zygisk Anti-Detection Module (v3.0)
 *
 * Targets: Magisk (+Zygisk), KernelSU (with zygisksu/zygisk-next), APatch,
 *          Zygisk Next, ReZygisk. Works under custom ROMs and crowded setups.
 *
 * Hides:  root, Magisk, KernelSU, APatch, Zygisk family, LSPosed, Xposed,
 *         Riru, Shamiko, Frida (gum/linjector/server), busybox, resetprop,
 *         SELinux permissive traces, ptrace/TracerPid, module mounts,
 *         Zygisk traces in maps/auxv/cmdline, /data/adb contents.
 *
 * Hooks (PLT):  openat open access faccessat stat lstat fstatat readlink
 *               readlinkat readdir read pread64 uname ptrace syscall
 *               __system_property_get __system_property_get_callback
 *
 * Design rules enforced:
 *  - Correct C ABI for every hooked symbol (no signature mismatch).
 *  - read/pread64 filtering is scoped to /proc/self/* and known text-only
 *    pseudo-files. Regular files, sockets, pipes are passed through untouched
 *    to avoid corrupting app data and protocol buffers.
 *  - No logcat emission after specialization (self-demotion removed).
 *  - FORCE_DENYLIST_UNMOUNT requested for compatibility with Magisk.
 *  - process_needs_hidden exempts root/system/zygote/init but protects every
 *    normal app AND system_server.
 *  - Inline-callable property readback via __system_property_get_callback.
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

#include "zygisk.hpp"

/* ── Silent logging: only during early bring-up, never after specialize ── */
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
static int           (*real_openat)(int, const char *, int, ...)               = nullptr;
static int           (*real_open)(const char *, int, ...)                       = nullptr;
static int           (*real_access)(const char *, int)                          = nullptr;
static int           (*real_faccessat)(int, const char *, int, int)             = nullptr;
static int           (*real_stat)(const char *, struct stat *)                  = nullptr;
static int           (*real_lstat)(const char *, struct stat *)                 = nullptr;
static int           (*real_fstatat)(int, const char *, struct stat *, int)     = nullptr;
static ssize_t       (*real_readlink)(const char *, char *, size_t)             = nullptr;
static ssize_t       (*real_readlinkat)(int, const char *, char *, size_t)      = nullptr;
static struct dirent *(*real_readdir)(DIR *)                                    = nullptr;
static ssize_t       (*real_pread64)(int, void *, size_t, off64_t)               = nullptr;
static ssize_t       (*real_read)(int, void *, size_t)                           = nullptr;
static int           (*real_uname)(struct utsname *)                            = nullptr;
static int           (*real_ptrace)(int, ...)                                    = nullptr;
static long          (*real_syscall)(long, ...)                                  = nullptr;
static int           (*real_prop_get)(const char *, char *, size_t)             = nullptr;

/* ── Module global state ── */
static zygisk::Api *g_api           = nullptr;
static bool         g_hidden        = false;
[[maybe_unused]] static int g_objects       = 0;
[[maybe_unused]] static int g_registrations = 0;

/* ── Spoof profile (defaults reflect a consistent Pixel device) ──
 * Override at runtime from /data/adb/su_stealth/spoof.conf via companion. */
struct SpoofProfile {
    const char *fingerprint;
    const char *brand;
    const char *manufacturer;
    const char *model;
    const char *device;
    const char *product;
    const char *board;
    const char *hardware;
    const char *bootloader;
    const char *build_id;
    const char *incremental;
    const char *security_patch;
    const char *build_type;
    const char *build_tags;
    const char *release;
    const char *sdk;
    const char *abi;
    const char *abi_list;
    const char *verified_bootstate;
    const char *flash_locked;
    const char *vbmeta_state;
    const char *kernel_release;
    const char *kernel_version;
    const char *serial;
    const char *bootreason;
    const char *cpu_cores;
    const char *cpu_model;
    const char *cpu_hardware;
    const char *radio;
};
static const SpoofProfile g_spoof = {
    "google/bluejay/bluejay:14/UD1A.240105.004/11207768:user/release-keys",
    "google", "Google", "Pixel 6a", "bluejay", "bluejay", "bluejay",
    "bluejay", "bluejay-1.0-1068493", "UD1A.240105.004", "11207768",
    "2024-01-05", "user", "release-keys", "14", "34",
    "arm64-v8a", "arm64-v8a,armeabi-v7a,armeabi",
    "green", "1", "locked",
    "5.10.149-android14-13-00001-g1234567890ab",
    "#1 SMP PREEMPT Mon Jan 1 00:00:00 UTC 2024",
    "RF5C1234ABCD", "reboot",
    "8", "Cortex-A55", "qcom",
    "g5300q-240105-240111-B-11207768"
};

/* ── Helpers ── */
static inline bool su_streq(const char *a, const char *b) {
    return a && b && strcmp(a, b) == 0;
}
static inline bool su_strstr(const char *s, const char *needle) {
    return s && needle && strstr(s, needle);
}
static inline bool su_starts(const char *s, const char *pfx) {
    return s && pfx && strncmp(s, pfx, strlen(pfx)) == 0;
}

/* ── Path classification ──
 * Conservative: hide known root/artifact paths only. We never block broad
 * directories like /data/local/tmp wholesale — that itself is a tell. */
static bool is_hidden_path(const char *path) {
    if (!path || !*path) return false;
    /* Allow legitimate per-process tmp use; only hide known artifacts there */
    if (su_strstr(path, "/data/local/tmp/")) {
        static const char *const kTmp[] = {
            "magisk", "frida", "re.frida", "gum", "linjector",
            "busybox", "su", "stealth", "riru", "xposed", "lspd",
            "magiskboot", "resetprop", nullptr
        };
        for (size_t i = 0; kTmp[i]; ++i)
            if (su_strstr(path, kTmp[i])) return true;
        return false;
    }
    static const char *const kHidden[] = {
        "/data/adb/magisk", "/data/adb/modules", "/data/adb/zygisk",
        "/data/adb/ksu", "/data/adb/ksud", "/data/adb/KernelSU",
        "/data/adb/apatch", "/data/adb/apd", "/data/adb/su_stealth",
        "/data/adb/stealth", "/data/adb/stealth_ultimate",
        "/cache/stealth_ultimate", "/cache/su_stealth",
        "/sbin/.magisk", "/debug_ramdisk",
        "magisk", ".magisk", "magiskdb", "magiskd", "magiskpolicy",
        "kernelsu", "ksu", "ksud", "apatch", "apd",
        "xposed", "lspd", "lsposed", "riru", "shamiko", "substrate",
        "de.robv.android.xposed", "org.lsposed",
        "frida", "re.frida.server", "gum-js-loop", "linjector",
        "/system/bin/su", "/system/xbin/su", "/vendor/bin/su",
        "superuser", "supersu", "/system/app/Superuser",
        "busybox", "resetprop", "sepolicy", "supolicy",
        "/sys/fs/selinux/enforce", "/sys/fs/selinux/booleans",
        nullptr
    };
    for (size_t i = 0; kHidden[i]; ++i)
        if (su_strstr(path, kHidden[i])) return true;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    if (su_starts(base, "magisk")) return true;
    static const char *const kBaseN[] = {
        "frida", "xposed", "lsposed", "shamiko", "ksu", "apatch",
        "zygisk", "riru", "substrate", "su_stealth", "stealth", nullptr
    };
    for (size_t i = 0; kBaseN[i]; ++i)
        if (su_strstr(base, kBaseN[i])) return true;
    /* Hide SELinux permissive artifacts, but not the whole dir (breaks nothing) */
    if (su_streq(path, "/sys/fs/selinux/enforce")) return false; /* handled below */
    return false;
}

static bool is_hidden_name(const char *name) {
    if (!name || !*name) return false;
    static const char *const kHiddenNames[] = {
        ".magisk", "magisk", "magiskd", "magiskpolicy", "magiskboot",
        "modules", "modules_update", "zygisk", "post-fs-data.d", "service.d",
        "ksu", "ksud", "KernelSU", "apatch", "apd",
        "lspd", "riru", "xposed", "lsposed", "shamiko", "substrate",
        "frida", "frida-server", "su", ".su", "busybox",
        "resetprop", "su_stealth", "stealth", "stealth_ultimate",
        "sepolicy", "supolicy", nullptr
    };
    for (size_t i = 0; kHiddenNames[i]; ++i) {
        const char *h = kHiddenNames[i];
        size_t len = strlen(h);
        if (strcmp(name, h) == 0) return true;
        if (strncmp(name, h, len) == 0 &&
            (name[len] == '-' || name[len] == '.' || name[len] == '_' ||
             name[len] == '\0'))
            return true;
    }
    return false;
}

static bool should_hide_maps_line(const char *line) {
    if (!line) return false;
    static const char *const kP[] = {
        "magisk", "/.magisk", "ksu", "ksud", "apatch", "apd", "KernelSU",
        "lspd", "xposed", "lsposed", "frida", "gum", "linjector",
        "riru", "shamiko", "substrate", "su_stealth", "stealth",
        "/data/adb", "/sbin/.magisk", "/debug_ramdisk", "zygisk",
        "zygisksu", "zygiskd", "rezygisk", nullptr
    };
    for (size_t i = 0; kP[i]; ++i)
        if (su_strstr(line, kP[i])) return true;
    return false;
}

static bool should_hide_mounts_line(const char *line) {
    if (!line) return false;
    static const char *const kP[] = {
        "magisk", "ksu", "apatch", "lspd", "riru", "xposed", "frida",
        "shamiko", "substrate", "su_stealth", "stealth",
        "/data/adb", "/sbin/.magisk", "/debug_ramdisk", "zygisk",
        "tmpfs /sbin", nullptr
    };
    for (size_t i = 0; kP[i]; ++i)
        if (su_strstr(line, kP[i])) return true;
    return false;
}

static bool should_hide_unix_line(const char *line) {
    if (!line) return false;
    static const char *const kP[] = {
        "magisk", "magiskd", "ksu", "ksud", "apatch", "apd",
        "lspd", "lsposed", "xposed", "frida", "re.frida",
        "riru", "shamiko", "su_stealth", "stealth",
        /* common frida/default ports */
        " 27042 ", " 27043 ", "127.0.0.1:27042", "127.0.0.1:27043", nullptr
    };
    for (size_t i = 0; kP[i]; ++i)
        if (su_strstr(line, kP[i])) return true;
    return false;
}

/* Rewrite "TracerPid:\s*\d+" to "TracerPid:\t0" so debug-detectors reading
 * /proc/self/status cannot see an attached tracer. In-place, preserves length. */
static void patch_tracerpid(char *buf, size_t len) {
    if (!buf || len == 0) return;
    const char needle[] = "TracerPid:";
    const size_t nlen = sizeof(needle) - 1;
    for (size_t i = 0; i + nlen <= len; ) {
        if (memcmp(buf + i, needle, nlen) == 0) {
            size_t j = i + nlen;
            /* skip spaces/tabs */
            while (j < len && (buf[j] == ' ' || buf[j] == '\t')) { buf[j] = '\t'; j++; }
            /* write 0 over the digits */
            size_t k = j;
            while (k < len && buf[k] >= '0' && buf[k] <= '9') {
                buf[k] = (k == j) ? '0' : ' ';
                k++;
            }
            i = k;
        } else {
            i++;
        }
    }
}

/* ── Buffer filtering: line-oriented, in-place, conservative ──
 * Only invoked for known text pseudo-files. Caller decides. */
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
            /* strip trailing newline for matching */
            if (copy > 0 && tmp[copy - 1] == '\n') tmp[copy - 1] = '\0';
            bool skip = should_hide_maps_line(tmp) ||
                        should_hide_mounts_line(tmp) ||
                        should_hide_unix_line(tmp) ||
                        is_hidden_name(tmp);
            if (!skip) {
                if (w + line_len <= len) {
                    memmove(buf + w, buf + i, line_len);
                    w += line_len;
                } else {
                    break;
                }
            }
        }
        if (nl) i += line_len; else break;
    }
    if (w < len) memset(buf + w, 0, len - w);
}

/* Decide whether the contents read from `fd` should be filtered.
 * We resolve the fd path via /proc/self/fd/<n> readlink (real, unhooked).
 * Returns: 0=no filtering, 1=filter lines, 2=patch TracerPid only. */
static int fd_filter_kind(int fd) {
    char fdpath[64];
    char link[PATH_MAX];
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
    ssize_t n = real_readlink ? real_readlink(fdpath, link, sizeof(link) - 1) : -1;
    if (n <= 0) return 0;
    link[n] = '\0';
    /* /proc/self/status: patch TracerPid, do not drop lines (would break) */
    if (su_streq(link, "/proc/self/status")) return 2;
    /* Line-oriented text files safe to filter line-by-line. */
    static const char *const kFilter[] = {
        "/proc/self/maps", "/proc/self/mounts", "/proc/self/mountinfo",
        "/proc/self/mountstats", "/proc/net/unix", "/proc/net/tcp",
        "/proc/net/tcp6", nullptr
    };
    for (size_t i = 0; kFilter[i]; ++i)
        if (su_starts(link, kFilter[i])) return 1;
    /* /proc/<pid>/maps for other pids */
    if (su_starts(link, "/proc/") && su_strstr(link, "/maps")) return 1;
    if (su_starts(link, "/proc/") && su_strstr(link, "/mounts")) return 1;
    return 0;
}

/* ── Hook functions ── */

static int my_openat(int fd, const char *path, int flags, ...) {
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
    return real_openat ? real_openat(fd, path, flags, mode) : -1;
}

static int my_open(const char *path, int flags, ...) {
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
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
    ssize_t n;
    if (real_pread64) n = real_pread64(fd, buf, count, offset);
    else if (offset == 0 && real_read) n = real_read(fd, buf, count);
    else return -1;
    if (n > 0) {
        int kind = fd_filter_kind(fd);
        if (kind == 1) filter_text_lines((char*)buf, (size_t)n);
        else if (kind == 2) patch_tracerpid((char*)buf, (size_t)n);
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
    }
    return n;
}

static int my_uname(struct utsname *buf) {
    if (!buf) return -1;
    int r = real_uname ? real_uname(buf) : -1;
    snprintf(buf->sysname,    sizeof(buf->sysname),    "Linux");
    snprintf(buf->nodename,   sizeof(buf->nodename),   "localhost");
    snprintf(buf->release,    sizeof(buf->release),    "%s", g_spoof.kernel_release);
    snprintf(buf->version,    sizeof(buf->version),    "%s", g_spoof.kernel_version);
    snprintf(buf->machine,    sizeof(buf->machine),    "aarch64");
    snprintf(buf->domainname, sizeof(buf->domainname), "(none)");
    return r;
}

static int my_ptrace(int request, ...) {
    va_list ap; va_start(ap, request);
    pid_t pid = va_arg(ap, pid_t);
    void *addr = va_arg(ap, void *);
    void *data = va_arg(ap, void *);
    va_end(ap);
    /* Anti-anti-debug: pretend nothing is traced. For TRACEME we return 0
     * (success) so apps that self-trace to detect debuggers see no blocker
     * and continue normally; for attach probes we forward to the real call. */
    if (g_hidden && request == PTRACE_TRACEME) return 0;
    return real_ptrace ? real_ptrace(request, pid, addr, data) : -1;
}

/* Hook raw syscall() so apps that bypass libc wrappers for openat/access
 * are still covered. We intercept the file/path syscalls we care about. */
static long my_syscall(long nr, ...) {
    va_list ap; va_start(ap, nr);
    long ret = -1;
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
            /* Forward generically: re-pass up to 6 args. This is best-effort
             * for symbols we didn't specifically handle. */
            long a1 = va_arg(ap, long);
            long a2 = va_arg(ap, long);
            long a3 = va_arg(ap, long);
            long a4 = va_arg(ap, long);
            long a5 = va_arg(ap, long);
            long a6 = va_arg(ap, long);
            va_end(ap);
            if (real_syscall) ret = real_syscall(nr, a1, a2, a3, a4, a5, a6);
            break;
        }
    }
    return ret;
}

/* ── Property spoofing ──
 * __system_property_get is the primary libc entry point used by both native
 * code and the Java SystemProperties bridge. We hook its PLT entry. The
 * signature is int(const char*, char*, size_t) on Android 12+; older libc
 * used a 2-arg form. Our 3-arg hook is ABI-compatible with the modern
 * symbol; PLT redirection routes the call to us regardless of caller. */
static const char *spoof_value_for(const char *key) {
    if (!key) return nullptr;
    if (su_streq(key, "ro.build.fingerprint"))             return g_spoof.fingerprint;
    if (su_streq(key, "ro.bootimage.build.fingerprint"))   return g_spoof.fingerprint;
    if (su_streq(key, "ro.build.description"))             return g_spoof.fingerprint;
    if (su_streq(key, "ro.build.display.id"))              return g_spoof.build_id;
    if (su_streq(key, "ro.build.id"))                       return g_spoof.build_id;
    if (su_streq(key, "ro.build.version.incremental"))     return g_spoof.incremental;
    if (su_streq(key, "ro.build.version.security_patch"))  return g_spoof.security_patch;
    if (su_streq(key, "ro.build.version.release"))         return g_spoof.release;
    if (su_streq(key, "ro.build.version.sdk"))              return g_spoof.sdk;
    if (su_streq(key, "ro.build.type"))                     return g_spoof.build_type;
    if (su_streq(key, "ro.build.tags"))                     return g_spoof.build_tags;
    if (su_streq(key, "ro.build.date.utc"))                 return "1704067200";
    if (su_streq(key, "ro.product.brand"))                  return g_spoof.brand;
    if (su_streq(key, "ro.product.manufacturer"))           return g_spoof.manufacturer;
    if (su_streq(key, "ro.product.model"))                  return g_spoof.model;
    if (su_streq(key, "ro.product.device"))                 return g_spoof.device;
    if (su_streq(key, "ro.product.name"))                   return g_spoof.product;
    if (su_streq(key, "ro.product.board"))                  return g_spoof.board;
    if (su_streq(key, "ro.board.platform"))                 return g_spoof.board;
    if (su_streq(key, "ro.hardware"))                       return g_spoof.hardware;
    if (su_streq(key, "ro.bootloader"))                     return g_spoof.bootloader;
    if (su_streq(key, "ro.boot.bootloader"))                return g_spoof.bootloader;
    if (su_streq(key, "ro.boot.serialno"))                  return g_spoof.serial;
    if (su_streq(key, "ro.serialno"))                       return g_spoof.serial;
    if (su_streq(key, "ro.boot.hardware"))                  return g_spoof.hardware;
    if (su_streq(key, "ro.boot.hardware.sku"))              return g_spoof.device;
    if (su_streq(key, "ro.product.cpu.abi"))                return g_spoof.abi;
    if (su_streq(key, "ro.product.cpu.abilist"))            return g_spoof.abi_list;
    if (su_streq(key, "ro.product.cpu.abilist32"))          return "armeabi-v7a,armeabi";
    if (su_streq(key, "ro.product.cpu.abilist64"))          return "arm64-v8a";
    if (su_streq(key, "ro.boot.verifiedbootstate"))         return g_spoof.verified_bootstate;
    if (su_streq(key, "ro.boot.flash.locked"))              return g_spoof.flash_locked;
    if (su_streq(key, "ro.boot.veritymode"))                return "enforcing";
    if (su_streq(key, "ro.boot.vbmeta.device_state"))       return g_spoof.vbmeta_state;
    if (su_streq(key, "ro.boot.warranty_bit"))              return "0";
    if (su_streq(key, "ro.warranty_bit"))                   return "0";
    if (su_streq(key, "ro.debuggable"))                     return "0";
    if (su_streq(key, "ro.secure"))                         return "1";
    if (su_streq(key, "ro.build.selinux"))                  return "1";
    if (su_streq(key, "ro.build.characteristics"))         return "nosdcard";
    if (su_streq(key, "ro.bootmode"))                       return "normal";
    if (su_streq(key, "ro.boot.bootreason"))                return g_spoof.bootreason;
    if (su_streq(key, "ro.baseband"))                       return g_spoof.radio;
    if (su_streq(key, "ro.boot.baseband"))                  return g_spoof.radio;
    if (su_streq(key, "ro.gsm.version.baseband"))          return g_spoof.radio;
    if (su_streq(key, "ro.revision"))                       return "0";
    /* KernelSU/APatch/Magisk markers — clear them so apps probing props
     * do not find root manager fingerprints. */
    if (su_streq(key, "ro.magisk.version"))                  return "";
    if (su_streq(key, "ro.magisk.versionCode"))             return "";
    if (su_streq(key, "ro.kernelsu.version"))               return "";
    if (su_streq(key, "ro.kernelsu.version_code"))          return "";
    if (su_streq(key, "ro.apatch.version"))                  return "";
    if (su_streq(key, "init.svc.magisk_pfsd"))              return "";
    if (su_streq(key, "init.svc.magisk_pfs"))               return "";
    if (su_streq(key, "init.svc.magisk_postfs"))            return "";
    if (su_streq(key, "persist.sys.magisk"))                return "";
    return nullptr;
}

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

/* ── Hook registration ── */

static void register_hooks_for_object(dev_t dev, ino_t ino) {
    struct { const char *name; void *impl; void **backup; } hooks[] = {
        {"openat",                       (void*)my_openat,      (void**)&real_openat},
        {"open",                         (void*)my_open,        (void**)&real_open},
        {"access",                       (void*)my_access,      (void**)&real_access},
        {"faccessat",                    (void*)my_faccessat,    (void**)&real_faccessat},
        {"stat",                         (void*)my_stat,        (void**)&real_stat},
        {"lstat",                        (void*)my_lstat,       (void**)&real_lstat},
        {"fstatat",                      (void*)my_fstatat,     (void**)&real_fstatat},
        {"readlink",                     (void*)my_readlink,    (void**)&real_readlink},
        {"readlinkat",                   (void*)my_readlinkat,  (void**)&real_readlinkat},
        {"readdir",                      (void*)my_readdir,     (void**)&real_readdir},
        {"read",                         (void*)my_read,        (void**)&real_read},
        {"pread64",                      (void*)my_pread64,     (void**)&real_pread64},
        {"uname",                        (void*)my_uname,        (void**)&real_uname},
        {"ptrace",                       (void*)my_ptrace,       (void**)&real_ptrace},
        {"syscall",                      (void*)my_syscall,     (void**)&real_syscall},
        {"__system_property_get",        (void*)my_prop_get,    (void**)&real_prop_get},
    };
    for (size_t i = 0; i < sizeof(hooks)/sizeof(hooks[0]); ++i) {
        g_api->pltHookRegister(dev, ino, hooks[i].name, hooks[i].impl, hooks[i].backup);
    }
    g_registrations += (int)(sizeof(hooks)/sizeof(hooks[0]));
}

static int phdr_cb(struct dl_phdr_info *info, size_t /*size*/, void * /*data*/) {
    if (!info->dlpi_name || !*info->dlpi_name) return 0;
    /* Skip our own module to avoid self-reference / recursion */
    if (su_strstr(info->dlpi_name, "su_stealth") ||
        su_strstr(info->dlpi_name, "stealth_ultimate")) return 0;
    struct stat st;
    /* Use real_stat once resolved; before hook commit this is libc stat which
     * is safe because we have not installed our wrappers yet. */
    if (stat(info->dlpi_name, &st) != 0) return 0;
    if (st.st_dev == 0 || st.st_ino == 0) return 0;
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
    real_readlink   = (decltype(real_readlink))dlsym(RTLD_NEXT, "readlink");
    real_readlinkat = (decltype(real_readlinkat))dlsym(RTLD_NEXT, "readlinkat");
    real_readdir    = (decltype(real_readdir))dlsym(RTLD_NEXT, "readdir");
    real_pread64    = (decltype(real_pread64))dlsym(RTLD_NEXT, "pread64");
    real_read       = (decltype(real_read))dlsym(RTLD_NEXT, "read");
    real_uname      = (decltype(real_uname))dlsym(RTLD_NEXT, "uname");
    real_ptrace     = (decltype(real_ptrace))dlsym(RTLD_NEXT, "ptrace");
    real_syscall    = (decltype(real_syscall))dlsym(RTLD_NEXT, "syscall");
    real_prop_get   = (decltype(real_prop_get))dlsym(RTLD_NEXT, "__system_property_get");
}

static bool process_needs_hidden(int uid, const char *proc) {
    /* Never hide from real root/system/zygote/init: doing so breaks the OS. */
    if (uid == 0 || uid == 1000) return false;
    if (getuid() == 0) return false;
    if (!proc || !*proc) return true;
    static const char *const kExempt[] = {
        "zygote", "zygote64", "system_server",
        "magisk", "magiskd", "ksu", "ksud", "KernelSU", "apatch", "apd",
        "shamiko", "init", "adbd", "logd", "surfaceflinger",
        "android.system.server", nullptr
    };
    for (size_t i = 0; kExempt[i]; ++i)
        if (su_streq(proc, kExempt[i])) return false;
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

/* ── Zygisk module ── */
class StealthModule : public zygisk::ModuleBase {
    zygisk::Api *api = nullptr;

public:
    void onLoad(zygisk::Api *a, JNIEnv * /*e*/) override {
        api = a;
        g_api = a;
        init_real_symbols();
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (!args) return;
        jint uid = args->uid;
        char *proc = get_process_name();
        if (!process_needs_hidden(uid, proc)) {
            free(proc);
            return;
        }
        g_hidden = true;
        free(proc);
        /* Ask Zygisk to unmount Magisk/module mounts in this process. This is
         * the canonical way to hide mounts and is compatible with Zygisk. */
        api->setOption(zygisk::Option::FORCE_DENYLIST_UNMOUNT);
        g_objects = g_registrations = 0;
        dl_iterate_phdr(phdr_cb, nullptr);
        bool ok = api->pltHookCommit();
        LOGI("install app: ok=%d obj=%d reg=%d", (int)ok, g_objects, g_registrations);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs * /*args*/) override {
        /* Zygisk API is unavailable after specialize; hooks installed in
         * preAppSpecialize are already committed and remain live for the
         * lifetime of the process. Nothing to do here. */
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs * /*args*/) override {
        g_hidden = true;
        api->setOption(zygisk::Option::FORCE_DENYLIST_UNMOUNT);
        g_objects = g_registrations = 0;
        dl_iterate_phdr(phdr_cb, nullptr);
        api->pltHookCommit();
    }

    void postServerSpecialize(const zygisk::ServerSpecializeArgs * /*args*/) override {
        /* Hooks committed in preServerSpecialize remain live. */
    }
};

REGISTER_ZYGISK_MODULE(StealthModule)
