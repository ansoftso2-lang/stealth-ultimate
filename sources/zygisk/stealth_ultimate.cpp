/* SPDX-License-Identifier: MIT */
/*
 * stealth_ultimate.cpp — Zygisk Anti-Detection Module (v2.2-rewrite)
 *
 *  Hides:  root, Magisk, KernelSU, APatch, Zygisk, LSPosed, Frida,
 *          Xposed, Riru, Shamiko, busybox, SELinux traces
 *  Spoofs: device props, kernel, /proc fields
 *  Hooks:  openat/open/access/faccessat/stat/lstat/fstatat/fstat/
 *          readlink/readlinkat/readdir/read/pread64/uname/
 *          __system_property_get/ptrace
 *
 *  Rewrite goals:
 *   - Use the OFFICIAL public zygisk.hpp (no hand-rolled ABI table).
 *   - Install ALL PLT hooks in preAppSpecialize, commit ONCE, verify+log result.
 *   - Register only real loaded ELF objects (real dev/inode), never (0,0).
 *   - Log through logd (always writable) so diagnostics cannot vanish.
 */
#define _GNU_SOURCE
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/system_properties.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <link.h>
#include <elf.h>
#include <android/log.h>

#include "zygisk.hpp"

#define LOG_TAG "stealth_ultimate"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

/* ── Real function pointers ── */
static int           (*real_openat)(int, const char *, int, ...)               = nullptr;
static int           (*real_open)(const char *, int, ...)                       = nullptr;
static int           (*real_access)(const char *, int)                          = nullptr;
static int           (*real_faccessat)(int, const char *, int)                  = nullptr;
static int           (*real_stat)(const char *, struct stat *)                  = nullptr;
static int           (*real_lstat)(const char *, struct stat *)                 = nullptr;
static int           (*real_fstatat)(int, const char *, struct stat *, int)      = nullptr;
static ssize_t       (*real_readlink)(const char *, char *, size_t)              = nullptr;
static ssize_t       (*real_readlinkat)(int, const char *, char *, size_t)       = nullptr;
static struct dirent *(*real_readdir)(DIR *)                                     = nullptr;
static ssize_t       (*real_read)(int, void *, size_t)                           = nullptr;
static ssize_t       (*real_pread64)(int, void *, size_t, off64_t)               = nullptr;
static int           (*real_uname)(struct utsname *)                             = nullptr;
static int           (*real_ptrace)(int, ...)                                    = nullptr;
static const char   *(*real_prop_get)(const char *)                              = nullptr;

/* ── Module global state ── */
static zygisk::Api *g_api              = nullptr;
static bool         g_hidden            = false;
static int          g_in_hook           = 0;
static int          g_objects           = 0;
static int          g_registrations     = 0;

/* ── Path / name classification ── */
static bool is_hidden_path(const char *path) {
    if (!path) return false;
    static const char *const kHidden[] = {
        "magisk", ".magisk", "/data/adb/magisk", "/data/adb/modules",
        "/data/adb/zygisk", "magiskdb", "magiskd", "magiskpolicy",
        "ksu", "ksud", "/data/adb/ksu", "kernelsu",
        "apatch", "apd", "/data/adb/apatch",
        "xposed", "lspd", "riru", "shamiko", "substrate",
        "lsposed", "org.lsposed", "de.robv.android.xposed",
        "frida", "re.frida.server", "gum-js-loop", "linjector",
        "su", ".su", "superuser", "supersu", "busybox",
        "resetprop", "sepolicy", "supolicy",
        "/sys/fs/selinux", "/proc/1/attr/current", "selinux",
        "/data/local/tmp", "/data/adb/stealth", "/data/adb/stealth_ultimate",
        "/cache/stealth_ultimate", nullptr
    };
    for (size_t i = 0; kHidden[i]; ++i)
        if (strstr(path, kHidden[i])) return true;

    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    if (strncmp(base, "magisk", 6) == 0) return true;
    if (strstr(base, "frida") || strstr(base, "xposed") ||
        strstr(base, "lsposed") || strstr(base, "shamiko") ||
        strstr(base, "ksu") || strstr(base, "apatch") ||
        strstr(base, "zygisk") || strstr(base, "riru") ||
        strstr(base, "substrate") || strstr(base, "stealth")) return true;
    return false;
}

static bool is_hidden_name(const char *name) {
    if (!name || !*name) return false;
    static const char *const kHiddenNames[] = {
        ".magisk", "magisk", "magiskd", "modules", "modules_update",
        "zygisk", "post-fs-data.d", "service.d",
        "ksu", "ksud", "apatch", "apd", "lspd", "riru",
        "xposed", "lsposed", "shamiko", "substrate",
        "frida", "frida-server", "su", ".su", "busybox",
        "resetprop", "stealth_ultimate", "magiskpolicy", "sepolicy", "supolicy",
        nullptr
    };
    for (size_t i = 0; kHiddenNames[i]; ++i) {
        size_t len = strlen(kHiddenNames[i]);
        if (strcmp(name, kHiddenNames[i]) == 0) return true;
        if (strncmp(name, kHiddenNames[i], len) == 0 &&
            (name[len] == '-' || name[len] == '.' || name[len] == '\0'))
            return true;
    }
    return false;
}

/* Hide /proc/self/maps & smaps lines containing root framework traces */
static bool should_hide_maps_line(const char *line) {
    if (!line) return false;
    static const char *const kPatterns[] = {
        "magisk", "ksu", "ksud", "apatch", "apd",
        "lspd", "xposed", "lsposed", "frida", "gum",
        "riru", "shamiko", "substrate", "stealth",
        "/data/adb", "/data/local/tmp",
        "27042", "27043", nullptr
    };
    for (size_t i = 0; kPatterns[i]; ++i)
        if (strstr(line, kPatterns[i])) return true;
    return false;
}

static bool should_hide_mounts_line(const char *line) {
    if (!line) return false;
    static const char *const kPatterns[] = {
        "magisk", "ksu", "apatch", "lspd", "riru", "xposed",
        "frida", "shamiko", "substrate", "stealth",
        "/data/adb", "/sbin/.magisk", "/debug_ramdisk",
        "/data/local/tmp", nullptr
    };
    for (size_t i = 0; kPatterns[i]; ++i)
        if (strstr(line, kPatterns[i])) return true;
    return false;
}

static bool should_hide_unix_line(const char *line) {
    return should_hide_maps_line(line);
}

/* ── Property spoofing ── */
static const char *get_spoof(const char *key) {
    if (!key) return nullptr;
    if (strcmp(key, "ro.build.fingerprint") == 0)
        return "google/sailfish/sailfish:14/UP1A.240205.002-B9-11876770:user/release-keys";
    if (strcmp(key, "ro.product.brand") == 0)        return "google";
    if (strcmp(key, "ro.product.manufacturer") == 0) return "Google";
    if (strcmp(key, "ro.product.model") == 0)       return "Pixel 8";
    if (strcmp(key, "ro.product.device") == 0)      return "shibuya";
    if (strcmp(key, "ro.product.name") == 0)        return "shibuya";
    if (strcmp(key, "ro.product.board") == 0)       return "shibuya";
    if (strcmp(key, "ro.build.type") == 0)          return "user";
    if (strcmp(key, "ro.build.tags") == 0)          return "release-keys";
    if (strcmp(key, "ro.debuggable") == 0)          return "0";
    if (strcmp(key, "ro.secure") == 0)              return "1";
    if (strcmp(key, "ro.boot.flash.locked") == 0)  return "1";
    if (strcmp(key, "ro.boot.verifiedbootstate") == 0) return "green";
    if (strcmp(key, "ro.boot.veritymode") == 0)     return "enforcing";
    return nullptr;
}

/* ── Buffer filtering helpers ── */
static void filter_buffer(char *buf, size_t len) {
    if (!buf || len == 0) return;
    size_t w = 0;
    for (size_t i = 0; i < len; ) {
        char *nl = (char*)memchr(buf + i, '\n', len - i);
        size_t line_len = nl ? (size_t)(nl - (buf + i) + 1) : (len - i);
        if (line_len > 0) {
            char namebuf[256];
            size_t copy = line_len < sizeof(namebuf) ? line_len : sizeof(namebuf) - 1;
            memcpy(namebuf, buf + i, copy);
            namebuf[copy] = '\0';
            bool skip = should_hide_maps_line(namebuf) ||
                        should_hide_mounts_line(namebuf) ||
                        should_hide_unix_line(namebuf) ||
                        is_hidden_name(namebuf);
            if (!skip && w + line_len <= len) {
                memmove(buf + w, buf + i, line_len);
                w += line_len;
            }
        }
        if (nl) i += line_len; else break;
    }
    if (len - w > 0 && len - w <= (size_t)1024)
        memset(buf + w, 0, len - w);
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
static int my_faccessat(int dirfd, const char *path, int mode) {
    if (is_hidden_path(path)) { errno = ENOENT; return -1; }
    return real_faccessat ? real_faccessat(dirfd, path, mode) : -1;
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
    ssize_t n = real_pread64 ? real_pread64(fd, buf, count, offset) :
                 (real_read && offset == 0 ? real_read(fd, buf, count) : -1);
    if (n <= 0) return n;
    filter_buffer((char*)buf, (size_t)n);
    return n;
}
static ssize_t my_read(int fd, void *buf, size_t count) {
    return my_pread64(fd, buf, count, 0);
}

static int my_uname(struct utsname *buf) {
    if (!buf) return -1;
    int r = real_uname ? real_uname(buf) : -1;
    snprintf(buf->sysname,    sizeof(buf->sysname),    "Linux");
    snprintf(buf->nodename,   sizeof(buf->nodename),   "localhost");
    snprintf(buf->release,    sizeof(buf->release),    "5.15.157-android13-2");
    snprintf(buf->version,   sizeof(buf->version),   "#1 SMP PREEMPT");
    snprintf(buf->machine,   sizeof(buf->machine),   "aarch64");
    snprintf(buf->domainname, sizeof(buf->domainname), "(none)");
    return r;
}

static int my_ptrace(int request, ...) {
    if (g_hidden && request == PTRACE_TRACEME) { errno = ESRCH; return -1; }
    va_list ap; va_start(ap, request);
    pid_t pid = va_arg(ap, pid_t);
    void *addr = va_arg(ap, void *);
    void *data = va_arg(ap, void *);
    va_end(ap);
    return real_ptrace ? real_ptrace(request, pid, addr, data) : -1;
}

static const char *my_prop_get(const char *key) {
    const char *spoof = get_spoof(key);
    if (spoof) return spoof;
    return real_prop_get ? real_prop_get(key) : "";
}

/* ── Hook registration ── */
static void register_hooks_for_object(dev_t dev, ino_t ino) {
    struct { const char *name; void *impl; void **backup; } hooks[] = {
        {"openat",      (void*)my_openat,      (void**)&real_openat},
        {"open",        (void*)my_open,        (void**)&real_open},
        {"access",      (void*)my_access,      (void**)&real_access},
        {"faccessat",   (void*)my_faccessat,   (void**)&real_faccessat},
        {"stat",        (void*)my_stat,        (void**)&real_stat},
        {"lstat",       (void*)my_lstat,       (void**)&real_lstat},
        {"fstatat",     (void*)my_fstatat,     (void**)&real_fstatat},
        {"readlink",    (void*)my_readlink,    (void**)&real_readlink},
        {"readlinkat",  (void*)my_readlinkat,  (void**)&real_readlinkat},
        {"readdir",     (void*)my_readdir,     (void**)&real_readdir},
        {"read",        (void*)my_read,        (void**)&real_read},
        {"pread64",     (void*)my_pread64,     (void**)&real_pread64},
        {"uname",       (void*)my_uname,       (void**)&real_uname},
        {"ptrace",      (void*)my_ptrace,      (void**)&real_ptrace},
        {"__system_property_get", (void*)my_prop_get, (void**)&real_prop_get},
    };
    for (size_t i = 0; i < sizeof(hooks)/sizeof(hooks[0]); ++i) {
        g_api->pltHookRegister(dev, ino, hooks[i].name, hooks[i].impl, hooks[i].backup);
    }
    g_registrations += (int)(sizeof(hooks)/sizeof(hooks[0]));
    LOGD("register: dev=%ld ino=%ld total=%d", (long)dev, (long)ino, g_registrations);
}

static int phdr_cb(struct dl_phdr_info *info, size_t /*size*/, void * /*data*/) {
    if (!info->dlpi_name || !*info->dlpi_name) return 0;
    if (strstr(info->dlpi_name, "stealth_ultimate")) return 0;

    struct stat st;
    if (stat(info->dlpi_name, &st) != 0) return 0;
    if (st.st_dev == 0 || st.st_ino == 0) return 0;

    register_hooks_for_object(st.st_dev, st.st_ino);
    g_objects++;
    return 0;
}

static void install_hooks(void) {
    dl_iterate_phdr(phdr_cb, nullptr);
    bool ok = g_api->pltHookCommit();
    LOGI("install: commit=%d objects=%d registrations=%d", ok ? 1 : 0, g_objects, g_registrations);
    if (!ok) LOGE("install: pltHookCommit FAILED");
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
    real_read       = (decltype(real_read))dlsym(RTLD_NEXT, "read");
    real_pread64    = (decltype(real_pread64))dlsym(RTLD_NEXT, "pread64");
    real_uname      = (decltype(real_uname))dlsym(RTLD_NEXT, "uname");
    real_ptrace     = (decltype(real_ptrace))dlsym(RTLD_NEXT, "ptrace");
    real_prop_get   = (decltype(real_prop_get))dlsym(RTLD_NEXT, "__system_property_get");
    LOGI("init_real_symbols done");
}

static bool process_needs_hidden(int uid, const char *proc) {
    if (uid == 0 || uid == 1000 || getuid() == 0) return false;
    if (!proc || !*proc) return false;
    static const char *const kExempt[] = {
        "zygote", "zygote64", "system_server", "magisk", "magiskd",
        "ksu", "ksud", "apatch", "shamiko", "init", "adbd", nullptr
    };
    for (size_t i = 0; kExempt[i]; ++i)
        if (strcmp(proc, kExempt[i]) == 0) return false;
    return true;
}

static char *resolve_nice_name(const zygisk::AppSpecializeArgs *args) {
    JNIEnv *env = nullptr;
    char *proc = nullptr;
    if (args && args->nice_name) {
        /* Try to get a JNIEnv; in practice one is passed by the Zygisk framework in onLoad */
        /* The entry point receives JNIEnv in onLoad; reuse via global not available here. */
        env = nullptr; /* best-effort: rely on cmdline below */
    }
    FILE *f = fopen("/proc/self/cmdline", "rb");
    if (f) {
        proc = (char*)calloc(256, 1);
        if (proc) {
            size_t i = 0, c;
            while ((c = fgetc(f)) != EOF && c != '\0' && i < 255)
                proc[i++] = (char)c;
            if (strstr(proc, "stealth_ultimate")) proc[0] = '\0';
            if (!*proc) { free(proc); proc = nullptr; }
        }
        fclose(f);
    }
    if (!proc) {
        proc = (char*)calloc(16, 1);
        if (proc) snprintf(proc, 16, "unknown");
    }
    return proc;
}

/* ── Zygisk module ── */
class StealthModule : public zygisk::ModuleBase {
    zygisk::Api *api = nullptr;
    JNIEnv      *env  = nullptr;

public:
    void onLoad(zygisk::Api *a, JNIEnv *e) override {
        api = a;
        env = e;
        g_api = a;
        LOGI("=== MODULE ENTRY START ===");
        LOGI("onLoad: api=%p", (void*)api);
        init_real_symbols();
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (!args) return;
        jint uid = args->uid;

        char *proc = resolve_nice_name(args);
        LOGI("preAppSpecialize: uid=%d proc=%s", uid, proc ? proc : "(null)");

        if (!process_needs_hidden(uid, proc)) {
            LOGI("preAppSpecialize: target exempt (uid=%d)", uid);
            free(proc);
            return;
        }

        g_hidden = true;
        free(proc);

        LOGI("preAppSpecialize: HIDDEN=1 installing hooks for uid=%d", uid);
        install_hooks();
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override {
        LOGI("postAppSpecialize: hidden=%d", g_hidden ? 1 : 0);
    }
};

REGISTER_ZYGISK_MODULE(StealthModule)
