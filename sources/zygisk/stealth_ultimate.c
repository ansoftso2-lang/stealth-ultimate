/*
 * stealth_ultimate.c v1.0
 *
 * Zygisk Anti-Detection Module
 * - Hides: root, Magisk, KSU, APatch, Zygisk, LSPosed, Frida, Xposed, Riru, Shamiko, busybox, SELinux
 * - Spoofs: device props, kernel, CPU, mounts, maps, environ, net/unix, SELinux context
 * - Hooks: open, openat, access, stat, lstat, fstatat, readlink, readlinkat, readdir,
 *          read, pread64, close, fopen, fopen64, fclose, fread, fgets, getline,
 *          __system_property_get/find/read_callback, uname, ptrace, prctl, syscall,
 *          getauxval, fstat, stat64, lstat64
 * - Auto-exempts: apps with root access (from Magisk/KSU/APatch DB), system apps
 * - Play Integrity: verified boot, vbmeta, debuggable, secure, build type/tags
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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
#include <sys/auxv.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <link.h>
#include <elf.h>
#include <sys/mman.h>

#define LOG_PATH "/data/adb/stealth_ultimate/stealth.log"
#define LOG_BUF_SIZE 1024
static int g_logging = 0;

static void log_write(const char *fmt, ...) {
    if (g_logging) return;
    g_logging = 1;
    char buf[LOG_BUF_SIZE];
    int fd = openat(AT_FDCWD, LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) { g_logging = 0; return; }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) write(fd, buf, n);
    write(fd, "\n", 1);
    close(fd);
    g_logging = 0;
}

#define LOGI(...) log_write("[I] " __VA_ARGS__)
#define LOGE(...) log_write("[E] " __VA_ARGS__)
#define LOGD(...) log_write("[D] " __VA_ARGS__)

extern long ptrace(int __request, ...);

#ifndef AT_SECURE
#define AT_SECURE 23
#endif
#ifndef AT_EXECFN
#define AT_EXECFN 31
#endif
#ifndef AT_ENTRY
#define AT_ENTRY 9
#endif

/* Syscall fallbacks */
#ifndef SYS_openat
#ifdef __NR_openat
#define SYS_openat __NR_openat
#endif
#endif
#ifndef SYS_open
#ifdef __NR_open
#define SYS_open __NR_open
#endif
#endif
#ifndef SYS_access
#ifdef __NR_access
#define SYS_access __NR_access
#endif
#endif
#ifndef SYS_faccessat
#ifdef __NR_faccessat
#define SYS_faccessat __NR_faccessat
#endif
#endif
#ifndef SYS_faccessat2
#ifdef __NR_faccessat2
#define SYS_faccessat2 __NR_faccessat2
#endif
#endif
#ifndef SYS_stat
#ifdef __NR_stat
#define SYS_stat __NR_stat
#endif
#endif
#ifndef SYS_lstat
#ifdef __NR_lstat
#define SYS_lstat __NR_lstat
#endif
#endif
#ifndef SYS_fstatat
#ifdef __NR_fstatat
#define SYS_fstatat __NR_fstatat
#endif
#endif
#ifndef SYS_newfstatat
#ifdef __NR_newfstatat
#define SYS_newfstatat __NR_newfstatat
#endif
#endif
#ifndef SYS_readlink
#ifdef __NR_readlink
#define SYS_readlink __NR_readlink
#endif
#endif
#ifndef SYS_readlinkat
#ifdef __NR_readlinkat
#define SYS_readlinkat __NR_readlinkat
#endif
#endif
#ifndef SYS_read
#ifdef __NR_read
#define SYS_read __NR_read
#endif
#endif
#ifndef SYS_close
#ifdef __NR_close
#define SYS_close __NR_close
#endif
#endif
#ifndef SYS_pread64
#ifdef __NR_pread64
#define SYS_pread64 __NR_pread64
#endif
#endif
#ifndef SYS_fstat
#ifdef __NR_fstat
#define SYS_fstat __NR_fstat
#endif
#endif

#define ZYGISK_API_VERSION 4

struct zygisk_module_abi {
    long api_version;
    void *impl;
    void (*preAppSpecialize)(void *, void *);
    void (*postAppSpecialize)(void *, const void *);
    void (*preServerSpecialize)(void *, void *);
    void (*postServerSpecialize)(void *, const void *);
};

struct zygisk_api_table {
    void *impl;
    int (*registerModule)(struct zygisk_api_table *, struct zygisk_module_abi *);
    void (*hookJniNativeMethods)(void *, const char *, void *, int);
    void (*pltHookRegister)(long, long, const char *, void *, void **);
    int (*exemptFd)(int);
    int (*pltHookCommit)(void);
    int (*connectCompanion)(void *);
    void (*setOption)(void *, int);
    int (*getModuleDir)(void *);
    unsigned int (*getFlags)(void *);
};

static struct zygisk_api_table *g_api = NULL;
static unsigned int g_zygisk_flags = 0;
#define ZYGISK_PROCESS_GRANTED_ROOT 1u
#define ZYGISK_PROCESS_ON_DENYLIST 2u

static __thread int g_in_hook = 0;
static int g_in_init = 0;

static int g_hidden = 0;
static char g_proc[256] = {0};
static int g_uid = -1;

/* Config (all enabled by default) */
static int cfg_spoof = 1;
static int cfg_spoof_kernel = 1;
static int cfg_spoof_cpu = 1;
static int cfg_block_ptrace = 1;
static int cfg_hide_maps = 1;
static int cfg_hide_environ = 1;
static int cfg_hide_status = 1;
static int cfg_hide_mounts = 1;
static int cfg_spoof_selinux_file = 1;
static int cfg_spoof_auxval = 1;
static int cfg_spoof_cpu_cores = 8;
static char cfg_spoof_cpu_model[64] = "Cortex-A55";
static char cfg_spoof_cpu_hardware[64] = "qcom";
static char cfg_custom_targets[8192] = {0};

/* Spoofed values (Pixel 6a default) */
static char s_fp[512] = "google/bluejay/bluejay:14/UD1A.240105.004/11207768:user/release-keys";
static char s_model[64] = "Pixel 6a";
static char s_brand[64] = "google";
static char s_mfr[64] = "Google";
static char s_device[64] = "bluejay";
static char s_product[64] = "bluejay";
static char s_board[64] = "bluejay";
static char s_hw[64] = "bluejay";
static char s_buildid[64] = "UD1A.240105.004";
static char s_incr[64] = "11207768";
static char s_secpatch[64] = "2024-01-05";
static char s_bootloader[128] = "bluejay-1.0-1068493";
static char s_tags[32] = "release-keys";
static char s_type[32] = "user";
static char s_release[16] = "14";
static char s_sdk[16] = "34";
static char s_vbstate[32] = "green";
static char s_flashlock[16] = "1";
static char s_vbmeta[32] = "locked";
static char s_kernel_rel[128] = "5.10.149-android14-13-00001-g1234567890ab";
static char s_kernel_ver[256] = "#1 SMP PREEMPT Mon Jan 1 00:00:00 UTC 2024";
static char s_debuggable[8] = "0";
static char s_secure[8] = "1";
static char s_radio[64] = "g5300q-240105-240111-B-11207768";
static char s_abi[32] = "arm64-v8a";
static char s_abilist[128] = "arm64-v8a,armeabi-v7a,armeabi";
static char s_locale[32] = "en-US";
static char s_timezone[64] = "Europe/Moscow";
static char s_opengles[16] = "196609";
static char s_serial[32] = "RF5C1234ABCD";
static char s_veritymode[32] = "enforcing";
static char s_warranty[8] = "0";
static char s_keymaster[8] = "1";
static char s_vbmeta_hash[16] = "sha256";
static char s_vbmeta_size[16] = "8192";
static char s_vbmeta_digest[128] = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
static char s_bootreason[32] = "reboot";
static char s_thermal[16] = "0";
static char s_opp_unlock[16] = "0";
static char s_hw_power_save[16] = "1";
static char s_hw_deep_sleep[16] = "1";
static char s_nocheckin[16] = "1";
static char s_lcd_density[16] = "320";
static char s_sf_hw[16] = "qcom";
static char s_display_id[64] = "UD1A.240105.004";
static char s_characteristics[32] = "default";
static char s_abilist32[64] = "";
static char s_changelist[16] = "11207768";

/* System whitelist */
static const char *WHITELIST[] = {
    "android","com.android.systemui","com.android.phone","com.android.settings",
    "com.android.providers.media","com.android.providers.contacts",
    "com.android.providers.calendar","com.android.providers.settings",
    "com.android.providers.telephony","com.android.providers.downloads",
    "com.android.inputmethod","com.google.android.inputmethod",
    "com.google.android.permissioncontroller","com.android.permissioncontroller",
    "com.android.shell","com.android.webview","com.android.networkstack",
    "com.android.nfc","com.android.bluetooth","com.android.wifi",
    "com.android.networkstack.tethering","com.android.captiveportallogin",
    "com.android.se","com.android.ims.rcsservice","com.android.wallpaperbackup",
    "com.android.backupconfirm","com.android.sharedstoragebackup",
    "com.android.printspooler","com.android.dreams.basic",
    "com.android.keychain","com.android.certinstaller",
    "com.android.externalstorage","com.android.defcontainer",
    "com.android.proxyhandler","com.android.vpndialogs",
    "com.android.pacprocessor","com.android.statementservice",
    "com.android.managedprovisioning","com.android.emergency",
    "system_server","zygote","zygote64","surfaceflinger","app_process",
    "installd","servicemanager","lmkd","healthd","logd","vold","netd",
    "keystore","gatekeeperd","fingerprintd","sensorservice","audioserver",
    "cameraserver","mediacodec","mediadrm","mediaextractor","mediaserver",
    "drmserver","com.android.providers.media.module",
    "com.android.providers.contacts.module","com.android.providers.calendar.module",
    "com.android.providers.telephony.module","com.android.providers.downloads.module",
    "com.google.android.webview","com.google.android.ext.shared",
    "com.google.android.gsf.login","com.android.modulemetadata",
    "com.android.provision","com.android.dynsystem",
    "com.android.cellbroadcastreceiver","com.android.cellbroadcastservice",
    "com.android.bips","com.android.bookmarkservice","com.android.calllogbackup",
    "com.android.carrierdefaultapp","com.android.companiondevicemanager",
    "com.android.cts.ctsshim","com.android.dnsresolver",
    "com.android.hotspot2.osuloginservice","com.android.ims.rcsmanager",
    "com.android.localtransport","com.android.mtp","com.android.nfc.emulator",
    "com.android.ondevicepersonalization","com.android.permissionmanager",
    "com.android.quicksearchbox","com.android.remoteconfig","com.android.rkpdapp",
    "com.android.safetycenter","com.android.sandbox","com.android.server.telecom",
    "com.android.simappdialog","com.android.traceur","com.android.uwb",
    "com.android.hotword","com.android.egg","com.android.secdevicereset",
    "com.android.vndk.secamu","com.android.art",
    NULL
};

/* Root UID list */
#define MAX_ROOT_UIDS 256
static int g_root_uids[MAX_ROOT_UIDS];
static int g_root_uid_count = 0;

/* Property types */
struct prop_info;
typedef struct prop_info prop_info;

#define MAX_SPOOF_PROPS 128
struct SpoofPropEntry { const prop_info *pi; char name[128]; };
static struct SpoofPropEntry g_spoof_props[MAX_SPOOF_PROPS];
static int g_spoof_prop_count = 0;
static pthread_mutex_t g_prop_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint8_t g_dummy_pi_buf[64];
#define G_DUMMY_PI ((const prop_info *)g_dummy_pi_buf)

struct prop_cb_wrapper_data {
    void (*user_cb)(void *cookie, const char *name, const char *value, uint32_t serial);
    void *user_cookie;
    const char *prop_name;
};

/* Real function pointers */
static int (*real_openat)(int, const char *, int, ...) = NULL;
static int (*real_open)(const char *, int, ...) = NULL;
static int (*real_access)(const char *, int) = NULL;
static int (*real_faccessat)(int, const char *, int, int) = NULL;
static int (*real_stat)(const char *, struct stat *) = NULL;
static int (*real_lstat)(const char *, struct stat *) = NULL;
static int (*real_fstatat)(int, const char *, struct stat *, int) = NULL;
static int (*real_fstat)(int, struct stat *) = NULL;
static ssize_t (*real_readlink)(const char *, char *, size_t) = NULL;
static ssize_t (*real_readlinkat)(int, const char *, char *, size_t) = NULL;
static struct dirent *(*real_readdir)(DIR *) = NULL;
static ssize_t (*real_read)(int, void *, size_t) = NULL;
static int (*real_close)(int) = NULL;
static int (*real_prop_get)(const char *, char *) = NULL;
static const prop_info *(*real_prop_find)(const char *) = NULL;
static void (*real_prop_read_cb)(const prop_info *, void (*)(void *, const char *, const char *, uint32_t), void *) = NULL;
static int (*real_uname)(struct utsname *) = NULL;
static long (*real_ptrace)(int, pid_t, void *, void *) = NULL;
static int (*real_prctl)(int, ...) = NULL;
static FILE *(*real_fopen)(const char *, const char *) = NULL;
static FILE *(*real_fopen64)(const char *, const char *) = NULL;
static int (*real_fclose)(FILE *) = NULL;
static size_t (*real_fread)(void *, size_t, size_t, FILE *) = NULL;
static char *(*real_fgets)(char *, int, FILE *) = NULL;
static ssize_t (*real_getline)(char **, size_t *, FILE *) = NULL;
static long (*real_syscall)(long, ...) = NULL;
static ssize_t (*real_pread64)(int, void *, size_t, off64_t) = NULL;
static unsigned long (*real_getauxval)(unsigned long) = NULL;

static void init_reals(void) {
    if (g_in_init) return;
    g_in_init = 1;
    int failed = 0;
    real_openat = dlsym(RTLD_NEXT, "openat");
    real_open = dlsym(RTLD_NEXT, "open");
    real_access = dlsym(RTLD_NEXT, "access");
    real_faccessat = dlsym(RTLD_NEXT, "faccessat");
    real_stat = dlsym(RTLD_NEXT, "stat");
    real_lstat = dlsym(RTLD_NEXT, "lstat");
    real_fstatat = dlsym(RTLD_NEXT, "fstatat");
    real_fstat = dlsym(RTLD_NEXT, "fstat");
    real_readlink = dlsym(RTLD_NEXT, "readlink");
    real_readlinkat = dlsym(RTLD_NEXT, "readlinkat");
    real_readdir = dlsym(RTLD_NEXT, "readdir");
    real_read = dlsym(RTLD_NEXT, "read");
    real_close = dlsym(RTLD_NEXT, "close");
    real_prop_get = dlsym(RTLD_NEXT, "__system_property_get");
    real_prop_find = dlsym(RTLD_NEXT, "__system_property_find");
    real_prop_read_cb = dlsym(RTLD_NEXT, "__system_property_read_callback");
    real_uname = dlsym(RTLD_NEXT, "uname");
    real_ptrace = dlsym(RTLD_NEXT, "ptrace");
    real_prctl = dlsym(RTLD_NEXT, "prctl");
    real_fopen = dlsym(RTLD_NEXT, "fopen");
    real_fopen64 = dlsym(RTLD_NEXT, "fopen64");
    real_fclose = dlsym(RTLD_NEXT, "fclose");
    real_fread = dlsym(RTLD_NEXT, "fread");
    real_fgets = dlsym(RTLD_NEXT, "fgets");
    real_getline = dlsym(RTLD_NEXT, "getline");
    real_syscall = dlsym(RTLD_NEXT, "syscall");
    real_pread64 = dlsym(RTLD_NEXT, "pread64");
    real_getauxval = dlsym(RTLD_NEXT, "getauxval");
    if (!real_openat) { failed++; LOGE("init_reals: openat=NULL"); }
    if (!real_open) { failed++; LOGE("init_reals: open=NULL"); }
    if (!real_read) { failed++; LOGE("init_reals: read=NULL"); }
    if (!real_prop_get) { failed++; LOGE("init_reals: prop_get=NULL"); }
    LOGI("init_reals: total_failed=%d", failed);
    g_in_init = 0;
}

/* FD Tracking */
#define MAX_FDS 256

enum ProcFdType {
    FD_TYPE_NONE = 0, FD_TYPE_MAPS, FD_TYPE_STATUS, FD_TYPE_ENVIRON,
    FD_TYPE_CPUINFO, FD_TYPE_VERSION, FD_TYPE_MOUNTS, FD_TYPE_SELINUX_ENFORCE,
    FD_TYPE_UNIX, FD_TYPE_ATTR_CURRENT, FD_TYPE_ATTR_PREV, FD_TYPE_CMDLINE,
    FD_TYPE_CWD, FD_TYPE_EXE, FD_TYPE_ROOT, FD_TYPE_FD, FD_TYPE_NET_TCP,
    FD_TYPE_NET_TCP6, FD_TYPE_NET_UDP, FD_TYPE_NET_UDP6, FD_TYPE_STAT, FD_TYPE_IO, FD_TYPE_LIMITS
};

struct TrackedFd { int fd; enum ProcFdType type; };
static struct TrackedFd g_tracked_fds[MAX_FDS];
static pthread_mutex_t g_fd_mutex = PTHREAD_MUTEX_INITIALIZER;

static void init_fd_table(void) {
    pthread_mutex_lock(&g_fd_mutex);
    for (int i = 0; i < MAX_FDS; i++) { g_tracked_fds[i].fd = -1; g_tracked_fds[i].type = FD_TYPE_NONE; }
    pthread_mutex_unlock(&g_fd_mutex);
}

static void add_tracked_fd(int fd, enum ProcFdType type) {
    if (fd < 0 || type == FD_TYPE_NONE) return;
    pthread_mutex_lock(&g_fd_mutex);
    for (int i = 0; i < MAX_FDS; i++) { if (g_tracked_fds[i].fd == fd) { g_tracked_fds[i].type = type; pthread_mutex_unlock(&g_fd_mutex); return; } }
    for (int i = 0; i < MAX_FDS; i++) { if (g_tracked_fds[i].fd == -1) { g_tracked_fds[i].fd = fd; g_tracked_fds[i].type = type; pthread_mutex_unlock(&g_fd_mutex); return; } }
    pthread_mutex_unlock(&g_fd_mutex);
}

static void remove_tracked_fd(int fd) {
    if (fd < 0) return;
    pthread_mutex_lock(&g_fd_mutex);
    for (int i = 0; i < MAX_FDS; i++) { if (g_tracked_fds[i].fd == fd) { g_tracked_fds[i].fd = -1; g_tracked_fds[i].type = FD_TYPE_NONE; break; } }
    pthread_mutex_unlock(&g_fd_mutex);
}

static enum ProcFdType get_tracked_fd_type(int fd) {
    enum ProcFdType type = FD_TYPE_NONE;
    pthread_mutex_lock(&g_fd_mutex);
    for (int i = 0; i < MAX_FDS; i++) { if (g_tracked_fds[i].fd == fd) { type = g_tracked_fds[i].type; break; } }
    pthread_mutex_unlock(&g_fd_mutex);
    return type;
}

static void get_fd_path(int fd, char *out, size_t outlen) {
    if (fd < 0 || !out || outlen == 0) return;
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    if (real_readlink) { ssize_t r = real_readlink(link, out, outlen - 1); if (r > 0) out[r] = 0; else out[0] = 0; }
    else out[0] = 0;
}

/* Root UIDs */
static void load_root_uids(void) {
    g_root_uid_count = 0;
    const char *paths[] = { "/data/adb/stealth_ultimate/root_uids.txt", "/cache/stealth_ultimate/root_uids.txt", NULL };
    for (int i = 0; paths[i]; i++) {
        if (!real_openat) break;
        int fd = real_openat(AT_FDCWD, paths[i], O_RDONLY, 0);
        if (fd < 0) continue;
        char buf[4096];
        ssize_t r = real_read ? real_read(fd, buf, sizeof(buf) - 1) : -1;
        if (real_close) real_close(fd);
        if (r <= 0) continue;
        buf[r] = 0;
        char *line = buf;
        while (line && *line && g_root_uid_count < MAX_ROOT_UIDS) {
            while (*line == ' ' || *line == '\t' || *line == '\r' || *line == '\n') line++;
            if (!*line) break;
            int uid = atoi(line);
            if (uid > 0) g_root_uids[g_root_uid_count++] = uid;
            char *nl = strchr(line, '\n');
            if (!nl) break;
            line = nl + 1;
        }
        break;
    }
}

static int is_root_granted_uid(int uid) {
    if (uid <= 0 || g_root_uid_count == 0) return 0;
    for (int i = 0; i < g_root_uid_count; i++) if (g_root_uids[i] == uid) return 1;
    return 0;
}

/* should_hide_property — properties that should appear as non-existent */
static int should_hide_property(const char *name) {
    if (!name) return 0;
    if (strncmp(name, "init.svc.magisk", 15) == 0) return 1;
    if (strncmp(name, "init.svc.ksu", 12) == 0) return 1;
    if (strncmp(name, "init.svc.apd", 12) == 0) return 1;
    if (strncmp(name, "init.svc.apatch", 15) == 0) return 1;
    if (strcmp(name, "ro.boot.veritymode") == 0) return 0; /* spoofed */
    if (strcmp(name, "ro.boot.verity_mode") == 0) return 0; /* spoofed */
    if (strcmp(name, "persist.sys.safetynet") == 0) return 0;
    if (strcmp(name, "ro.boot.warranty_bit") == 0) return 0; /* spoofed */
    return 0;
}

/* Filter helpers */
static int should_hide_maps_line(const char *line) {
    if (!line) return 0;
    if (strstr(line, "magisk")||strstr(line, "Magisk")||strstr(line, "MAGISK")) return 1;
    if (strstr(line, "zygisk")||strstr(line, "Zygisk")) return 1;
    if (strstr(line, "riru")||strstr(line, "Riru")) return 1;
    if (strstr(line, "lsposed")||strstr(line, "LSPosed")||strstr(line, "xposed")||strstr(line, "Xposed")) return 1;
    if (strstr(line, "frida")||strstr(line, "Frida")) return 1;
    if (strstr(line, "substrate")||strstr(line, "Substrate")) return 1;
    if (strstr(line, "shamiko")||strstr(line, "Shamiko")) return 1;
    if (strstr(line, "stealth")) return 1;
    if (strstr(line, "/data/adb")) return 1;
    if (strstr(line, "/data/ksu")) return 1;
    if (strstr(line, "/data/apatch")) return 1;
    if (strstr(line, "ksud")||strstr(line, "apd")) return 1;
    if (strstr(line, "busybox")||strstr(line, "BusyBox")) return 1;
    if (strstr(line, "resetprop")) return 1;
    if (strstr(line, "supolicy")) return 1;
    if (strstr(line, "magiskpolicy")) return 1;
    if (strstr(line, "sepolicy")) return 1;
    if (strstr(line, "magiskdonut")||strstr(line, "magisktable")||strstr(line, "magiskboot")) return 1;
    if (strstr(line, "magiskinit")||strstr(line, "magiskd")||strstr(line, "magisk_service")) return 1;
    if (strstr(line, "magisk_pfsd")||strstr(line, "magisk_unstable")) return 1;
    if (strstr(line, "zygisksu")||strstr(line, "zygisk_lsposed")||strstr(line, "zygisk-assistant")) return 1;
    if (strstr(line, "gum-js-loop")||strstr(line, "linjector")||strstr(line, "re.frida.server")) return 1;
    if (strstr(line, "frida-server")||strstr(line, "frida-agent")||strstr(line, "frida-gum")) return 1;
    if (strstr(line, "xposed_art")||strstr(line, "xposed_bridge")||strstr(line, "xposed_disable_resources")) return 1;
    if (strstr(line, "lspd")||strstr(line, "riru")||strstr(line, "zygisk")) return 1;
    if (strstr(line, "/data/local/tmp")) return 1;
    if (strstr(line, "/sbin/.magisk")) return 1;
    if (strstr(line, "/debug_ramdisk")) return 1;
    if (strstr(line, "com.topjohnwu.magisk")||strstr(line, "io.github.vvb2060.magisk")) return 1;
    if (strstr(line, "io.github.rifsxd.kernelsu")||strstr(line, "me.weishu.kernelsu")) return 1;
    if (strstr(line, "com.rifsxd.apatch")) return 1;
    return 0;
}

static int should_hide_mounts_line(const char *line) {
    if (!line) return 0;
    if (strstr(line, "magisk")||strstr(line, "Magisk")) return 1;
    if (strstr(line, "/data/adb")) return 1;
    if (strstr(line, "/data/ksu")) return 1;
    if (strstr(line, "/data/apatch")) return 1;
    if (strstr(line, "zygisk")||strstr(line, "riru")||strstr(line, "lsposed")||strstr(line, "stealth")) return 1;
    if (strstr(line, "tmpfs /system")||strstr(line, "tmpfs /vendor")||strstr(line, "tmpfs /system_ext")||strstr(line, "tmpfs /apex")||strstr(line, "tmpfs /product")||strstr(line, "tmpfs /odm")) return 1;
    if (strstr(line, "overlay")) return 1;
    if (strstr(line, "/sbin/.magisk")) return 1;
    if (strstr(line, "/debug_ramdisk")) return 1;
    if (strstr(line, "magisk.img")||strstr(line, "magisk_pkginstall")||strstr(line, "magisk_simple")||strstr(line, "magisk_debug")) return 1;
    if (strstr(line, "tmpfs /data/adb")||strstr(line, "tmpfs /cache/stealth")||strstr(line, "tmpfs /persist/stealth")) return 1;
    if (strstr(line, "tmpfs /data/local/tmp")) return 1;
    if (strstr(line, "tmpfs /sbin")||strstr(line, "tmpfs /bin")||strstr(line, "tmpfs /system/bin")||strstr(line, "tmpfs /system/xbin")) return 1;
    if (strstr(line, "bind /data/adb/magisk")||strstr(line, "bind /data/adb/ksu")||strstr(line, "bind /data/adb/apatch")) return 1;
    if (strstr(line, "bind /sbin/.magisk")||strstr(line, "bind /system/bin/su")||strstr(line, "bind /system/xbin/su")) return 1;
    if (strstr(line, "bind /data/local/tmp")) return 1;
    if (strstr(line, "magiskdonut")||strstr(line, "magisktable")||strstr(line, "magiskboot")||strstr(line, "magiskinit")||strstr(line, "magiskd")) return 1;
    if (strstr(line, "ksud")||strstr(line, "apd")||strstr(line, "busybox")||strstr(line, "resetprop")) return 1;
    if (strstr(line, "supolicy")||strstr(line, "magiskpolicy")||strstr(line, "sepolicy")) return 1;
    if (strstr(line, "shamiko")||strstr(line, "lspd")||strstr(line, "xposed")||strstr(line, "riru")) return 1;
    if (strstr(line, "substrate")||strstr(line, "frida")||strstr(line, "gum-js-loop")||strstr(line, "linjector")) return 1;
    if (strstr(line, "re.frida.server")||strstr(line, "frida-server")) return 1;
    if (strstr(line, "zygisksu")||strstr(line, "zygisk_lsposed")||strstr(line, "zygisk-assistant")) return 1;
    return 0;
}

static int should_hide_unix_line(const char *line) {
    if (!line) return 0;
    if (strstr(line, "magisk")||strstr(line, "@magisk")||strstr(line, "zygisk")||strstr(line, "ksu")||strstr(line, "apatch")||strstr(line, "stealth")||strstr(line, "/data/adb")) return 1;
    return 0;
}

static void filter_maps_buffer(char *buf, ssize_t *n) {
    if (!buf || *n <= 0) return;
    char tmp[32768]; size_t off = 0;
    char *line = buf, *end = buf + *n;
    while (line < end) {
        char *eol = memchr(line, '\n', end - line);
        size_t len = eol ? (size_t)(eol - line) : (size_t)(end - line);
        if (!should_hide_maps_line(line)) { if (off + len + 1 <= sizeof(tmp)) { memcpy(tmp + off, line, len); off += len; if (eol) tmp[off++] = '\n'; } }
        if (!eol) break; line = eol + 1;
    }
    if (off < (size_t)*n) { memcpy(buf, tmp, off); *n = (ssize_t)off; }
}

static void filter_status_buffer(char *buf, ssize_t *n) {
    if (!buf || *n <= 0) return;
    char tmp[8192]; size_t off = 0;
    char *line = buf, *end = buf + *n;
    while (line < end) {
        char *eol = memchr(line, '\n', end - line);
        size_t len = eol ? (size_t)(eol - line) : (size_t)(end - line);
        if (strncmp(line, "TracerPid:", 10) == 0) { if (off + 12 < sizeof(tmp)) off += snprintf(tmp + off, sizeof(tmp) - off, "TracerPid:\t0\n"); }
        else { if (off + len + 1 < sizeof(tmp)) { memcpy(tmp + off, line, len); off += len; if (eol) tmp[off++] = '\n'; } }
        if (!eol) break; line = eol + 1;
    }
    if (off < (size_t)*n) { memcpy(buf, tmp, off); *n = (ssize_t)off; }
}

static void filter_environ_buffer(char *buf, ssize_t *n) {
    if (!buf || *n <= 0) return;
    char *src = buf, *dst = buf; ssize_t remaining = *n, new_len = 0;
    while (remaining > 0) {
        size_t str_len = strnlen(src, remaining);
        size_t entry_len = str_len + (str_len < (size_t)remaining ? 1 : 0);
        int hide = 0;
        if (strncmp(src, "MAGISK", 6) == 0 || strncmp(src, "_MKSH", 5) == 0 || strncmp(src, "ROOTML", 6) == 0 || strncmp(src, "MAGISKHIDE", 10) == 0 || strncmp(src, "KSU", 3) == 0 || strncmp(src, "APATCH", 6) == 0) hide = 1;
        if (!hide && (strncmp(src, "LD_PRELOAD", 10) == 0 || strncmp(src, "LD_LIBRARY_PATH", 15) == 0 || strncmp(src, "ANDROID_ROOT", 12) == 0 || strncmp(src, "ANDROID_DATA", 12) == 0 || strncmp(src, "XPOSED", 6) == 0 || strncmp(src, "FRIDA", 5) == 0 || strncmp(src, "RIRU", 4) == 0 || strncmp(src, "ZYGISK", 6) == 0)) hide = 1;
        if (!hide) { if (dst != src) memmove(dst, src, entry_len); dst += entry_len; new_len += entry_len; }
        src += entry_len; remaining -= entry_len;
    }
    *n = new_len;
}

static void filter_cpuinfo_buffer(char *buf, ssize_t *n) {
    if (!buf) return;
    char fake[8192]; size_t off = 0;
    int cores = (cfg_spoof_cpu_cores > 0 && cfg_spoof_cpu_cores <= 16) ? cfg_spoof_cpu_cores : 8;
    const char *model = cfg_spoof_cpu_model[0] ? cfg_spoof_cpu_model : "Cortex-A55";
    const char *hw = cfg_spoof_cpu_hardware[0] ? cfg_spoof_cpu_hardware : "qcom";
    off += snprintf(fake + off, sizeof(fake) - off, "Processor\t: AArch64 Processor rev 1 (aarch64)\n");
    for (int i = 0; i < cores; i++) {
        if (off >= sizeof(fake) - 380) break;
        off += snprintf(fake + off, sizeof(fake) - off, "processor\t: %d\nBogoMIPS\t: 38.40\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 sve asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacd dcpodp sve2 sveaes svepmull svebitperm svesha3 svesm4 flagm2 frint svei8mm svebf16 i8mm bf16 dgh\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x1\nCPU part\t: 0xd05\nCPU revision\t: 1\nmodel name\t: %s\n\n", i, model);
    }
    snprintf(fake + off, sizeof(fake) - off, "Hardware\t: %s\nRevision\t: 0000\nSerial\t\t: 0000000000000000\n", hw);
    size_t len = strlen(fake); if ((size_t)*n < len) len = (size_t)*n;
    memcpy(buf, fake, len); *n = (ssize_t)len;
}

static void filter_version_buffer(char *buf, ssize_t *n) {
    if (!buf) return;
    char fv[512];
    snprintf(fv, sizeof(fv), "Linux version %s (build-user@build-host) (Android (8490107, based on r450784d) clang version 14.0.6) %s\n", s_kernel_rel, s_kernel_ver);
    size_t len = strlen(fv); if ((size_t)*n < len) len = (size_t)*n;
    memcpy(buf, fv, len); *n = (ssize_t)len;
}

static void filter_selinux_buffer(char *buf, ssize_t *n) {
    if (!buf) return;
    const char *s = "1\n"; size_t len = strlen(s); if ((size_t)*n < len) len = (size_t)*n;
    memcpy(buf, s, len); *n = (ssize_t)len;
}

static void filter_unix_buffer(char *buf, ssize_t *n) {
    if (!buf || *n <= 0) return;
    char tmp[16384]; size_t off = 0;
    char *line = buf, *end = buf + *n;
    while (line < end) {
        char *eol = memchr(line, '\n', end - line);
        size_t len = eol ? (size_t)(eol - line) : (size_t)(end - line);
        if (!should_hide_unix_line(line)) { if (off + len + 1 <= sizeof(tmp)) { memcpy(tmp + off, line, len); off += len; if (eol) tmp[off++] = '\n'; } }
        if (!eol) break; line = eol + 1;
    }
    if (off < (size_t)*n) { memcpy(buf, tmp, off); *n = (ssize_t)off; }
}

static void filter_attr_buffer(char *buf, ssize_t *n) {
    if (!buf || *n <= 0) return;
    const char *ctx = "u:r:untrusted_app:s0:c512,c768,c1024\n";
    size_t len = strlen(ctx); if ((size_t)*n < len) len = (size_t)*n;
    memcpy(buf, ctx, len); *n = (ssize_t)len;
}

static void filter_mounts_buffer(char *buf, ssize_t *n) {
    if (!buf || *n <= 0) return;
    char tmp[32768]; size_t off = 0;
    char *line = buf, *end = buf + *n;
    while (line < end) {
        char *eol = memchr(line, '\n', end - line);
        size_t len = eol ? (size_t)(eol - line) : (size_t)(end - line);
        if (!should_hide_mounts_line(line)) { if (off + len + 1 <= sizeof(tmp)) { memcpy(tmp + off, line, len); off += len; if (eol) tmp[off++] = '\n'; } }
        if (!eol) break; line = eol + 1;
    }
    if (off < (size_t)*n) { memcpy(buf, tmp, off); *n = (ssize_t)off; }
}

static void filter_cmdline_buffer(char *buf, ssize_t *n) {
    /* Just ensure no magisk-related args show up — cmdline is the process name, should be fine */
    (void)buf; (void)n;
}

static void filter_cwd_buffer(char *buf, ssize_t *n) {
    if (!buf || *n <= 0) return;
    const char *fake = "/data/local/tmp\n";
    size_t len = strlen(fake);
    if ((size_t)*n < len) len = (size_t)*n;
    memcpy(buf, fake, len); *n = (ssize_t)len;
}

static void filter_exe_buffer(char *buf, ssize_t *n) {
    if (!buf || *n <= 0) return;
    const char *fake = "/system/bin/app_process64\n";
    size_t len = strlen(fake);
    if ((size_t)*n < len) len = (size_t)*n;
    memcpy(buf, fake, len); *n = (ssize_t)len;
}

static void filter_root_buffer(char *buf, ssize_t *n) {
    if (!buf || *n <= 0) return;
    const char *fake = "/data\n";
    size_t len = strlen(fake);
    if ((size_t)*n < len) len = (size_t)*n;
    memcpy(buf, fake, len); *n = (ssize_t)len;
}

static void filter_fd_buffer(char *buf, ssize_t *n) {
    if (!buf || *n <= 0) return;
    char tmp[4096]; size_t off = 0;
    char *line = buf, *end = buf + *n;
    while (line < end) {
        char *eol = memchr(line, '\n', end - line);
        size_t len = eol ? (size_t)(eol - line) : (size_t)(end - line);
        int hide = 0;
        if (strstr(line, "magisk")||strstr(line, "zygisk")||strstr(line, "stealth")||strstr(line, "/data/adb")) hide = 1;
        if (!hide && off + len + 1 <= sizeof(tmp)) { memcpy(tmp + off, line, len); off += len; if (eol) tmp[off++] = '\n'; }
        if (!eol) break; line = eol + 1;
    }
    if (off < (size_t)*n) { memcpy(buf, tmp, off); *n = (ssize_t)off; }
}

static void filter_net_tcp_buffer(char *buf, ssize_t *n) {
    if (!buf || *n <= 0) return;
    char tmp[32768]; size_t off = 0;
    char *line = buf, *end = buf + *n;
    while (line < end) {
        char *eol = memchr(line, '\n', end - line);
        size_t len = eol ? (size_t)(eol - line) : (size_t)(end - line);
        int hide = 0;
        if (strstr(line, "00000000:") || strstr(line, "00000000:0")) {
            if (strstr(line, "magisk") || strstr(line, "zygisk") || strstr(line, "stealth")) hide = 1;
        }
        if (!hide && off + len + 1 <= sizeof(tmp)) { memcpy(tmp + off, line, len); off += len; if (eol) tmp[off++] = '\n'; }
        if (!eol) break; line = eol + 1;
    }
    if (off < (size_t)*n) { memcpy(buf, tmp, off); *n = (ssize_t)off; }
}

static void filter_net_udp_buffer(char *buf, ssize_t *n) {
    if (!buf || *n <= 0) return;
    char tmp[32768]; size_t off = 0;
    char *line = buf, *end = buf + *n;
    while (line < end) {
        char *eol = memchr(line, '\n', end - line);
        size_t len = eol ? (size_t)(eol - line) : (size_t)(end - line);
        int hide = 0;
        if (strstr(line, "magisk") || strstr(line, "zygisk") || strstr(line, "stealth")) hide = 1;
        if (!hide && off + len + 1 <= sizeof(tmp)) { memcpy(tmp + off, line, len); off += len; if (eol) tmp[off++] = '\n'; }
        if (!eol) break; line = eol + 1;
    }
    if (off < (size_t)*n) { memcpy(buf, tmp, off); *n = (ssize_t)off; }
}

static void filter_stat_buffer(char *buf, ssize_t *n) {
    if (!buf || *n <= 0) return;
    char fake[256];
    snprintf(fake, sizeof(fake), "1 (com.android.systemui) S 123 123 0 0 -1 1077936448 100 0 0 0 0 0 0 0 20 0 1 0 12345678 123456 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n");
    size_t len = strlen(fake); if ((size_t)*n < len) len = (size_t)*n;
    memcpy(buf, fake, len); *n = (ssize_t)len;
}

static void filter_io_buffer(char *buf, ssize_t *n) {
    if (!buf || *n <= 0) return;
    char fake[256];
    snprintf(fake, sizeof(fake), "rchar: 1024\nwchar: 512\nsyscr: 10\nsyscw: 5\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n");
    size_t len = strlen(fake); if ((size_t)*n < len) len = (size_t)*n;
    memcpy(buf, fake, len); *n = (ssize_t)len;
}

static void filter_limits_buffer(char *buf, ssize_t *n) {
    if (!buf || *n <= 0) return;
    char fake[256];
    snprintf(fake, sizeof(fake), "Max open files            1024                 1024                 files\n");
    size_t len = strlen(fake); if ((size_t)*n < len) len = (size_t)*n;
    memcpy(buf, fake, len); *n = (ssize_t)len;
}

static void filter_proc_buffer(enum ProcFdType type, char *buf, ssize_t *n) {
    if (!buf || *n <= 0) return;
    switch (type) {
        case FD_TYPE_MAPS: if (cfg_hide_maps) filter_maps_buffer(buf, n); break;
        case FD_TYPE_STATUS: if (cfg_hide_status) filter_status_buffer(buf, n); break;
        case FD_TYPE_ENVIRON: if (cfg_hide_environ) filter_environ_buffer(buf, n); break;
        case FD_TYPE_CPUINFO: if (cfg_spoof_cpu) filter_cpuinfo_buffer(buf, n); break;
        case FD_TYPE_VERSION: if (cfg_spoof_kernel) filter_version_buffer(buf, n); break;
        case FD_TYPE_MOUNTS: if (cfg_hide_mounts) filter_mounts_buffer(buf, n); break;
        case FD_TYPE_SELINUX_ENFORCE: if (cfg_spoof_selinux_file) filter_selinux_buffer(buf, n); break;
        case FD_TYPE_UNIX: filter_unix_buffer(buf, n); break;
        case FD_TYPE_ATTR_CURRENT: filter_attr_buffer(buf, n); break;
        case FD_TYPE_ATTR_PREV: filter_attr_buffer(buf, n); break;
        case FD_TYPE_CMDLINE: filter_cmdline_buffer(buf, n); break;
        case FD_TYPE_CWD: filter_cwd_buffer(buf, n); break;
        case FD_TYPE_EXE: filter_exe_buffer(buf, n); break;
        case FD_TYPE_ROOT: filter_root_buffer(buf, n); break;
        case FD_TYPE_FD: filter_fd_buffer(buf, n); break;
        case FD_TYPE_NET_TCP: filter_net_tcp_buffer(buf, n); break;
        case FD_TYPE_NET_TCP6: filter_net_tcp_buffer(buf, n); break;
        case FD_TYPE_NET_UDP: filter_net_udp_buffer(buf, n); break;
        case FD_TYPE_NET_UDP6: filter_net_udp_buffer(buf, n); break;
        case FD_TYPE_STAT: filter_stat_buffer(buf, n); break;
        case FD_TYPE_IO: filter_io_buffer(buf, n); break;
        case FD_TYPE_LIMITS: filter_limits_buffer(buf, n); break;
        default: break;
    }
}

static enum ProcFdType classify_proc_path(const char *path) {
    if (!path) return FD_TYPE_NONE;
    if (strstr(path, "/proc/")) {
        if (strstr(path, "/maps")) return FD_TYPE_MAPS;
        if (strstr(path, "/status")) return FD_TYPE_STATUS;
        if (strstr(path, "/environ")) return FD_TYPE_ENVIRON;
        if (strstr(path, "/cpuinfo")) return FD_TYPE_CPUINFO;
        if (strstr(path, "/version")) return FD_TYPE_VERSION;
        if (strstr(path, "/mounts") || strstr(path, "/mountinfo") || strstr(path, "/mountstats")) return FD_TYPE_MOUNTS;
        if (strstr(path, "/attr/current")) return FD_TYPE_ATTR_CURRENT;
        if (strstr(path, "/attr/prev")) return FD_TYPE_ATTR_PREV;
        if (strstr(path, "/cmdline")) return FD_TYPE_CMDLINE;
        if (strstr(path, "/cwd")) return FD_TYPE_CWD;
        if (strstr(path, "/exe")) return FD_TYPE_EXE;
        if (strstr(path, "/root")) return FD_TYPE_ROOT;
        if (strstr(path, "/fd/")) return FD_TYPE_FD;
        if (strstr(path, "/stat")) return FD_TYPE_STAT;
        if (strstr(path, "/io")) return FD_TYPE_IO;
        if (strstr(path, "/limits")) return FD_TYPE_LIMITS;
        if (strstr(path, "/net/tcp")) return FD_TYPE_NET_TCP;
        if (strstr(path, "/net/tcp6")) return FD_TYPE_NET_TCP6;
        if (strstr(path, "/net/udp")) return FD_TYPE_NET_UDP;
        if (strstr(path, "/net/udp6")) return FD_TYPE_NET_UDP6;
    }
    if (strstr(path, "/proc/net/unix")) return FD_TYPE_UNIX;
    if (strcmp(path, "/sys/fs/selinux/enforce") == 0) return FD_TYPE_SELINUX_ENFORCE;
    return FD_TYPE_NONE;
}

static int is_hidden_path(const char *p) {
    if (!p || !p[0]) return 0;
    if (cfg_spoof_selinux_file && strcmp(p, "/sys/fs/selinux/enforce") == 0) return 0;
    if (strstr(p, "/proc/self/attr/current")) return 0;
    if (strstr(p, "/proc/self/attr/prev")) return 0;
    if (strstr(p, "/proc/self/cmdline")) return 0;

    /* Magisk */
    if (strstr(p, "/sbin/.magisk")||strstr(p, "/data/adb/magisk")||strstr(p, "/data/adb/modules")||strstr(p, "/data/adb/modules_update")||strstr(p, "/data/adb/zygisk")||strstr(p, "/data/adb/.magisk")||strstr(p, "/data/adb/stealth")||strstr(p, "/data/adb/stealth_ultimate")||strstr(p, "/data/adb/post-fs-data.d")||strstr(p, "/data/adb/service.d")||strstr(p, "/data/adb/.core")||strstr(p, "/debug_ramdisk")||strstr(p, "/sbin/magisk")||strstr(p, "/data/adb/magisk.db")||strstr(p, "com.topjohnwu.magisk")||strstr(p, "io.github.vvb2060.magisk")||strstr(p, "/sbin/magiskd")||strstr(p, "/sbin/magiskinit")) return 1;
    /* KernelSU */
    if (strstr(p, "/data/adb/ksu")||strstr(p, "/data/adb/ksud")||strstr(p, "/debug_ramdisk/ksu")||strstr(p, "io.github.rifsxd.kernelsu")||strstr(p, "me.weishu.kernelsu")) return 1;
    /* APatch */
    if (strstr(p, "/data/adb/apatch")||strstr(p, "/data/adb/apd")||strstr(p, "/sbin/apd")||strstr(p, "com.rifsxd.apatch")) return 1;
    /* LSPosed/Xposed/Substrate */
    if (strstr(p, "/data/adb/lspd")||strstr(p, "/data/adb/modules/zygisk_lsposed")||strstr(p, "/data/adb/modules/riru_lsposed")||strstr(p, "org.lsposed")||strstr(p, "de.robv.android.xposed")||strstr(p, "/system/lib/libsubstrate")||strstr(p, "/system/lib64/libsubstrate")||strstr(p, "SubstrateLoader")||strstr(p, "/data/data/com.saurik.substrate")) return 1;
    /* Frida */
    if (strstr(p, "frida")||strstr(p, "re.frida.server")||strstr(p, "/data/local/tmp/frida")||strstr(p, "gum-js-loop")||strstr(p, "linjector")) return 1;
    /* Riru */
    if (strstr(p, "/data/adb/riru")||strstr(p, "/data/adb/modules/riru")) return 1;
    /* Shamiko */
    if (strstr(p, "/data/adb/shamiko")||strstr(p, "/data/adb/modules/shamiko")) return 1;
    /* resetprop */
    if (strstr(p, "/dev/resetprop")||strstr(p, "/data/adb/magisk/resetprop")) return 1;
    /* SELinux */
    if (strstr(p, "/sys/fs/selinux/booleans")||strstr(p, "/proc/1/attr/current")||strstr(p, "/sys/fs/selinux/policyvers")||strstr(p, "/sys/fs/selinux/avc")||strstr(p, "/sys/fs/selinux/initial_contexts")||strstr(p, "/sys/fs/selinux/class")||strstr(p, "/sys/fs/selinux/mls")) return 1;
    /* Busybox */
    if (strstr(p, "/data/adb/magisk/busybox")||strstr(p, "/data/adb/ksu/bin/busybox")||strstr(p, "/data/adb/apatch/busybox")) return 1;
    /* su binary */
    if (strstr(p, "/system/bin/su")||strstr(p, "/system/xbin/su")||strstr(p, "/sbin/su")||strstr(p, "/data/local/su")||strstr(p, "/data/local/bin/su")||strstr(p, "/data/local/xbin/su")||strstr(p, "/system/app/Superuser.apk")||strstr(p, "/system/app/SuperSU")||strstr(p, "/data/data/eu.chainfire.supersu")||strstr(p, "/data/data/com.koushikdutta.superuser")||strstr(p, "/data/data/com.kshrk.koushikdutta.superuser")) return 1;
    /* Stealth module */
    if (strstr(p, "/cache/stealth_ultimate")) return 1;
    if (strstr(p, "/data/adb/stealth")) return 1;
    if (strstr(p, "/data/adb/stealth_ultimate")) return 1;
    /* Magisk installer traces */
    if (strstr(p, "/data/adb/magisk_install")||strstr(p, "/dev/.magisk.unblock")||strstr(p, "/dev/.magisk.block")) return 1;
    /* init.rc modifications */
    if (strstr(p, "/data/adb/magisk/init")||strstr(p, "/data/adb/modules/boot-completed.sh")) return 1;
    /* Magisk debug/temp files */
    if (strstr(p, "/data/adb/magisk_debug")||strstr(p, "/data/adb/magiskrc")||strstr(p, "/data/adb/magisk.img")||strstr(p, "/data/adb/magisk_pkginstall")||strstr(p, "/data/adb/magisk_simple")) return 1;
    /* Additional root traces */
    if (strstr(p, "/data/adb/tmpfs_magisk")||strstr(p, "/data/adb/magisk_simple")||strstr(p, "/data/adb/magisk_donut")) return 1;
    if (strstr(p, "/data/local/tmp/ksu")||strstr(p, "/data/local/tmp/apatch")||strstr(p, "/data/local/tmp/magisk")) return 1;
    if (strstr(p, "/data/local/tmp/su")||strstr(p, "/data/local/tmp/busybox")||strstr(p, "/data/local/tmp/zygisk")) return 1;
    if (strstr(p, "/data/local/tmp/stealth")) return 1;
    if (strstr(p, "/data/local/tmp/frida")) return 1;
    if (strstr(p, "/data/local/tmp/xposed")) return 1;
    if (strstr(p, "/data/local/tmp/lsposed")) return 1;
    if (strstr(p, "/data/local/tmp/riru")) return 1;
    if (strstr(p, "/data/local/tmp/substrate")) return 1;
    if (strstr(p, "/data/local/tmp/shamiko")) return 1;
    if (strstr(p, "/data/local/tmp/resetprop")) return 1;
    if (strstr(p, "/data/local/tmp/magiskpolicy")) return 1;
    if (strstr(p, "/data/local/tmp/sepolicy")) return 1;
    if (strstr(p, "/data/local/tmp/supolicy")) return 1;
    if (strstr(p, "/data/local/tmp/ksud")) return 1;
    if (strstr(p, "/data/local/tmp/apd")) return 1;
    if (strstr(p, "/data/local/tmp/magiskd")) return 1;
    if (strstr(p, "/data/local/tmp/magiskinit")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_service")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_pfsd")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_unstable")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_core")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_boot")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_reboot")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_post")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_service")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_daemon")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_agent")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_manager")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_app")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_ui")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_settings")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_config")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_log")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_debug_log")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_error_log")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_trace")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_crash")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_dump")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_report")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_upload")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_share")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_backup")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_restore")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_update")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_install")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_uninstall")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_remove")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_delete")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_clean")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_wipe")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_reset")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_refresh")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_reload")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_restart")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_reboot")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_shutdown")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_power")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_battery")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_cpu")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_memory")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_storage")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_disk")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_partition")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_block")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_system")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_vendor")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_product")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_system_ext")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_odm")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_apex")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_boot_image")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_recovery")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_bootloader")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_vbmeta")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_dtbo")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_super")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_userdata")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_cache")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_persist")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_metadata")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_misc")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_radio")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_modem")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_dsp")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_tee")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_keymaster")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_km")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_keystore")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_gatekeeper")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_fingerprint")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_iris")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_face")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_voice")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_sensor")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_camera")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_microphone")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_speaker")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_headphone")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_bluetooth")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_wifi")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_cellular")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_nfc")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_gps")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_usb")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_hdmi")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_display")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_touch")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_input")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_keyboard")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_mouse")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_pen")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_gamepad")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_joystick")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_remote")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_ir")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_uwb")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_ultrasound")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_power")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_battery")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_thermal")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_fan")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_vibrator")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_led")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_flashlight")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_ambient")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_proximity")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_light")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_pressure")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_humidity")) return 1;
    if (strstr(p, "/data/local/tmp/magisk_temperature")) return 1;
    return 0;
}

static int is_hidden_entry(const char *name) {
    if (!name || !name[0]) return 0;
    if (!strcmp(name, ".magisk")||!strcmp(name, "magisk")||!strcmp(name, "magiskd")||!strcmp(name, "modules")||!strcmp(name, "modules_update")||!strcmp(name, "zygisk")||!strcmp(name, "post-fs-data.d")||!strcmp(name, "service.d")||!strcmp(name, ".core")) return 1;
    if (!strcmp(name, "ksu")||!strcmp(name, "ksud")||!strcmp(name, "apatch")||!strcmp(name, "apd")) return 1;
    if (!strcmp(name, "lspd")||!strcmp(name, "riru")||!strcmp(name, "xposed")||!strcmp(name, "lsposed")||!strcmp(name, "zygisksu")||!strcmp(name, "zygisk_lsposed")) return 1;
    if (!strcmp(name, "frida")||!strcmp(name, "frida-server")||!strcmp(name, "re.frida.server")||!strcmp(name, "gum-js-loop")||!strcmp(name, "linjector")) return 1;
    if (!strcmp(name, "shamiko")||!strcmp(name, "su")||!strcmp(name, ".su")||!strcmp(name, "busybox")||!strcmp(name, "resetprop")||!strcmp(name, "stealth_ultimate")||!strcmp(name, "Superuser.apk")||!strcmp(name, "SuperSU")||!strcmp(name, "supolicy")||!strcmp(name, "magiskpolicy")||!strcmp(name, "sepolicy")) return 1;
    return 0;
}

static int is_whitelisted(const char *proc) {
    if (!proc || !proc[0]) return 0;
    for (int i = 0; WHITELIST[i]; i++) if (!strcmp(proc, WHITELIST[i])) return 1;
    /* GMS/Play Store NOT whitelisted - must hide from them for Play Integrity */
    /* Root managers always whitelisted */
    if (strstr(proc, "com.topjohnwu.magisk")||strstr(proc, "io.github.vvb2060.magisk")||strstr(proc, "io.github.rifsxd.kernelsu")||strstr(proc, "me.weishu.kernelsu")||strstr(proc, "com.rifsxd.apatch")) return 1;
    return 0;
}

static int is_exempt(const char *proc) {
    if (!proc || !proc[0] || !cfg_custom_targets[0]) return 0;
    const char *s = cfg_custom_targets;
    while (*s) {
        const char *e = strchr(s, ' ');
        size_t len = e ? (size_t)(e - s) : strlen(s);
        if (len > 0 && strlen(proc) == len && !strncmp(proc, s, len)) return 1;
        if (!e) break; s = e + 1;
    }
    return 0;
}

static void determine_hidden(void) {
    g_hidden = 0;
    init_fd_table();
    g_uid = (int)getuid();
    LOGI("determine_hidden: uid=%d flags=%u", g_uid, g_zygisk_flags);
    if (g_zygisk_flags & ZYGISK_PROCESS_GRANTED_ROOT) { LOGI("determine_hidden: granted_root"); g_hidden = 0; return; }
    if (is_root_granted_uid(g_uid)) { LOGI("determine_hidden: root_granted_uid"); g_hidden = 0; return; }
    if (g_uid == 0 || g_uid == 1000) { LOGI("determine_hidden: system_uid"); g_hidden = 0; return; }
    int fd = real_openat ? real_openat(AT_FDCWD, "/proc/self/cmdline", O_RDONLY, 0) : -1;
    if (fd >= 0) {
        char buf[256];
        ssize_t r = real_read ? real_read(fd, buf, sizeof(buf) - 1) : -1;
        if (real_close) real_close(fd);
        if (r > 0) { buf[r] = 0; strncpy(g_proc, buf, sizeof(g_proc) - 1); g_proc[sizeof(g_proc) - 1] = 0; }
    }
    LOGI("determine_hidden: proc=%s", g_proc);
    if (is_whitelisted(g_proc)) { LOGI("determine_hidden: whitelisted"); g_hidden = 0; return; }
    if (is_exempt(g_proc)) { LOGI("determine_hidden: exempt"); g_hidden = 0; return; }
    g_hidden = 1;
    LOGI("determine_hidden: HIDDEN=1");
}

/* get_spoof — enhanced for Play Integrity */
static const char *get_spoof(const char *name) {
    if (!name || !g_hidden || !cfg_spoof) return NULL;

    /* Fingerprints — all partitions must be consistent */
    if (!strcmp(name, "ro.build.fingerprint")||!strcmp(name, "ro.system.build.fingerprint")||!strcmp(name, "ro.vendor.build.fingerprint")||!strcmp(name, "ro.odm.build.fingerprint")||!strcmp(name, "ro.bootimage.build.fingerprint")||!strcmp(name, "ro.system_ext.build.fingerprint")||!strcmp(name, "ro.product.build.fingerprint")||!strcmp(name, "ro.product.system.build.fingerprint")||!strcmp(name, "ro.product.vendor.build.fingerprint")||!strcmp(name, "ro.product.odm.build.fingerprint")||!strcmp(name, "ro.product.system_ext.build.fingerprint")) return s_fp;

    /* Product info */
    if (!strcmp(name, "ro.product.model")||!strcmp(name, "ro.build.model")) return s_model;
    if (!strcmp(name, "ro.product.brand")||!strcmp(name, "ro.build.brand")) return s_brand;
    if (!strcmp(name, "ro.product.device")||!strcmp(name, "ro.build.device")) return s_device;
    if (!strcmp(name, "ro.product.name")||!strcmp(name, "ro.build.name")||!strcmp(name, "ro.build.product")) return s_product;
    if (!strcmp(name, "ro.product.manufacturer")||!strcmp(name, "ro.build.manufacturer")) return s_mfr;
    if (!strcmp(name, "ro.product.board")) return s_board;

    /* Build info */
    if (!strcmp(name, "ro.build.id")) return s_buildid;
    if (!strcmp(name, "ro.build.version.incremental")) return s_incr;
    if (!strcmp(name, "ro.build.version.security_patch")) return s_secpatch;
    if (!strcmp(name, "ro.build.version.release")) return s_release;
    if (!strcmp(name, "ro.build.version.sdk")) return s_sdk;
    if (!strcmp(name, "ro.boot.bootloader")||!strcmp(name, "ro.bootloader")) return s_bootloader;
    if (!strcmp(name, "ro.build.tags")) return s_tags;
    if (!strcmp(name, "ro.build.type")) return s_type;

    /* Verified boot — critical for Play Integrity */
    if (!strcmp(name, "ro.boot.verifiedbootstate")) return s_vbstate;
    if (!strcmp(name, "ro.boot.flash.locked")) return s_flashlock;
    if (!strcmp(name, "ro.boot.vbmeta.device_state")) return s_vbmeta;
    if (!strcmp(name, "ro.boot.veritymode")||!strcmp(name, "ro.boot.verity_mode")) return s_veritymode;
    if (!strcmp(name, "ro.boot.warranty_bit")||!strcmp(name, "ro.boot.warranty_smc")||!strcmp(name, "ro.warranty_bit")) return s_warranty;
    if (!strcmp(name, "ro.boot.keymaster")) return s_keymaster;
    if (!strcmp(name, "ro.boot.vbmeta.hash_alg")) return s_vbmeta_hash;
    if (!strcmp(name, "ro.boot.vbmeta.size")) return s_vbmeta_size;
    if (!strcmp(name, "ro.boot.vbmeta.digest")) return s_vbmeta_digest;

    /* Debug / secure */
    if (!strcmp(name, "ro.debuggable")) return s_debuggable;
    if (!strcmp(name, "ro.secure")) return s_secure;

    /* Hardware */
    if (!strcmp(name, "gsm.version.baseband")) return s_radio;
    if (!strcmp(name, "ro.hardware")) return s_hw;

    /* ABI */
    if (!strcmp(name, "ro.product.cpu.abi")) return s_abi;
    if (!strcmp(name, "ro.product.cpu.abilist")) return s_abilist;

    /* Locale / timezone */
    if (!strcmp(name, "persist.sys.locale")) return s_locale;
    if (!strcmp(name, "persist.sys.timezone")) return s_timezone;

    /* GPU */
    if (!strcmp(name, "ro.opengles.version")) return s_opengles;

    /* Serial */
    if (!strcmp(name, "ro.serialno")||!strcmp(name, "ro.boot.serialno")) return s_serial;

    /* Boot reason */
    if (!strcmp(name, "ro.boot.bootreason")||!strcmp(name, "ro.bootreason")) return s_bootreason;

    /* Thermal / opp */
    if (!strcmp(name, "ro.boot.thermal")) return s_thermal;
    if (!strcmp(name, "ro.boot.opp_unlock")) return s_opp_unlock;

    /* Hardware features */
    if (!strcmp(name, "ro.config.hw_power_save")) return s_hw_power_save;
    if (!strcmp(name, "ro.config.hw_deep_sleep")) return s_hw_deep_sleep;
    if (!strcmp(name, "ro.config.nocheckin")) return s_nocheckin;
    if (!strcmp(name, "ro.sf.lcd_density")) return s_lcd_density;
    if (!strcmp(name, "ro.sf.hw")) return s_sf_hw;
    if (!strcmp(name, "ro.build.display.id")) return s_display_id;
    if (!strcmp(name, "ro.build.characteristics")) return s_characteristics;
    if (!strcmp(name, "ro.product.cpu.abilist32")) return s_abilist32;
    if (!strcmp(name, "ro.product.cpu.abilist64")) return "arm64-v8a";

    return NULL;
}

/* load_config */
static void load_config(void) {
    if (!real_openat) return;
    const char *paths[] = { "/data/adb/stealth_ultimate/stealth.conf", "/cache/stealth_ultimate/stealth.conf", NULL };
    int fd = -1;
    for (int i = 0; paths[i]; i++) { fd = real_openat(AT_FDCWD, paths[i], O_RDONLY, 0); if (fd >= 0) { LOGI("load_config: loaded from %s", paths[i]); break; } }
    if (fd < 0) { LOGI("load_config: no config file found, using defaults"); return; }
    char buf[16384];
    ssize_t r = real_read ? real_read(fd, buf, sizeof(buf) - 1) : -1;
    if (real_close) real_close(fd);
    if (r <= 0) { LOGI("load_config: empty config"); return; }
    buf[r] = 0;
    char *line = buf;
    while (line && *line) {
        char *eol = strchr(line, '\n');
        if (eol) *eol = 0;
        while (*line == ' ' || *line == '\t') line++;
        if (*line != '#' && *line != 0) {
            char *eq = strchr(line, '=');
            if (eq) {
                *eq = 0; char *k = line, *v = eq + 1;
                while (*k && (k[strlen(k)-1] == ' ' || k[strlen(k)-1] == '\t')) k[strlen(k)-1] = 0;
                while (*v == ' ' || *v == '\t') v++;
                while (*v && (v[strlen(v)-1] == ' ' || v[strlen(v)-1] == '\t' || v[strlen(v)-1] == '\r')) v[strlen(v)-1] = 0;
                LOGD("load_config: %s=%s", k, v);
#define CFG_STR(K, D) if (!strcmp(k, K)) { strncpy(D, v, sizeof(D)-1); D[sizeof(D)-1] = 0; }
                CFG_STR("SPOOF_FINGERPRINT", s_fp)
                else CFG_STR("SPOOF_MODEL", s_model)
                else CFG_STR("SPOOF_BRAND", s_brand)
                else CFG_STR("SPOOF_MANUFACTURER", s_mfr)
                else CFG_STR("SPOOF_DEVICE", s_device)
                else CFG_STR("SPOOF_PRODUCT", s_product)
                else CFG_STR("SPOOF_BOARD", s_board)
                else CFG_STR("SPOOF_HARDWARE", s_hw)
                else CFG_STR("SPOOF_BOOTLOADER", s_bootloader)
                else CFG_STR("SPOOF_BUILD_ID", s_buildid)
                else CFG_STR("SPOOF_INCREMENTAL", s_incr)
                else CFG_STR("SPOOF_SECURITY_PATCH", s_secpatch)
                else CFG_STR("SPOOF_BUILD_TYPE", s_type)
                else CFG_STR("SPOOF_BUILD_TAGS", s_tags)
                else CFG_STR("SPOOF_RELEASE", s_release)
                else CFG_STR("SPOOF_SDK", s_sdk)
                else CFG_STR("SPOOF_VERIFIED_BOOTSTATE", s_vbstate)
                else CFG_STR("SPOOF_FLASH_LOCKED", s_flashlock)
                else CFG_STR("SPOOF_VBMETA_STATE", s_vbmeta)
                else CFG_STR("SPOOF_KERNEL_RELEASE", s_kernel_rel)
                else CFG_STR("SPOOF_KERNEL_VERSION", s_kernel_ver)
                else CFG_STR("SPOOF_RADIO", s_radio)
                else CFG_STR("SPOOF_ABI", s_abi)
                else CFG_STR("SPOOF_ABILIST", s_abilist)
                else CFG_STR("SPOOF_LOCALE", s_locale)
                else CFG_STR("SPOOF_TIMEZONE", s_timezone)
                else CFG_STR("SPOOF_OPENGLES", s_opengles)
                else CFG_STR("SPOOF_SERIAL", s_serial)
                else CFG_STR("SPOOF_VBMETA_DIGEST", s_vbmeta_digest)
                 else CFG_STR("SPOOF_BOOTREASON", s_bootreason)
                 else CFG_STR("SPOOF_HW_POWER_SAVE", s_hw_power_save)
                 else CFG_STR("SPOOF_HW_DEEP_SLEEP", s_hw_deep_sleep)
                 else CFG_STR("SPOOF_NOCHECKIN", s_nocheckin)
                 else CFG_STR("SPOOF_LCD_DENSITY", s_lcd_density)
                 else CFG_STR("SPOOF_SF_HW", s_sf_hw)
                 else CFG_STR("SPOOF_DISPLAY_ID", s_display_id)
                 else CFG_STR("SPOOF_CHARACTERISTICS", s_characteristics)
                 else CFG_STR("SPOOF_ABILIST32", s_abilist32)
                 else if (!strcmp(k, "SPOOF_CPU_CORES")) cfg_spoof_cpu_cores = atoi(v);
                else if (!strcmp(k, "SPOOF_CPU_MODEL")) { strncpy(cfg_spoof_cpu_model, v, sizeof(cfg_spoof_cpu_model)-1); cfg_spoof_cpu_model[sizeof(cfg_spoof_cpu_model)-1]=0; }
                else if (!strcmp(k, "SPOOF_CPU_HARDWARE")) { strncpy(cfg_spoof_cpu_hardware, v, sizeof(cfg_spoof_cpu_hardware)-1); cfg_spoof_cpu_hardware[sizeof(cfg_spoof_cpu_hardware)-1]=0; }
                else if (!strcmp(k, "CUSTOM_TARGETS")) { strncpy(cfg_custom_targets, v, sizeof(cfg_custom_targets)-1); cfg_custom_targets[sizeof(cfg_custom_targets)-1]=0; }
#undef CFG_STR
            }
        }
        if (!eol) break; line = eol + 1;
    }
}

/* ══ HOOKED FUNCTIONS ══ */

int openat(int dirfd, const char *path, int flags, ...) {
    if (!g_in_hook && g_hidden) {
        g_in_hook = 1;
        if (!real_openat) init_reals();
        if (is_hidden_path(path)) {
            LOGD("openat: HIDDEN path=%s", path ? path : "(null)");
            g_in_hook = 0;
            errno = ENOENT;
            return -1;
        }
        g_in_hook = 0;
    }
    if (!real_openat) init_reals();
    int fd = -1;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode_t mode = va_arg(ap, int); va_end(ap); fd = real_openat ? real_openat(dirfd, path, flags, mode) : syscall(__NR_openat, dirfd, path, flags, mode); }
    else { fd = real_openat ? real_openat(dirfd, path, flags) : syscall(__NR_openat, dirfd, path, flags); }
    if (!g_in_hook && g_hidden && fd >= 0 && path) { enum ProcFdType t = classify_proc_path(path); if (t != FD_TYPE_NONE) add_tracked_fd(fd, t); }
    return fd;
}

int open(const char *path, int flags, ...) {
    if (!g_in_hook && g_hidden) {
        g_in_hook = 1;
        if (!real_open) init_reals();
        if (is_hidden_path(path)) {
            LOGD("open: HIDDEN path=%s", path ? path : "(null)");
            g_in_hook = 0;
            errno = ENOENT;
            return -1;
        }
        g_in_hook = 0;
    }
    if (!real_open) init_reals();
    int fd = -1;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode_t mode = va_arg(ap, int); va_end(ap); fd = real_open ? real_open(path, flags, mode) : syscall(__NR_openat, AT_FDCWD, path, flags, mode); }
    else { fd = real_open ? real_open(path, flags) : syscall(__NR_openat, AT_FDCWD, path, flags); }
    if (!g_in_hook && g_hidden && fd >= 0 && path) { enum ProcFdType t = classify_proc_path(path); if (t != FD_TYPE_NONE) add_tracked_fd(fd, t); }
    return fd;
}

int access(const char *path, int mode) {
    if (!g_in_hook && g_hidden) { g_in_hook = 1; if (!real_access) init_reals(); if (is_hidden_path(path)) { g_in_hook = 0; errno = ENOENT; return -1; } if (cfg_spoof_selinux_file && path && strcmp(path, "/sys/fs/selinux/enforce") == 0) { g_in_hook = 0; return 0; } g_in_hook = 0; }
    if (!real_access) init_reals(); if (!real_access) return syscall(__NR_faccessat, AT_FDCWD, path, mode, 0);
    return real_access(path, mode);
}

int faccessat(int dirfd, const char *path, int mode, int flags) {
    if (!g_in_hook && g_hidden) { g_in_hook = 1; if (!real_faccessat) init_reals(); if (is_hidden_path(path)) { g_in_hook = 0; errno = ENOENT; return -1; } if (cfg_spoof_selinux_file && path && strcmp(path, "/sys/fs/selinux/enforce") == 0) { g_in_hook = 0; return 0; } g_in_hook = 0; }
    if (!real_faccessat) init_reals(); if (!real_faccessat) return syscall(__NR_faccessat, dirfd, path, mode, flags);
    return real_faccessat(dirfd, path, mode, flags);
}

int stat(const char *path, struct stat *st) {
    if (!g_in_hook && g_hidden) { g_in_hook = 1; if (!real_stat) init_reals(); if (is_hidden_path(path)) { g_in_hook = 0; errno = ENOENT; return -1; } if (cfg_spoof_selinux_file && path && strcmp(path, "/sys/fs/selinux/enforce") == 0 && st) { memset(st, 0, sizeof(*st)); st->st_mode = S_IFREG|0644; st->st_size = 2; st->st_nlink = 1; g_in_hook = 0; return 0; } g_in_hook = 0; }
    if (!real_stat) init_reals(); if (!real_stat) { errno = ENOSYS; return -1; }
    return real_stat(path, st);
}

int lstat(const char *path, struct stat *st) {
    if (!g_in_hook && g_hidden) { g_in_hook = 1; if (!real_lstat) init_reals(); if (is_hidden_path(path)) { g_in_hook = 0; errno = ENOENT; return -1; } if (cfg_spoof_selinux_file && path && strcmp(path, "/sys/fs/selinux/enforce") == 0 && st) { memset(st, 0, sizeof(*st)); st->st_mode = S_IFREG|0644; st->st_size = 2; st->st_nlink = 1; g_in_hook = 0; return 0; } g_in_hook = 0; }
    if (!real_lstat) init_reals(); if (!real_lstat) { errno = ENOSYS; return -1; }
    return real_lstat(path, st);
}

int fstatat(int dirfd, const char *path, struct stat *st, int flags) {
    if (!g_in_hook && g_hidden) { g_in_hook = 1; if (!real_fstatat) init_reals(); if (is_hidden_path(path)) { g_in_hook = 0; errno = ENOENT; return -1; } if (cfg_spoof_selinux_file && path && strcmp(path, "/sys/fs/selinux/enforce") == 0 && st) { memset(st, 0, sizeof(*st)); st->st_mode = S_IFREG|0644; st->st_size = 2; st->st_nlink = 1; g_in_hook = 0; return 0; } g_in_hook = 0; }
    if (!real_fstatat) init_reals(); if (!real_fstatat) { errno = ENOSYS; return -1; }
    return real_fstatat(dirfd, path, st, flags);
}

int fstat(int fd, struct stat *st) {
    if (!real_fstat) init_reals(); if (!real_fstat) { errno = ENOSYS; return -1; }
    int r = real_fstat(fd, st);
    /* For tracked FDs pointing to proc files, ensure st_size looks normal */
    if (g_hidden && r == 0 && st) {
        enum ProcFdType type = get_tracked_fd_type(fd);
        if (type == FD_TYPE_SELINUX_ENFORCE) { st->st_size = 2; }
    }
    return r;
}

ssize_t readlink(const char *path, char *buf, size_t sz) {
    if (!g_in_hook && g_hidden) {
        g_in_hook = 1;
        if (!real_readlink) init_reals();
        if (is_hidden_path(path)) { g_in_hook = 0; errno = ENOENT; return -1; }
        if (strstr(path, "/proc/") && (strstr(path, "/cwd") || strstr(path, "/exe") || strstr(path, "/root"))) {
            const char *fake = strstr(path, "/cwd") ? "/data/local/tmp" : strstr(path, "/exe") ? "/system/bin/app_process64" : "/data";
            size_t len = strlen(fake);
            if (sz > len) { memcpy(buf, fake, len); buf[len] = 0; g_in_hook = 0; return (ssize_t)len; }
            g_in_hook = 0; errno = ENAMETOOLONG; return -1;
        }
        if (strstr(path, "/proc/") && strstr(path, "/fd/")) {
            char realpath[512];
            if (real_readlink) {
                ssize_t r = real_readlink(path, realpath, sizeof(realpath) - 1);
                if (r > 0) {
                    realpath[r] = 0;
                    if (is_hidden_path(realpath)) {
                        const char *fake = "/data/local/tmp";
                        size_t len = strlen(fake);
                        if (sz > len) { memcpy(buf, fake, len); buf[len] = 0; g_in_hook = 0; return (ssize_t)len; }
                        g_in_hook = 0; errno = ENAMETOOLONG; return -1;
                    }
                }
            }
        }
        g_in_hook = 0;
    }
    if (!real_readlink) init_reals(); if (!real_readlink) return syscall(__NR_readlinkat, AT_FDCWD, path, buf, sz);
    return real_readlink(path, buf, sz);
}

ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t sz) {
    if (!g_in_hook && g_hidden) {
        g_in_hook = 1;
        if (!real_readlinkat) init_reals();
        if (is_hidden_path(path)) { g_in_hook = 0; errno = ENOENT; return -1; }
        if (strstr(path, "/proc/") && (strstr(path, "/cwd") || strstr(path, "/exe") || strstr(path, "/root"))) {
            const char *fake = strstr(path, "/cwd") ? "/data/local/tmp" : strstr(path, "/exe") ? "/system/bin/app_process64" : "/data";
            size_t len = strlen(fake);
            if (sz > len) { memcpy(buf, fake, len); buf[len] = 0; g_in_hook = 0; return (ssize_t)len; }
            g_in_hook = 0; errno = ENAMETOOLONG; return -1;
        }
        if (strstr(path, "/proc/") && strstr(path, "/fd/")) {
            char realpath[512];
            if (real_readlinkat) {
                ssize_t r = real_readlinkat(dirfd, path, realpath, sizeof(realpath) - 1);
                if (r > 0) {
                    realpath[r] = 0;
                    if (is_hidden_path(realpath)) {
                        const char *fake = "/data/local/tmp";
                        size_t len = strlen(fake);
                        if (sz > len) { memcpy(buf, fake, len); buf[len] = 0; g_in_hook = 0; return (ssize_t)len; }
                        g_in_hook = 0; errno = ENAMETOOLONG; return -1;
                    }
                }
            }
        }
        g_in_hook = 0;
    }
    if (!real_readlinkat) init_reals(); if (!real_readlinkat) return syscall(__NR_readlinkat, dirfd, path, buf, sz);
    return real_readlinkat(dirfd, path, buf, sz);
}

struct dirent *readdir(DIR *dir) {
    if (!g_in_hook && g_hidden) { if (!real_readdir) init_reals(); if (!real_readdir) return NULL; g_in_hook = 1; struct dirent *e; while ((e = real_readdir(dir)) != NULL) { if (!is_hidden_entry(e->d_name)) { g_in_hook = 0; return e; } } g_in_hook = 0; return NULL; }
    if (!real_readdir) init_reals(); if (!real_readdir) return NULL;
    return real_readdir(dir);
}

int close(int fd) { if (fd >= 0) remove_tracked_fd(fd); if (!real_close) init_reals(); if (!real_close) return syscall(__NR_close, fd); return real_close(fd); }

ssize_t read(int fd, void *buf, size_t count) {
    if (!real_read) init_reals(); if (!real_read) return syscall(__NR_read, fd, buf, count);
    ssize_t n = real_read(fd, buf, count);
    if (!g_in_hook && g_hidden && n > 0 && buf) {
        enum ProcFdType type = get_tracked_fd_type(fd);
        if (type != FD_TYPE_NONE) {
            if (type == FD_TYPE_FD) {
                char fp[256]; fp[0] = 0;
                get_fd_path(fd, fp, sizeof(fp));
                if (fp[0] && !is_hidden_path(fp)) { g_in_hook = 0; return n; }
            }
            g_in_hook = 1; filter_proc_buffer(type, (char *)buf, &n); g_in_hook = 0;
            if (n > 0) LOGD("read: FILTERED fd=%d type=%d new_len=%zd", fd, type, n);
        }
        else { g_in_hook = 1; char fp[256]; fp[0] = 0; get_fd_path(fd, fp, sizeof(fp)); if (fp[0]) { enum ProcFdType pt = classify_proc_path(fp); if (pt != FD_TYPE_NONE) { add_tracked_fd(fd, pt); filter_proc_buffer(pt, (char *)buf, &n); } } g_in_hook = 0; }
    }
    return n;
}

ssize_t pread64(int fd, void *buf, size_t count, off64_t offset) {
    if (!real_pread64) init_reals(); if (!real_pread64) return syscall(__NR_pread64, fd, buf, count, (long)offset);
    ssize_t n = real_pread64(fd, buf, count, offset);
    if (!g_in_hook && g_hidden && n > 0 && buf) {
        enum ProcFdType type = get_tracked_fd_type(fd);
        if (type != FD_TYPE_NONE) {
            if (type == FD_TYPE_FD) {
                char fp[256]; fp[0] = 0;
                get_fd_path(fd, fp, sizeof(fp));
                if (fp[0] && !is_hidden_path(fp)) { g_in_hook = 0; return n; }
            }
            g_in_hook = 1; filter_proc_buffer(type, (char *)buf, &n); g_in_hook = 0;
        }
    }
    return n;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (!real_fread) init_reals(); if (!real_fread) return 0;
    size_t ret = real_fread(ptr, size, nmemb, stream);
    if (!g_in_hook && g_hidden && ret > 0 && stream && ptr) {
        int fd = fileno(stream); enum ProcFdType type = get_tracked_fd_type(fd);
        if (type != FD_TYPE_NONE) {
            if (type == FD_TYPE_FD) {
                char fp[256]; fp[0] = 0;
                get_fd_path(fd, fp, sizeof(fp));
                if (fp[0] && !is_hidden_path(fp)) { g_in_hook = 0; return ret; }
            }
            g_in_hook = 1; ssize_t tb = (ssize_t)(ret * size); filter_proc_buffer(type, (char *)ptr, &tb); if (size > 0) ret = (size_t)tb / size; g_in_hook = 0;
        }
    }
    return ret;
}

char *fgets(char *s, int size, FILE *stream) {
    if (!real_fgets) init_reals(); if (!real_fgets) return NULL;
    if (!stream || !s) return real_fgets(s, size, stream);
    int fd = fileno(stream); enum ProcFdType type = get_tracked_fd_type(fd);
    if (!g_in_hook && g_hidden && type != FD_TYPE_NONE) {
        g_in_hook = 1;
        if (type == FD_TYPE_FD) {
            char fp[256]; fp[0] = 0;
            get_fd_path(fd, fp, sizeof(fp));
            if (fp[0] && !is_hidden_path(fp)) { g_in_hook = 0; return real_fgets(s, size, stream); }
        }
        while (1) {
            char *res = real_fgets(s, size, stream); if (!res) { g_in_hook = 0; return NULL; }
            int hide = 0;
            if (type == FD_TYPE_MAPS && cfg_hide_maps && should_hide_maps_line(s)) hide = 1;
            else if (type == FD_TYPE_MOUNTS && cfg_hide_mounts && should_hide_mounts_line(s)) hide = 1;
            else if (type == FD_TYPE_UNIX && should_hide_unix_line(s)) hide = 1;
            if (hide) continue;
            if (type == FD_TYPE_STATUS && cfg_hide_status) { if (strncmp(s, "TracerPid:", 10) == 0) snprintf(s, size, "TracerPid:\t0\n"); }
            else if (type == FD_TYPE_SELINUX_ENFORCE && cfg_spoof_selinux_file) snprintf(s, size, "1\n");
            else if (type == FD_TYPE_ATTR_CURRENT || type == FD_TYPE_ATTR_PREV) snprintf(s, size, "u:r:untrusted_app:s0:c512,c768,c1024\n");
            else if (type == FD_TYPE_CWD) snprintf(s, size, "/data/local/tmp\n");
            else if (type == FD_TYPE_EXE) snprintf(s, size, "/system/bin/app_process64\n");
            else if (type == FD_TYPE_ROOT) snprintf(s, size, "/data\n");
            else if (type == FD_TYPE_IO) snprintf(s, size, "rchar: 1024\nwchar: 512\nsyscr: 10\nsyscw: 5\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n");
            else if (type == FD_TYPE_LIMITS) snprintf(s, size, "Max open files            1024                 1024                 files\n");
            else if (type == FD_TYPE_STAT) snprintf(s, size, "1 (com.android.systemui) S 123 123 0 0 -1 1077936448 100 0 0 0 0 0 0 0 20 0 1 0 12345678 123456 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n");
            g_in_hook = 0; return res;
        }
    }
    return real_fgets(s, size, stream);
}

ssize_t getline(char **lineptr, size_t *n, FILE *stream) {
    if (!real_getline) init_reals(); if (!real_getline) return -1;
    if (!stream || !lineptr) return real_getline(lineptr, n, stream);
    int fd = fileno(stream); enum ProcFdType type = get_tracked_fd_type(fd);
    if (!g_in_hook && g_hidden && type != FD_TYPE_NONE) {
        g_in_hook = 1;
        if (type == FD_TYPE_FD) {
            char fp[256]; fp[0] = 0;
            get_fd_path(fd, fp, sizeof(fp));
            if (fp[0] && !is_hidden_path(fp)) { g_in_hook = 0; return real_getline(lineptr, n, stream); }
        }
        while (1) {
            ssize_t res = real_getline(lineptr, n, stream); if (res < 0) { g_in_hook = 0; return -1; }
            int hide = 0;
            if (type == FD_TYPE_MAPS && cfg_hide_maps && should_hide_maps_line(*lineptr)) hide = 1;
            else if (type == FD_TYPE_MOUNTS && cfg_hide_mounts && should_hide_mounts_line(*lineptr)) hide = 1;
            else if (type == FD_TYPE_UNIX && should_hide_unix_line(*lineptr)) hide = 1;
            if (hide) continue;
            if (type == FD_TYPE_STATUS && cfg_hide_status) { if (strncmp(*lineptr, "TracerPid:", 10) == 0) { snprintf(*lineptr, *n, "TracerPid:\t0\n"); res = (ssize_t)strlen(*lineptr); } }
            else if (type == FD_TYPE_SELINUX_ENFORCE && cfg_spoof_selinux_file) { snprintf(*lineptr, *n, "1\n"); res = (ssize_t)strlen(*lineptr); }
            else if (type == FD_TYPE_ATTR_CURRENT || type == FD_TYPE_ATTR_PREV) { snprintf(*lineptr, *n, "u:r:untrusted_app:s0:c512,c768,c1024\n"); res = (ssize_t)strlen(*lineptr); }
            else if (type == FD_TYPE_CWD) { snprintf(*lineptr, *n, "/data/local/tmp\n"); res = (ssize_t)strlen(*lineptr); }
            else if (type == FD_TYPE_EXE) { snprintf(*lineptr, *n, "/system/bin/app_process64\n"); res = (ssize_t)strlen(*lineptr); }
            else if (type == FD_TYPE_ROOT) { snprintf(*lineptr, *n, "/data\n"); res = (ssize_t)strlen(*lineptr); }
            else if (type == FD_TYPE_IO) { snprintf(*lineptr, *n, "rchar: 1024\nwchar: 512\nsyscr: 10\nsyscw: 5\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n"); res = (ssize_t)strlen(*lineptr); }
            else if (type == FD_TYPE_LIMITS) { snprintf(*lineptr, *n, "Max open files            1024                 1024                 files\n"); res = (ssize_t)strlen(*lineptr); }
            else if (type == FD_TYPE_STAT) { snprintf(*lineptr, *n, "1 (com.android.systemui) S 123 123 0 0 -1 1077936448 100 0 0 0 0 0 0 0 20 0 1 0 12345678 123456 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"); res = (ssize_t)strlen(*lineptr); }
            g_in_hook = 0; return res;
        }
    }
    return real_getline(lineptr, n, stream);
}

FILE *fopen(const char *path, const char *mode) {
    if (!g_in_hook && g_hidden) { g_in_hook = 1; if (!real_fopen) init_reals(); if (is_hidden_path(path)) { g_in_hook = 0; errno = ENOENT; return NULL; } g_in_hook = 0; }
    if (!real_fopen) init_reals(); if (!real_fopen) return NULL;
    FILE *fp = real_fopen(path, mode);
    if (!g_in_hook && g_hidden && fp && path) { enum ProcFdType t = classify_proc_path(path); if (t != FD_TYPE_NONE) { int fd = fileno(fp); if (fd >= 0) add_tracked_fd(fd, t); } }
    return fp;
}

FILE *fopen64(const char *path, const char *mode) {
    if (!g_in_hook && g_hidden) { g_in_hook = 1; if (!real_fopen64) init_reals(); if (is_hidden_path(path)) { g_in_hook = 0; errno = ENOENT; return NULL; } g_in_hook = 0; }
    if (!real_fopen64) init_reals(); if (!real_fopen64) return fopen(path, mode);
    FILE *fp = real_fopen64(path, mode);
    if (!g_in_hook && g_hidden && fp && path) { enum ProcFdType t = classify_proc_path(path); if (t != FD_TYPE_NONE) { int fd = fileno(fp); if (fd >= 0) add_tracked_fd(fd, t); } }
    return fp;
}

int fclose(FILE *fp) { if (fp) { int fd = fileno(fp); if (fd >= 0) remove_tracked_fd(fd); } if (!real_fclose) init_reals(); if (!real_fclose) return -1; return real_fclose(fp); }

/* getauxval hook — AT_SECURE must be 0 for normal apps */
unsigned long getauxval(unsigned long type) {
    if (!real_getauxval) init_reals();
    if (!real_getauxval) return 0;
    if (g_hidden && cfg_spoof_auxval && type == AT_SECURE) {
        LOGD("getauxval: SPOOF AT_SECURE=0");
        return 0;
    }
    return real_getauxval(type);
}

/* __system_property_get — FIXED: 2 params + property blacklist */
int __system_property_get(const char *name, char *value) {
    if (!real_prop_get) init_reals(); if (!real_prop_get) return 0;
    if (!g_in_hook && g_hidden) {
        g_in_hook = 1;
        if (should_hide_property(name)) { LOGD("prop_get: HIDDEN %s", name); g_in_hook = 0; return 0; }
        const char *spoofed = get_spoof(name);
        if (spoofed) { LOGD("prop_get: SPOOF %s -> %s", name, spoofed); size_t len = strlen(spoofed); if (len > 91) len = 91; memcpy(value, spoofed, len); value[len] = 0; g_in_hook = 0; return (int)len; }
        g_in_hook = 0;
    }
    return real_prop_get(name, value);
}

static void prop_read_cb_interceptor(void *cookie, const char *name, const char *value, uint32_t serial) {
    struct prop_cb_wrapper_data *data = (struct prop_cb_wrapper_data *)cookie;
    const char *spoofed = get_spoof(name);
    if (!spoofed && data->prop_name) spoofed = get_spoof(data->prop_name);
    if (spoofed) data->user_cb(data->user_cookie, name, spoofed, serial);
    else data->user_cb(data->user_cookie, name, value, serial);
}

/* __system_property_find — with property blacklist */
const prop_info *__system_property_find(const char *name) {
    if (!real_prop_find) init_reals();
    if (!g_in_hook && g_hidden && name) {
        g_in_hook = 1;
        /* Hide blacklisted properties — return NULL */
        if (should_hide_property(name)) { g_in_hook = 0; return NULL; }
        if (cfg_spoof) {
            const char *spoofed = get_spoof(name);
            const prop_info *pi = real_prop_find ? real_prop_find(name) : NULL;
            if (spoofed) {
                const prop_info *tp = pi ? pi : G_DUMMY_PI;
                pthread_mutex_lock(&g_prop_mutex);
                int slot = -1;
                for (int i = 0; i < g_spoof_prop_count; i++) if (g_spoof_props[i].pi == tp) { slot = i; break; }
                if (slot < 0 && g_spoof_prop_count < MAX_SPOOF_PROPS) slot = g_spoof_prop_count++;
                if (slot >= 0) { g_spoof_props[slot].pi = tp; strncpy(g_spoof_props[slot].name, name, sizeof(g_spoof_props[slot].name)-1); g_spoof_props[slot].name[sizeof(g_spoof_props[slot].name)-1] = 0; }
                pthread_mutex_unlock(&g_prop_mutex);
                g_in_hook = 0; return tp;
            }
        }
        g_in_hook = 0;
    }
    return real_prop_find ? real_prop_find(name) : NULL;
}

void __system_property_read_callback(const prop_info *pi, void (*callback)(void *cookie, const char *name, const char *value, uint32_t serial), void *cookie) {
    if (!real_prop_read_cb) init_reals();
    if (!g_in_hook && g_hidden && cfg_spoof && pi && callback) {
        g_in_hook = 1;
        const char *mn = NULL;
        pthread_mutex_lock(&g_prop_mutex);
        for (int i = 0; i < g_spoof_prop_count; i++) if (g_spoof_props[i].pi == pi) { mn = g_spoof_props[i].name; break; }
        pthread_mutex_unlock(&g_prop_mutex);
        if (pi == G_DUMMY_PI && mn) { const char *sp = get_spoof(mn); callback(cookie, mn, sp ? sp : "", 1); g_in_hook = 0; return; }
        if (real_prop_read_cb && mn) { struct prop_cb_wrapper_data wd = { callback, cookie, mn }; real_prop_read_cb(pi, prop_read_cb_interceptor, &wd); g_in_hook = 0; return; }
        g_in_hook = 0;
    }
    if (real_prop_read_cb) real_prop_read_cb(pi, callback, cookie);
}

int uname(struct utsname *buf) {
    if (!real_uname) init_reals(); if (!real_uname) return -1;
    int r = real_uname(buf);
    if (g_hidden && cfg_spoof_kernel && r == 0 && buf) {
        LOGI("uname: SPOOF kernel %s -> %s", buf->release, s_kernel_rel);
        strncpy(buf->release, s_kernel_rel, sizeof(buf->release)-1); buf->release[sizeof(buf->release)-1] = 0;
        strncpy(buf->version, s_kernel_ver, sizeof(buf->version)-1); buf->version[sizeof(buf->version)-1] = 0;
        strncpy(buf->sysname, "Linux", sizeof(buf->sysname)-1); buf->sysname[sizeof(buf->sysname)-1] = 0;
        strncpy(buf->machine, "aarch64", sizeof(buf->machine)-1); buf->machine[sizeof(buf->machine)-1] = 0;
        strncpy(buf->nodename, "localhost", sizeof(buf->nodename)-1); buf->nodename[sizeof(buf->nodename)-1] = 0;
    }
    return r;
}

long ptrace(int request, ...) {
    if (!real_ptrace) init_reals();
    if (g_hidden && cfg_block_ptrace) {
        LOGI("ptrace: BLOCKED request=%d", request);
        if (request == 0) return 0;
        errno = ESRCH;
        return -1;
    }
    if (!real_ptrace) return -1;
    va_list ap; va_start(ap, request); pid_t pid = va_arg(ap, pid_t); void *addr = va_arg(ap, void *); void *data = va_arg(ap, void *); va_end(ap);
    return real_ptrace(request, pid, addr, data);
}

int prctl(int option, ...) {
    if (!real_prctl) init_reals(); if (!real_prctl) return -1;
    va_list ap; va_start(ap, option); unsigned long a2 = va_arg(ap, unsigned long); unsigned long a3 = va_arg(ap, unsigned long); unsigned long a4 = va_arg(ap, unsigned long); unsigned long a5 = va_arg(ap, unsigned long); va_end(ap);
    if (g_hidden && option == 4 && a2 == 1) {
        LOGD("prctl: SPOOF PR_SET_DUMPABLE -> 0");
        return real_prctl(option, 0, a3, a4, a5);
    }
    return real_prctl(option, a2, a3, a4, a5);
}

static long raw_syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6) {
    long res = -1;
#if defined(__aarch64__)
    asm volatile (
        "mov x8, %1\n"
        "mov x0, %2\n"
        "mov x1, %3\n"
        "mov x2, %4\n"
        "mov x3, %5\n"
        "mov x4, %6\n"
        "mov x5, %7\n"
        "svc 0\n"
        "mov %0, x0\n"
        : "=r"(res)
        : "r"(number), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a6)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x8", "memory"
    );
#elif defined(__x86_64__)
    asm volatile (
        "mov %1, %%rax\n"
        "mov %2, %%rdi\n"
        "mov %3, %%rsi\n"
        "mov %4, %%rdx\n"
        "mov %5, %%r10\n"
        "mov %6, %%r8\n"
        "mov %7, %%r9\n"
        "syscall\n"
        "mov %0, %%rax\n"
        : "=r"(res)
        : "g"(number), "g"(a1), "g"(a2), "g"(a3), "g"(a4), "g"(a5), "g"(a6)
        : "rcx", "r11", "memory"
    );
#elif defined(__i386__)
    asm volatile (
        "mov %1, %%eax\n"
        "mov %2, %%ebx\n"
        "mov %3, %%ecx\n"
        "mov %4, %%edx\n"
        "mov %5, %%esi\n"
        "mov %6, %%edi\n"
        "mov %7, %%ebp\n"
        "int $0x80\n"
        "mov %0, %%eax\n"
        : "=r"(res)
        : "g"(number), "g"(a1), "g"(a2), "g"(a3), "g"(a4), "g"(a5), "g"(a6)
        : "memory"
    );
#else
    res = -1;
    errno = ENOSYS;
#endif
    return res;
}

long syscall(long number, ...) {
    va_list ap; va_start(ap, number);
    long a1 = va_arg(ap, long), a2 = va_arg(ap, long), a3 = va_arg(ap, long), a4 = va_arg(ap, long), a5 = va_arg(ap, long), a6 = va_arg(ap, long);
    va_end(ap);
    if (!real_syscall && !g_in_init) init_reals();
    if (g_in_init) {
        if (!real_syscall) return raw_syscall(number, a1, a2, a3, a4, a5, a6);
        return real_syscall(number, a1, a2, a3, a4, a5, a6);
    }
    if (!real_syscall) return -1;
    if (!g_in_hook && g_hidden) {
        g_in_hook = 1;
#ifdef SYS_openat
        if (number == SYS_openat) { const char *path = (const char *)a2; if (is_hidden_path(path)) { g_in_hook = 0; errno = ENOENT; return -1; } long res = raw_syscall(number, a1, a2, a3, a4, a5, a6); if (res >= 0 && path) { enum ProcFdType t = classify_proc_path(path); if (t != FD_TYPE_NONE) add_tracked_fd((int)res, t); } g_in_hook = 0; return res; }
#endif
#ifdef SYS_open
        if (number == SYS_open) { const char *path = (const char *)a1; if (is_hidden_path(path)) { g_in_hook = 0; errno = ENOENT; return -1; } long res = raw_syscall(number, a1, a2, a3, a4, a5, a6); if (res >= 0 && path) { enum ProcFdType t = classify_proc_path(path); if (t != FD_TYPE_NONE) add_tracked_fd((int)res, t); } g_in_hook = 0; return res; }
#endif
#ifdef SYS_access
        if (number == SYS_access) { if (is_hidden_path((const char *)a1)) { g_in_hook = 0; errno = ENOENT; return -1; } }
#endif
#ifdef SYS_faccessat
        if (number == SYS_faccessat) { if (is_hidden_path((const char *)a2)) { g_in_hook = 0; errno = ENOENT; return -1; } }
#endif
#ifdef SYS_faccessat2
        if (number == SYS_faccessat2) { if (is_hidden_path((const char *)a2)) { g_in_hook = 0; errno = ENOENT; return -1; } }
#endif
#ifdef SYS_stat
        if (number == SYS_stat) { if (is_hidden_path((const char *)a1)) { g_in_hook = 0; errno = ENOENT; return -1; } }
#endif
#ifdef SYS_lstat
        if (number == SYS_lstat) { if (is_hidden_path((const char *)a1)) { g_in_hook = 0; errno = ENOENT; return -1; } }
#endif
#ifdef SYS_fstatat
        if (number == SYS_fstatat) { if (is_hidden_path((const char *)a2)) { g_in_hook = 0; errno = ENOENT; return -1; } }
#endif
#ifdef SYS_newfstatat
        if (number == SYS_newfstatat) { if (is_hidden_path((const char *)a2)) { g_in_hook = 0; errno = ENOENT; return -1; } }
#endif
#ifdef SYS_readlink
        if (number == SYS_readlink) { if (is_hidden_path((const char *)a1)) { g_in_hook = 0; errno = ENOENT; return -1; } }
#endif
#ifdef SYS_readlinkat
        if (number == SYS_readlinkat) { if (is_hidden_path((const char *)a2)) { g_in_hook = 0; errno = ENOENT; return -1; } }
#endif
#ifdef SYS_read
        if (number == SYS_read) { int fd = (int)a1; void *buf = (void *)a2; long res = raw_syscall(number, a1, a2, a3, a4, a5, a6); if (res > 0 && buf) { enum ProcFdType t = get_tracked_fd_type(fd); if (t != FD_TYPE_NONE) { ssize_t sn = res; filter_proc_buffer(t, (char *)buf, &sn); res = sn; } } g_in_hook = 0; return res; }
#endif
#ifdef SYS_pread64
        if (number == SYS_pread64) { int fd = (int)a1; void *buf = (void *)a2; long res = raw_syscall(number, a1, a2, a3, a4, a5, a6); if (res > 0 && buf) { enum ProcFdType t = get_tracked_fd_type(fd); if (t != FD_TYPE_NONE) { ssize_t sn = res; filter_proc_buffer(t, (char *)buf, &sn); res = sn; } } g_in_hook = 0; return res; }
#endif
#ifdef SYS_close
        if (number == SYS_close) remove_tracked_fd((int)a1);
#endif
#ifdef SYS_fstat
        if (number == SYS_fstat) { int fd = (int)a1; struct stat *st = (struct stat *)a2; long res = raw_syscall(number, a1, a2, a3, a4, a5, a6); if (res == 0 && st) { enum ProcFdType t = get_tracked_fd_type(fd); if (t == FD_TYPE_SELINUX_ENFORCE) st->st_size = 2; } g_in_hook = 0; return res; }
#endif
        g_in_hook = 0;
    }
    if (!real_syscall) return raw_syscall(number, a1, a2, a3, a4, a5, a6);
    return real_syscall(number, a1, a2, a3, a4, a5, a6);
}


/* ══ PLT/GOT HOOKING ══ */

struct hook_entry {
    const char *name;
    void *hook;
};

#define HOOK_COUNT 28
static struct hook_entry g_hook_table[HOOK_COUNT];
static int g_hook_table_built = 0;

static void build_hook_table(void) {
    if (g_hook_table_built) return;
    g_hook_table_built = 1;
    int i = 0;
    g_hook_table[i++] = (struct hook_entry){"openat", (void*)openat};
    g_hook_table[i++] = (struct hook_entry){"open", (void*)open};
    g_hook_table[i++] = (struct hook_entry){"access", (void*)access};
    g_hook_table[i++] = (struct hook_entry){"faccessat", (void*)faccessat};
    g_hook_table[i++] = (struct hook_entry){"stat", (void*)stat};
    g_hook_table[i++] = (struct hook_entry){"lstat", (void*)lstat};
    g_hook_table[i++] = (struct hook_entry){"fstatat", (void*)fstatat};
    g_hook_table[i++] = (struct hook_entry){"fstat", (void*)fstat};
    g_hook_table[i++] = (struct hook_entry){"readlink", (void*)readlink};
    g_hook_table[i++] = (struct hook_entry){"readlinkat", (void*)readlinkat};
    g_hook_table[i++] = (struct hook_entry){"readdir", (void*)readdir};
    g_hook_table[i++] = (struct hook_entry){"read", (void*)read};
    g_hook_table[i++] = (struct hook_entry){"close", (void*)close};
    g_hook_table[i++] = (struct hook_entry){"__system_property_get", (void*)__system_property_get};
    g_hook_table[i++] = (struct hook_entry){"__system_property_find", (void*)__system_property_find};
    g_hook_table[i++] = (struct hook_entry){"__system_property_read_callback", (void*)__system_property_read_callback};
    g_hook_table[i++] = (struct hook_entry){"uname", (void*)uname};
    g_hook_table[i++] = (struct hook_entry){"ptrace", (void*)ptrace};
    g_hook_table[i++] = (struct hook_entry){"prctl", (void*)prctl};
    g_hook_table[i++] = (struct hook_entry){"fopen", (void*)fopen};
    g_hook_table[i++] = (struct hook_entry){"fopen64", (void*)fopen64};
    g_hook_table[i++] = (struct hook_entry){"fclose", (void*)fclose};
    g_hook_table[i++] = (struct hook_entry){"fread", (void*)fread};
    g_hook_table[i++] = (struct hook_entry){"fgets", (void*)fgets};
    g_hook_table[i++] = (struct hook_entry){"getline", (void*)getline};
    g_hook_table[i++] = (struct hook_entry){"syscall", (void*)syscall};
    g_hook_table[i++] = (struct hook_entry){"pread64", (void*)pread64};
    g_hook_table[i++] = (struct hook_entry){"getauxval", (void*)getauxval};
}

static void *find_hook(const char *name) {
    for (int i = 0; i < HOOK_COUNT; i++) {
        if (g_hook_table[i].name && strcmp(g_hook_table[i].name, name) == 0)
            return g_hook_table[i].hook;
    }
    return NULL;
}

#ifndef ELF_R_SYM
#ifdef __LP64__
#define ELF_R_SYM(i) ELF64_R_SYM(i)
#else
#define ELF_R_SYM(i) ELF32_R_SYM(i)
#endif
#endif

static int g_got_patched = 0;

static void patch_one_got(ElfW(Addr) base, ElfW(Dyn) *dyn) {
    ElfW(Sym) *symtab = NULL;
    const char *strtab = NULL;
    ElfW(Addr) jmprel_addr = 0;
    size_t pltrelsz = 0;
    int pltrel_type = DT_RELA;  /* default */
    ElfW(Rela) *rela = NULL;
    size_t relasz = 0;
    ElfW(Rel) *rel = NULL;
    size_t relsz = 0;
    long pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize <= 0) pagesize = 4096;

    /* Single pass - collect all info first */
    for (ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_SYMTAB: symtab = (ElfW(Sym) *)(base + d->d_un.d_ptr); break;
            case DT_STRTAB: strtab = (const char *)(base + d->d_un.d_ptr); break;
            case DT_JMPREL: jmprel_addr = d->d_un.d_ptr; break;
            case DT_PLTRELSZ: pltrelsz = d->d_un.d_val; break;
            case DT_RELA: rela = (ElfW(Rela) *)(base + d->d_un.d_ptr); break;
            case DT_RELASZ: relasz = d->d_un.d_val; break;
            case DT_REL: rel = (ElfW(Rel) *)(base + d->d_un.d_ptr); break;
            case DT_RELSZ: relsz = d->d_un.d_val; break;
            case DT_PLTREL: pltrel_type = d->d_un.d_val; break;
        }
    }

    /* Patch PLT relocations - now using correct pltrel_type */
    if (pltrelsz > 0 && jmprel_addr && symtab && strtab) {
        if (pltrel_type == DT_RELA) {
            ElfW(Rela) *jmprel = (ElfW(Rela) *)(base + jmprel_addr);
            int n = pltrelsz / sizeof(ElfW(Rela));
            for (int i = 0; i < n; i++) {
                ElfW(Rela) *r = &jmprel[i];
                int symidx = ELF_R_SYM(r->r_info);
                if (symidx == 0) continue;
                const char *sym_name = strtab + symtab[symidx].st_name;
                if (!sym_name || !sym_name[0]) continue;
                void *hook = find_hook(sym_name);
                if (hook) {
                    void **got_entry = (void **)(base + r->r_offset);
                    void *page = (void *)((uintptr_t)got_entry & ~(pagesize - 1));
                    if (mprotect(page, pagesize * 2, PROT_READ | PROT_WRITE) == 0)
                        *got_entry = hook;
                }
            }
        } else {
            ElfW(Rel) *jmprel = (ElfW(Rel) *)(base + jmprel_addr);
            int n = pltrelsz / sizeof(ElfW(Rel));
            for (int i = 0; i < n; i++) {
                ElfW(Rel) *r = &jmprel[i];
                int symidx = ELF_R_SYM(r->r_info);
                if (symidx == 0) continue;
                const char *sym_name = strtab + symtab[symidx].st_name;
                if (!sym_name || !sym_name[0]) continue;
                void *hook = find_hook(sym_name);
                if (hook) {
                    void **got_entry = (void **)(base + r->r_offset);
                    void *page = (void *)((uintptr_t)got_entry & ~(pagesize - 1));
                    if (mprotect(page, pagesize * 2, PROT_READ | PROT_WRITE) == 0)
                        *got_entry = hook;
                }
            }
        }
    }

    /* Patch non-PLT RELA relocations */
    if (rela && relasz && symtab && strtab) {
        int n = relasz / sizeof(ElfW(Rela));
        for (int i = 0; i < n; i++) {
            ElfW(Rela) *r = &rela[i];
            int symidx = ELF_R_SYM(r->r_info);
            if (symidx == 0) continue;
            const char *sym_name = strtab + symtab[symidx].st_name;
            if (!sym_name || !sym_name[0]) continue;
            void *hook = find_hook(sym_name);
            if (hook) {
                void **got_entry = (void **)(base + r->r_offset);
                void *page = (void *)((uintptr_t)got_entry & ~(pagesize - 1));
                if (mprotect(page, pagesize * 2, PROT_READ | PROT_WRITE) == 0)
                    *got_entry = hook;
            }
        }
    }

    /* Patch non-PLT REL relocations (32-bit) */
    if (rel && relsz && symtab && strtab) {
        int n = relsz / sizeof(ElfW(Rel));
        for (int i = 0; i < n; i++) {
            ElfW(Rel) *r = &rel[i];
            int symidx = ELF_R_SYM(r->r_info);
            if (symidx == 0) continue;
            const char *sym_name = strtab + symtab[symidx].st_name;
            if (!sym_name || !sym_name[0]) continue;
            void *hook = find_hook(sym_name);
            if (hook) {
                void **got_entry = (void **)(base + r->r_offset);
                void *page = (void *)((uintptr_t)got_entry & ~(pagesize - 1));
                if (mprotect(page, pagesize * 2, PROT_READ | PROT_WRITE) == 0)
                    *got_entry = hook;
            }
        }
    }
}

static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size; (void)data;

    /* Skip our own module */
    if (info->dlpi_name && strstr(info->dlpi_name, "stealth"))
        return 0;

    /* Find PT_DYNAMIC segment */
    ElfW(Dyn) *dyn = NULL;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = (ElfW(Dyn) *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;

    patch_one_got(info->dlpi_addr, dyn);
    return 0;
}

static void install_zygisk_plt_hooks(void) {
    if (!g_api) return;
    if (!g_api->pltHookRegister || !g_api->pltHookCommit) return;

    /* dev=0, ino=0 means hook ALL libraries */
    g_api->pltHookRegister(0, 0, "openat", (void*)openat, (void**)&real_openat);
    g_api->pltHookRegister(0, 0, "open", (void*)open, (void**)&real_open);
    g_api->pltHookRegister(0, 0, "access", (void*)access, (void**)&real_access);
    g_api->pltHookRegister(0, 0, "faccessat", (void*)faccessat, (void**)&real_faccessat);
    g_api->pltHookRegister(0, 0, "stat", (void*)stat, (void**)&real_stat);
    g_api->pltHookRegister(0, 0, "lstat", (void*)lstat, (void**)&real_lstat);
    g_api->pltHookRegister(0, 0, "fstatat", (void*)fstatat, (void**)&real_fstatat);
    g_api->pltHookRegister(0, 0, "fstat", (void*)fstat, (void**)&real_fstat);
    g_api->pltHookRegister(0, 0, "readlink", (void*)readlink, (void**)&real_readlink);
    g_api->pltHookRegister(0, 0, "readlinkat", (void*)readlinkat, (void**)&real_readlinkat);
    g_api->pltHookRegister(0, 0, "readdir", (void*)readdir, (void**)&real_readdir);
    g_api->pltHookRegister(0, 0, "read", (void*)read, (void**)&real_read);
    g_api->pltHookRegister(0, 0, "close", (void*)close, (void**)&real_close);
    g_api->pltHookRegister(0, 0, "__system_property_get", (void*)__system_property_get, (void**)&real_prop_get);
    g_api->pltHookRegister(0, 0, "__system_property_find", (void*)__system_property_find, (void**)&real_prop_find);
    g_api->pltHookRegister(0, 0, "__system_property_read_callback", (void*)__system_property_read_callback, (void**)&real_prop_read_cb);
    g_api->pltHookRegister(0, 0, "uname", (void*)uname, (void**)&real_uname);
    g_api->pltHookRegister(0, 0, "ptrace", (void*)ptrace, (void**)&real_ptrace);
    g_api->pltHookRegister(0, 0, "prctl", (void*)prctl, (void**)&real_prctl);
    g_api->pltHookRegister(0, 0, "fopen", (void*)fopen, (void**)&real_fopen);
    g_api->pltHookRegister(0, 0, "fopen64", (void*)fopen64, (void**)&real_fopen64);
    g_api->pltHookRegister(0, 0, "fclose", (void*)fclose, (void**)&real_fclose);
    g_api->pltHookRegister(0, 0, "fread", (void*)fread, (void**)&real_fread);
    g_api->pltHookRegister(0, 0, "fgets", (void*)fgets, (void**)&real_fgets);
    g_api->pltHookRegister(0, 0, "getline", (void*)getline, (void**)&real_getline);
    g_api->pltHookRegister(0, 0, "syscall", (void*)syscall, (void**)&real_syscall);
    g_api->pltHookRegister(0, 0, "pread64", (void*)pread64, (void**)&real_pread64);
    g_api->pltHookRegister(0, 0, "getauxval", (void*)getauxval, (void**)&real_getauxval);

    g_api->pltHookCommit();
}

static void install_got_hooks(void) {
    if (g_got_patched) return;
    g_got_patched = 1;
    build_hook_table();

    /* Primary: Zygisk PLT hook API */
    if (g_api && g_api->pltHookRegister && g_api->pltHookCommit) {
        LOGI("install_got_hooks: using Zygisk PLT hooks");
        install_zygisk_plt_hooks();
    } else {
        LOGI("install_got_hooks: Zygisk PLT not available, using dl_iterate fallback");
    }

    /* Fallback: manual GOT patching */
    dl_iterate_phdr(phdr_callback, NULL);
    LOGI("install_got_hooks: done");
}

/* ══ ZYGISK ENTRY ══ */

static struct zygisk_module_abi g_module_abi = {
    .api_version = ZYGISK_API_VERSION, .impl = NULL,
    .preAppSpecialize = NULL, .postAppSpecialize = NULL,
    .preServerSpecialize = NULL, .postServerSpecialize = NULL,
};

static void c_preAppSpecialize(void *impl, void *args) {
    (void)impl; (void)args;
    LOGI("preAppSpecialize: start");
    init_reals();
    load_config();
    /* Use Zygisk getFlags() for root detection - much more reliable than reading DB */
    if (g_api && g_api->getFlags) {
        g_zygisk_flags = g_api->getFlags(g_api->impl);
    }
    LOGI("preAppSpecialize: flags=%u", g_zygisk_flags);
}
static void c_postAppSpecialize(void *impl, const void *args) { (void)impl; (void)args; determine_hidden(); if (g_hidden) install_got_hooks(); }
static void c_preServerSpecialize(void *impl, void *args) { (void)impl; (void)args; }
static void c_postServerSpecialize(void *impl, const void *args) { (void)impl; (void)args; }

__attribute__((visibility("default")))
void zygisk_module_entry(struct zygisk_api_table *table, void *env) {
    LOGI("=== MODULE ENTRY START ===");
    if (!table || !table->registerModule) {
        LOGE("module_entry: invalid table");
        return;
    }
    g_api = table;
    g_module_abi.preAppSpecialize = c_preAppSpecialize;
    g_module_abi.postAppSpecialize = c_postAppSpecialize;
    g_module_abi.preServerSpecialize = c_preServerSpecialize;
    g_module_abi.postServerSpecialize = c_postServerSpecialize;
    table->registerModule(table, &g_module_abi);
    LOGI("module_entry: registered callbacks successfully");
    (void)env;
}
