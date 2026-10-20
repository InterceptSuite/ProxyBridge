#include "gui_boot.h"
#include "pb_unit.h"
#include <fcntl.h>
#include <glib/gstdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#define UNIT_NAME "proxybridge.service"

static const char *unit_dir() {
#ifdef PB_TEST_HOOKS
    const char *e = getenv("PROXYBRIDGE_SYSTEMD_DIR");      // tests only
    if (e && *e) return e;
#endif
    return "/etc/systemd/system";
}

static const char *systemctl_cmd() {
#ifdef PB_TEST_HOOKS
    const char *e = getenv("PROXYBRIDGE_SYSTEMCTL");
    if (e && *e) return e;
#endif
    return "systemctl";
}

static char *unit_path() { return g_strdup_printf("%s/" UNIT_NAME, unit_dir()); }

// A program that systemd will start as root at every boot must not be replaceable by an ordinary user: the file and
// every directory above it have to belong to root and be writable by root only. A copy run from ~/Downloads fails this.
bool boot_path_trusted(const char *path, char **why) {
    if (!path || path[0] != '/') { if (why) *why = g_strdup("not an absolute path"); return false; }
    char *cur = g_strdup(path);
    for (;;) {
        struct stat st;
        if (lstat(cur, &st) != 0) { if (why) *why = g_strdup_printf("%s: %s", cur, g_strerror(errno)); g_free(cur); return false; }
        bool file = !strcmp(cur, path);
        if (S_ISLNK(st.st_mode) || (file ? !S_ISREG(st.st_mode) : !S_ISDIR(st.st_mode))) {
            if (why) *why = g_strdup_printf("%s is a symbolic link or not a regular %s", cur, file ? "file" : "directory");
            g_free(cur); return false;
        }
        if (st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH))) {
            if (why) *why = g_strdup_printf("%s is not owned by root or is writable by other users", cur);
            g_free(cur); return false;
        }
        if (!strcmp(cur, "/")) break;
        char *up = g_path_get_dirname(cur);
        g_free(cur); cur = up;
    }
    g_free(cur);
    return true;
}

// The command line program that sits next to this one (an installed pair), otherwise the default install location.
static char *cli_path(char **error) {
#ifdef PB_TEST_HOOKS
    const char *e = getenv("PROXYBRIDGE_CLI");
    if (e && *e) return g_strdup(e);
#endif
    char self[4096];
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    char *cli = NULL;
    if (n > 0) {
        self[n] = 0;
        char *dir = g_path_get_dirname(self);
        cli = g_build_filename(dir, "ProxyBridge", NULL);
        g_free(dir);
        if (!g_file_test(cli, G_FILE_TEST_IS_EXECUTABLE)) { g_free(cli); cli = NULL; }
    }
    if (!cli) cli = g_strdup("/usr/local/bin/ProxyBridge");
    char *why = NULL;
    if (!boot_path_trusted(cli, &why)) {
        if (error) *error = g_strdup_printf("%s cannot be started at boot: %s. Install ProxyBridge with setup.sh and start the GUI from there.", cli, why);
        g_free(why); g_free(cli);
        return NULL;
    }
    return cli;
}

char *boot_unit_text(const char *cli, char **error) {
    const char *why = NULL;
    char *text = pb_unit_text(cli, &why);
    if (!text) {
        if (error) *error = g_strdup(why ? why : "cannot build the unit");
        return NULL;
    }
    char *out = g_strdup(text);
    free(text);
    return out;
}

bool boot_is_enabled(void) {
    char *path = unit_path();
    bool yes = g_file_test(path, G_FILE_TEST_IS_REGULAR);
    g_free(path);
    return yes;
}

static bool run_systemctl(const char *a, const char *b, char **error) {
    char *argv[] = { (char *)systemctl_cmd(), (char *)a, (char *)b, NULL };
    char *err_out = NULL;
    int status = 0;
    GError *gerr = NULL;
    if (!g_spawn_sync(NULL, argv, NULL, G_SPAWN_SEARCH_PATH | G_SPAWN_STDOUT_TO_DEV_NULL, NULL, NULL, NULL, &err_out, &status, &gerr)) {
        if (error) *error = g_strdup_printf("could not run %s: %s", systemctl_cmd(), gerr ? gerr->message : "unknown error");
        if (gerr) g_error_free(gerr);
        return false;
    }
    bool ok = g_spawn_check_wait_status(status, NULL);
    if (!ok && error) {
        g_strstrip(err_out ? err_out : (char *)"");
        *error = g_strdup_printf("systemctl %s %s failed%s%s", a, b ? b : "", err_out && *err_out ? ": " : "", err_out ? err_out : "");
    }
    g_free(err_out);
    return ok;
}

static bool write_unit(char **error) {
    char *cli = cli_path(error);
    if (!cli) return false;
    char *text = boot_unit_text(cli, error);
    g_free(cli);
    if (!text) return false;
    char *path = unit_path(), *tmp = g_strdup_printf("%s.tmp", path);
    bool ok = false;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
    if (fd >= 0) {
        size_t n = strlen(text), off = 0;
        while (off < n) {
            ssize_t w = write(fd, text + off, n - off);
            if (w <= 0) break;
            off += (size_t)w;
        }
        ok = off == n && close(fd) == 0 && rename(tmp, path) == 0;
        if (!ok) g_unlink(tmp);
    }
    if (!ok && error) *error = g_strdup_printf("cannot write %s: %s", path, g_strerror(errno));
    g_free(tmp); g_free(path); g_free(text);
    return ok;
}

bool boot_set(bool enable, char **error) {
    if (error) *error = NULL;
    if (enable) {
        if (!write_unit(error)) return false;
        if (!run_systemctl("daemon-reload", NULL, error) || !run_systemctl("enable", UNIT_NAME, error)) {
            char *path = unit_path();
            g_unlink(path);                          // do not leave a unit behind that is not enabled
            g_free(path);
            return false;
        }
        return true;
    }
    char *path = unit_path();
    bool existed = g_file_test(path, G_FILE_TEST_EXISTS);
    bool ok = !existed || run_systemctl("disable", UNIT_NAME, error);
    if (ok && existed && g_unlink(path) != 0) {
        if (error) *error = g_strdup_printf("cannot remove %s: %s", path, g_strerror(errno));
        ok = false;
    }
    if (ok && existed) run_systemctl("daemon-reload", NULL, NULL);
    g_free(path);
    return ok;
}
