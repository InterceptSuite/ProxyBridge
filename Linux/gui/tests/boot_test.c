// Unit test of gui_boot.c: the systemd unit "Start at boot" writes, with a fake systemctl. Needs no root.
#include "../gui_boot.h"
#include <glib/gstdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int checks, fails;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)

static char *slurp(const char *path)
{
    char *s = NULL;
    if (!g_file_get_contents(path, &s, NULL, NULL)) s = g_strdup("");
    return s;
}

int main(void)
{
    char *dir = g_dir_make_tmp("pbboot-XXXXXX", NULL);
    char *units = g_build_filename(dir, "units", NULL), *calls = g_build_filename(dir, "calls.log", NULL), *fake = g_build_filename(dir, "systemctl", NULL);
    g_mkdir_with_parents(units, 0755);
    char *script = g_strdup_printf("#!/bin/sh\necho \"$@\" >> %s\n[ \"$FAKE_FAIL\" = \"$1\" ] && { echo \"boom: $1\" >&2; exit 1; }\nexit 0\n", calls);
    g_file_set_contents(fake, script, -1, NULL);
    chmod(fake, 0755);
    setenv("PROXYBRIDGE_SYSTEMD_DIR", units, 1);
    setenv("PROXYBRIDGE_SYSTEMCTL", fake, 1);
    setenv("PROXYBRIDGE_CLI", "/opt/pb dir/ProxyBridge", 1);
    char *unit = g_build_filename(units, "proxybridge.service", NULL);
    char *err = NULL;
    char *t;

    // unit text
    t = boot_unit_text("x/ProxyBridge", &err);                                                // a relative path would resolve against the service's cwd
    CHECK(t == NULL && err && strstr(err, "absolute"));
    g_free(err); err = NULL;
    t = boot_unit_text("/usr/local/bin/ProxyBridge", &err);
    CHECK(t && strstr(t, "LimitNOFILE=1048576") && strstr(t, "NoNewPrivileges=yes") && strstr(t, "ProtectSystem=strict") && strstr(t, "ProtectHome=yes") &&
          strstr(t, "RuntimeDirectory=proxybridge") && strstr(t, "ReadWritePaths=/etc/proxybridge\n") &&
          strstr(t, "CapabilityBoundingSet=CAP_BPF ") && strstr(t, "RestrictAddressFamilies=") && strstr(t, "MemoryDenyWriteExecute=yes") && strstr(t, "UMask=0077"));
    g_free(t);

    // only root-owned, root-writable-only paths may be started at boot
    char *why = NULL;
    CHECK(!boot_path_trusted(fake, &why) && why && strstr(why, "owned by root"));            // our own temp file
    g_free(why); why = NULL;
    CHECK(!boot_path_trusted("relative/ProxyBridge", &why) && why); g_free(why); why = NULL;
    CHECK(!boot_path_trusted("/nonexistent/ProxyBridge", &why) && why); g_free(why); why = NULL;
    if (access("/usr/bin/true", X_OK) == 0) CHECK(boot_path_trusted("/usr/bin/true", &why) && why == NULL);
    char *lnk = g_build_filename(dir, "lnk", NULL);
    CHECK(symlink("/usr/bin/true", lnk) == 0 && !boot_path_trusted(lnk, &why)); g_free(why); why = NULL; g_free(lnk);

    t = boot_unit_text("/usr/local/bin/ProxyBridge", &err);
    CHECK(t && strstr(t, "ExecStart=\"/usr/local/bin/ProxyBridge\" --daemon\n") && strstr(t, "WantedBy=multi-user.target") &&
          strstr(t, "After=network-online.target") && strstr(t, "Restart=on-failure") && !strstr(t, "--profile"));
    g_free(t);
    t = boot_unit_text("/x/a \"b\" \\c %h $HOME/ProxyBridge", &err);
    CHECK(t && strstr(t, "ExecStart=\"/x/a \\\"b\\\" \\\\c %%h $$HOME/ProxyBridge\" --daemon\n"));            // quoting that systemd understands
    g_free(t);
    t = boot_unit_text("/x/Proxy\nBridge", &err);
    CHECK(t == NULL && err && strstr(err, "control characters"));
    g_free(err); err = NULL;
    t = boot_unit_text("/x/Proxy\tBridge", &err);
    CHECK(t == NULL);
    g_free(err); err = NULL;

    // enable
    CHECK(!boot_is_enabled());
    CHECK(boot_set(true, &err) && err == NULL);
    CHECK(boot_is_enabled());
    char *content = slurp(unit);
    CHECK(strstr(content, "ExecStart=\"/opt/pb dir/ProxyBridge\" --daemon\n"));       // a path with a space is quoted
    struct stat st;
    CHECK(stat(unit, &st) == 0 && (st.st_mode & 0777) == 0644);
    char *log = slurp(calls);
    CHECK(strstr(log, "daemon-reload") && strstr(log, "enable proxybridge.service"));
    g_free(content); g_free(log);

    // disable
    g_unlink(calls);
    CHECK(boot_set(false, &err));
    CHECK(!boot_is_enabled());
    log = slurp(calls);
    CHECK(strstr(log, "disable proxybridge.service") && strstr(log, "daemon-reload"));
    g_free(log);
    g_unlink(calls);
    CHECK(boot_set(false, &err));                                                     // disabling twice is fine and runs nothing
    log = slurp(calls);
    CHECK(strlen(log) == 0);
    g_free(log);

    // a failing systemctl: report it and leave no unit behind
    setenv("FAKE_FAIL", "enable", 1);
    CHECK(!boot_set(true, &err) && err && strstr(err, "systemctl enable") && strstr(err, "boom"));
    CHECK(!boot_is_enabled());
    g_free(err); err = NULL;
    setenv("FAKE_FAIL", "daemon-reload", 1);
    CHECK(!boot_set(true, &err) && err && strstr(err, "daemon-reload"));
    CHECK(!boot_is_enabled());
    g_free(err); err = NULL;
    unsetenv("FAKE_FAIL");
    CHECK(boot_set(true, &err));
    setenv("FAKE_FAIL", "disable", 1);
    CHECK(!boot_set(false, &err) && err && strstr(err, "disable"));
    CHECK(boot_is_enabled());                                                                 // still enabled: the disable failed
    g_free(err); err = NULL;
    unsetenv("FAKE_FAIL");
    CHECK(boot_set(false, &err));

    // systemctl missing, and a directory that cannot be written
    setenv("PROXYBRIDGE_SYSTEMCTL", "/nonexistent/systemctl", 1);
    CHECK(!boot_set(true, &err) && err && strstr(err, "could not run"));
    CHECK(!boot_is_enabled());
    g_free(err); err = NULL;
    setenv("PROXYBRIDGE_SYSTEMCTL", fake, 1);
    setenv("PROXYBRIDGE_SYSTEMD_DIR", "/nonexistent/dir", 1);
    CHECK(!boot_set(true, &err) && err && strstr(err, "cannot write"));
    g_free(err); err = NULL;
    g_free(err);

    char *cmd = g_strdup_printf("rm -rf %s", dir);
    CHECK(system(cmd) == 0);
    g_free(cmd); g_free(dir); g_free(units); g_free(calls); g_free(fake); g_free(script); g_free(unit);
    printf("boot_test: %d checks, %d failed\n", checks, fails);
    return fails != 0;
}
