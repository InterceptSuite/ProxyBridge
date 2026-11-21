package com.interceptsuite.proxybridge.vpn;

import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import com.interceptsuite.proxybridge.R;
import com.interceptsuite.proxybridge.data.ConfigStore;
import com.interceptsuite.proxybridge.model.AppConfig;
import com.interceptsuite.proxybridge.model.AppMode;
import com.interceptsuite.proxybridge.router.Router;
import com.interceptsuite.proxybridge.router.TunnelNetwork;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Builds the tunnel and starts the two halves that run in it: the router, which applies the rules, and hev, which turns
 * the device's packets into connections for the router.
 */
public final class ProxyVpnService extends VpnService implements ConfigStore.Listener {
    public static final String ACTION_STOP = "com.interceptsuite.proxybridge.STOP";

    private ParcelFileDescriptor tunnel;
    private Router router;
    private String appSelection;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopTunnel();
            stopSelf();
        } else {
            startTunnel();
        }
        return START_NOT_STICKY;
    }

    @Override
    public void onRevoke() {
        stopTunnel();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        stopTunnel();
        super.onDestroy();
    }

    /** The router takes new rules at once. A change to the chosen apps needs a new tunnel. */
    @Override
    public void onConfigChanged() {
        AppConfig config = ConfigStore.get(this).config();
        if (router == null) {
            return;
        }
        if (Objects.equals(appSelection, selection(config))) {
            router.update(config);
        } else {
            stopTunnel();
            startTunnel();
        }
    }

    private void startTunnel() {
        if (tunnel != null) {
            return;
        }
        TunnelState.set(TunnelState.Status.STARTING, null);
        ConfigStore store = ConfigStore.get(this);
        AppConfig config = store.config();
        try {
            router = new Router(config, UpstreamDns.servers(this));
            int port = router.start();
            tunnel = establish(config);
            if (tunnel == null) {
                throw new IOException(getString(R.string.error_permission));
            }
            if (!HevTunnel.start(writeHevConfig(port), tunnel.getFd())) {
                throw new IOException(getString(R.string.error_hev));
            }
            appSelection = selection(config);
            store.addListener(this);
            TunnelState.set(TunnelState.Status.ON, null);
        } catch (IOException | RuntimeException e) {
            stopTunnel();
            TunnelState.set(TunnelState.Status.OFF, e.getMessage());
            stopSelf();
        }
    }

    private void stopTunnel() {
        ConfigStore.get(this).removeListener(this);
        if (tunnel != null) {
            HevTunnel.stop();
            try {
                tunnel.close();
            } catch (IOException ignored) {
                // the device is closed with the process anyway
            }
            tunnel = null;
        }
        if (router != null) {
            router.close();
            router = null;
        }
        appSelection = null;
        TunnelState.set(TunnelState.Status.OFF, null);
    }

    /** Which apps are in the tunnel, as one string, to tell whether a config change needs a new tunnel. */
    private static String selection(AppConfig config) {
        return config.appMode + ":" + config.packages;
    }

    private ParcelFileDescriptor establish(AppConfig config) throws IOException {
        Builder builder = new Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(TunnelNetwork.MTU)
                .addAddress(TunnelNetwork.ADDRESS, TunnelNetwork.PREFIX_LENGTH)
                .addAddress(TunnelNetwork.ADDRESS_V6, TunnelNetwork.PREFIX_LENGTH_V6)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer(TunnelNetwork.DNS_SERVER);
        addApps(builder, config);
        return builder.establish();
    }

    /**
     * Chooses the apps whose traffic enters the tunnel. This app is always left out, so the router's own connections
     * to the proxies cannot loop back into it.
     */
    private void addApps(Builder builder, AppConfig config) throws IOException {
        try {
            if (config.appMode == AppMode.ONLY_SELECTED) {
                int added = 0;
                for (String name : config.packages) {
                    if (!name.equals(getPackageName()) && allow(builder, name)) {
                        added++;
                    }
                }
                if (added == 0) {
                    throw new IOException(getString(R.string.error_no_apps));
                }
                return;
            }
            builder.addDisallowedApplication(getPackageName());
            if (config.appMode == AppMode.ALL_EXCEPT_SELECTED) {
                for (String name : config.packages) {
                    disallow(builder, name);
                }
            }
        } catch (PackageManager.NameNotFoundException e) {
            throw new IOException(e);
        }
    }

    private static boolean allow(Builder builder, String name) {
        try {
            builder.addAllowedApplication(name);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private static void disallow(Builder builder, String name) {
        try {
            builder.addDisallowedApplication(name);
        } catch (PackageManager.NameNotFoundException ignored) {
            // an app that was removed since it was chosen needs no exception
        }
    }

    private File writeHevConfig(int routerPort) throws IOException {
        String yaml = "tunnel:\n"
                + "  mtu: " + TunnelNetwork.MTU + "\n"
                + "socks5:\n"
                + "  address: 127.0.0.1\n"
                + "  port: " + routerPort + "\n"
                + "  udp: 'udp'\n"
                + "misc:\n"
                + "  task-stack-size: 24576\n"
                + "  tcp-buffer-size: 4096\n"
                + "  max-session-count: 1200\n";
        File file = new File(getCacheDir(), "hev.yml");
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(yaml.getBytes(StandardCharsets.UTF_8));
        }
        return file;
    }
}
