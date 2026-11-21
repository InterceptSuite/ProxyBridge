package com.interceptsuite.proxybridge.vpn;

import android.os.Handler;
import android.os.Looper;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/** What the tunnel is doing, for the screens. The service and the screens run in the same process. */
public final class TunnelState {
    public enum Status {
        OFF,
        STARTING,
        ON
    }

    public interface Listener {
        void onTunnelChanged();
    }

    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static final List<Listener> LISTENERS = new CopyOnWriteArrayList<>();
    private static volatile Status status = Status.OFF;
    private static volatile String error;

    private TunnelState() {
    }

    public static Status status() {
        return status;
    }

    /** Why the last start failed, or null. */
    public static String error() {
        return error;
    }

    static void set(Status newStatus, String newError) {
        status = newStatus;
        error = newError;
        MAIN.post(() -> {
            for (Listener listener : LISTENERS) {
                listener.onTunnelChanged();
            }
        });
    }

    public static void addListener(Listener listener) {
        LISTENERS.add(listener);
    }

    public static void removeListener(Listener listener) {
        LISTENERS.remove(listener);
    }
}
