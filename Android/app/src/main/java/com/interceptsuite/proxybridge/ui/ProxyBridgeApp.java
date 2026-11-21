package com.interceptsuite.proxybridge.ui;

import android.app.Application;

import com.google.android.material.color.DynamicColors;

public final class ProxyBridgeApp extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        DynamicColors.applyToActivitiesIfAvailable(this);
    }
}
