package com.interceptsuite.proxybridge.data;

import android.content.Context;
import android.content.SharedPreferences;

public final class Prefs {
    private static final String FILE = "settings";
    private static final String DISCLOSURE_VERSION = "acceptedDisclosureVersion";

    private Prefs() {
    }

    public static boolean disclosureAccepted(Context context, int currentVersion) {
        return preferences(context).getInt(DISCLOSURE_VERSION, 0) >= currentVersion;
    }

    public static void acceptDisclosure(Context context, int version) {
        preferences(context).edit().putInt(DISCLOSURE_VERSION, version).apply();
    }

    private static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }
}
