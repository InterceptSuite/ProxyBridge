package com.interceptsuite.proxybridge.ui;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;

final class Links {
    static final String WEBSITE = "https://proxybridge.interceptsuite.com/";
    static final String GITHUB = "https://github.com/InterceptSuite/ProxyBridge";
    static final String PRIVACY_POLICY = "https://proxybridge.interceptsuite.com/privacy/";

    private Links() {
    }

    static void open(Context context, String url) {
        context.startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
    }
}
