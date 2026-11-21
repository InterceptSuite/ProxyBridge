package com.interceptsuite.proxybridge.ui;

import android.content.Intent;
import android.widget.TextView;

import com.interceptsuite.proxybridge.R;
import com.interceptsuite.proxybridge.model.AppConfig;
import com.interceptsuite.proxybridge.model.ProxyConfig;

import java.util.List;

public final class ProxiesFragment extends EditableListFragment<ProxyConfig> {
    @Override
    int titleRes() {
        return R.string.proxies_title;
    }

    @Override
    int emptyRes() {
        return R.string.proxies_empty;
    }

    @Override
    int footerRes() {
        return R.string.proxies_footer;
    }

    @Override
    List<ProxyConfig> items(AppConfig config) {
        return config.proxies;
    }

    @Override
    void bind(ProxyConfig proxy, TextView title, TextView subtitle) {
        title.setText(proxy.displayName());
        subtitle.setText(proxy.kind + ", " + proxy.host + ":" + proxy.port);
    }

    @Override
    void open(ProxyConfig proxy) {
        Intent intent = new Intent(requireContext(), ProxyEditorActivity.class);
        if (proxy != null) {
            intent.putExtra(EditorActivity.EXTRA_ID, proxy.id);
        }
        startActivity(intent);
    }

    @Override
    void remove(AppConfig config, ProxyConfig proxy) {
        config.removeProxy(proxy.id);
    }
}
