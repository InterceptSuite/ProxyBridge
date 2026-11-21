package com.interceptsuite.proxybridge.ui;

import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import com.google.android.material.button.MaterialButtonToggleGroup;
import com.google.android.material.materialswitch.MaterialSwitch;
import com.interceptsuite.proxybridge.R;
import com.interceptsuite.proxybridge.data.ConfigStore;
import com.interceptsuite.proxybridge.model.AppConfig;
import com.interceptsuite.proxybridge.model.ProxyConfig;
import com.interceptsuite.proxybridge.model.ProxyKind;

public final class ProxyEditorActivity extends EditorActivity {
    private ProxyConfig proxy;
    private EditText name;
    private EditText host;
    private EditText port;
    private EditText username;
    private EditText password;
    private MaterialSwitch sendHostname;

    @Override
    int addTitle() {
        return R.string.proxy_add;
    }

    @Override
    int editTitle() {
        return R.string.proxy_edit;
    }

    @Override
    int formLayout() {
        return R.layout.form_proxy;
    }

    @Override
    void bind(View form, String id) {
        ProxyConfig existing = id == null ? null : store().config().proxy(id);
        proxy = existing == null ? new ProxyConfig() : existing.copy();

        name = form.findViewById(R.id.name);
        host = form.findViewById(R.id.host);
        port = form.findViewById(R.id.port);
        username = form.findViewById(R.id.username);
        password = form.findViewById(R.id.password);
        sendHostname = form.findViewById(R.id.send_hostname);
        name.setText(proxy.name);
        host.setText(proxy.host);
        port.setText(String.valueOf(proxy.port));
        username.setText(proxy.username);
        password.setText(proxy.password);
        sendHostname.setChecked(proxy.sendHostname);

        MaterialButtonToggleGroup kind = form.findViewById(R.id.kind);
        ProxyKind[] kinds = ProxyKind.values();
        String[] labels = new String[kinds.length];
        for (int i = 0; i < kinds.length; i++) {
            labels[i] = kinds[i].name();
        }
        Toggles.fill(kind, labels, proxy.kind.ordinal(), index -> proxy.kind = kinds[index]);
    }

    @Override
    boolean save(ConfigStore store) {
        int portNumber = parsePort(port.getText().toString());
        String hostName = host.getText().toString().trim();
        if (hostName.isEmpty() || portNumber < 0) {
            Toast.makeText(this, R.string.proxy_invalid, Toast.LENGTH_SHORT).show();
            return false;
        }
        proxy.name = name.getText().toString().trim();
        proxy.host = hostName;
        proxy.port = portNumber;
        proxy.username = username.getText().toString();
        proxy.password = password.getText().toString();
        proxy.sendHostname = sendHostname.isChecked();
        store.update(config -> upsert(config.proxies, proxy, item -> item.id));
        return true;
    }

    @Override
    void delete(AppConfig config, String id) {
        config.removeProxy(id);
    }

    /** The port, or -1 when the text is not a number from 1 to 65535. */
    private static int parsePort(String text) {
        try {
            int value = Integer.parseInt(text.trim());
            return value >= 1 && value <= 65535 ? value : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
