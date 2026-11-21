package com.interceptsuite.proxybridge.ui;

import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.Spinner;

import com.google.android.material.materialswitch.MaterialSwitch;
import com.interceptsuite.proxybridge.R;
import com.interceptsuite.proxybridge.data.ConfigStore;
import com.interceptsuite.proxybridge.model.AppConfig;
import com.interceptsuite.proxybridge.model.ProxyConfig;
import com.interceptsuite.proxybridge.model.ProxyKind;
import com.interceptsuite.proxybridge.model.ProxyRule;
import com.interceptsuite.proxybridge.model.RuleAction;
import com.interceptsuite.proxybridge.model.RuleProtocol;

import java.util.ArrayList;
import java.util.List;

public final class RuleEditorActivity extends EditorActivity {
    private ProxyRule rule;
    private EditText name;
    private EditText hosts;
    private EditText ports;
    private MaterialSwitch enabled;
    private Spinner proxy;
    private View proxySection;
    private View httpUdp;

    @Override
    int addTitle() {
        return R.string.rule_add;
    }

    @Override
    int editTitle() {
        return R.string.rule_edit;
    }

    @Override
    int formLayout() {
        return R.layout.form_rule;
    }

    @Override
    void bind(View form, String id) {
        ProxyRule existing = id == null ? null : store().config().rules.stream()
                .filter(item -> item.id.equals(id)).findFirst().orElse(null);
        rule = existing == null ? new ProxyRule() : existing.copy();

        name = form.findViewById(R.id.name);
        hosts = form.findViewById(R.id.hosts);
        ports = form.findViewById(R.id.ports);
        enabled = form.findViewById(R.id.enabled);
        proxy = form.findViewById(R.id.proxy);
        proxySection = form.findViewById(R.id.proxy_section);
        httpUdp = form.findViewById(R.id.http_udp);
        name.setText(rule.name);
        hosts.setText(rule.hosts);
        ports.setText(rule.ports);
        enabled.setChecked(rule.enabled);

        Toggles.fill(form.findViewById(R.id.protocol), Labels.protocols(this), rule.protocol.ordinal(), index -> {
            rule.protocol = RuleProtocol.values()[index];
            updateProxySection();
        });
        Toggles.fill(form.findViewById(R.id.action), Labels.actions(this), rule.action.ordinal(), index -> {
            rule.action = RuleAction.values()[index];
            updateProxySection();
        });
        fillProxies();
        updateProxySection();
    }

    /** The first entry is the default proxy, the others are the proxies in their order. */
    private void fillProxies() {
        List<ProxyConfig> proxies = store().config().proxies;
        List<String> labels = new ArrayList<>();
        labels.add(getString(R.string.rule_default_proxy));
        int selected = 0;
        for (int i = 0; i < proxies.size(); i++) {
            labels.add(proxies.get(i).displayName());
            if (proxies.get(i).id.equals(rule.proxyId)) {
                selected = i + 1;
            }
        }
        proxy.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, labels));
        proxy.setSelection(selected);
        proxy.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                rule.proxyId = position == 0 ? null : proxies.get(position - 1).id;
                updateProxySection();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
            }
        });
    }

    private void updateProxySection() {
        boolean viaProxy = rule.action == RuleAction.PROXY;
        proxySection.setVisibility(viaProxy ? View.VISIBLE : View.GONE);
        ProxyConfig chosen = rule.proxyId == null ? store().config().defaultProxy() : store().config().proxy(rule.proxyId);
        boolean httpWithUdp = viaProxy && chosen != null && chosen.kind == ProxyKind.HTTP
                && rule.protocol != RuleProtocol.TCP;
        httpUdp.setVisibility(httpWithUdp ? View.VISIBLE : View.GONE);
    }

    @Override
    boolean save(ConfigStore store) {
        rule.name = name.getText().toString().trim();
        rule.hosts = hosts.getText().toString().trim();
        rule.ports = ports.getText().toString().trim();
        rule.enabled = enabled.isChecked();
        store.update(config -> upsert(config.rules, rule, item -> item.id));
        return true;
    }

    @Override
    void delete(AppConfig config, String id) {
        config.rules.removeIf(item -> item.id.equals(id));
    }
}
