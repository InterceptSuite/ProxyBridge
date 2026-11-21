package com.interceptsuite.proxybridge.ui;

import android.content.Intent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import com.google.android.material.button.MaterialButtonToggleGroup;
import com.interceptsuite.proxybridge.R;
import com.interceptsuite.proxybridge.model.AppConfig;
import com.interceptsuite.proxybridge.model.ProxyConfig;
import com.interceptsuite.proxybridge.model.ProxyRule;
import com.interceptsuite.proxybridge.model.RuleAction;

import java.util.ArrayList;
import java.util.List;

public final class RulesFragment extends EditableListFragment<ProxyRule> {
    @Override
    int titleRes() {
        return R.string.rules_title;
    }

    @Override
    int emptyRes() {
        return R.string.rules_empty;
    }

    @Override
    int footerRes() {
        return R.string.rules_footer;
    }

    @Override
    List<ProxyRule> items(AppConfig config) {
        return config.rules;
    }

    @Override
    void bind(ProxyRule rule, TextView title, TextView subtitle) {
        if (!rule.name.isEmpty()) {
            title.setText(rule.name);
        } else {
            title.setText(rule.hosts.isEmpty() ? getString(R.string.rule_all_traffic) : rule.hosts);
        }
        List<String> details = new ArrayList<>();
        details.add(rule.ports.isEmpty() ? getString(R.string.rule_any_port) : rule.ports);
        details.add(Labels.protocol(requireContext(), rule.protocol));
        details.add(rule.action == RuleAction.PROXY
                ? getString(R.string.rule_proxy, proxyName(rule.proxyId))
                : Labels.action(requireContext(), rule.action));
        subtitle.setText(String.join(", ", details));
        float alpha = rule.enabled ? 1f : 0.5f;
        title.setAlpha(alpha);
        subtitle.setAlpha(alpha);
    }

    private String proxyName(String proxyId) {
        AppConfig config = store().config();
        ProxyConfig proxy = proxyId == null ? null : config.proxy(proxyId);
        if (proxy == null) {
            proxy = config.defaultProxy();
        }
        return proxy == null ? getString(R.string.no_proxy) : proxy.displayName();
    }

    @Override
    void open(ProxyRule rule) {
        Intent intent = new Intent(requireContext(), RuleEditorActivity.class);
        if (rule != null) {
            intent.putExtra(EditorActivity.EXTRA_ID, rule.id);
        }
        startActivity(intent);
    }

    @Override
    View header(LayoutInflater inflater, ViewGroup parent) {
        View header = inflater.inflate(R.layout.header_default_action, parent, false);
        MaterialButtonToggleGroup group = header.findViewById(R.id.default_action);
        Toggles.fill(group, Labels.actions(requireContext()), store().config().defaultAction.ordinal(),
                index -> store().update(config -> config.defaultAction = RuleAction.values()[index]));
        return header;
    }
}
