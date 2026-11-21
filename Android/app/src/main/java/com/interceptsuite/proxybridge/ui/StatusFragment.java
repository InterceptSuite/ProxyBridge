package com.interceptsuite.proxybridge.ui;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.google.android.material.materialswitch.MaterialSwitch;
import com.interceptsuite.proxybridge.R;
import com.interceptsuite.proxybridge.data.ConfigStore;
import com.interceptsuite.proxybridge.model.AppConfig;
import com.interceptsuite.proxybridge.vpn.ProxyVpnService;
import com.interceptsuite.proxybridge.vpn.TunnelState;

public final class StatusFragment extends Fragment implements TunnelState.Listener, ConfigStore.Listener {
    private final ActivityResultLauncher<Intent> permission = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(), result -> {
                if (result.getResultCode() == android.app.Activity.RESULT_OK) {
                    startTunnel();
                } else {
                    render();
                }
            });

    private ConfigStore store;
    private MaterialSwitch toggle;
    private TextView status;
    private TextView error;
    private TextView hint;
    private View appsRow;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle state) {
        store = ConfigStore.get(requireContext());
        View view = inflater.inflate(R.layout.fragment_status, container, false);
        toggle = view.findViewById(R.id.toggle);
        status = view.findViewById(R.id.status);
        error = view.findViewById(R.id.error);
        hint = view.findViewById(R.id.hint);
        appsRow = view.findViewById(R.id.apps_row);

        toggle.setOnClickListener(button -> {
            if (toggle.isChecked()) {
                requestTunnel();
            } else {
                stopTunnel();
            }
        });
        appsRow.setOnClickListener(row -> startActivity(new Intent(requireContext(), AppsActivity.class)));
        setRow(view, R.id.apps_row, getString(R.string.apps), null);
        setRow(view, R.id.version_row, getString(R.string.version), version());
        setRow(view, R.id.website_row, getString(R.string.website), Links.WEBSITE)
                .setOnClickListener(row -> Links.open(requireContext(), Links.WEBSITE));
        setRow(view, R.id.github_row, getString(R.string.github), Links.GITHUB)
                .setOnClickListener(row -> Links.open(requireContext(), Links.GITHUB));
        setRow(view, R.id.privacy_row, getString(R.string.privacy_policy), Links.PRIVACY_POLICY)
                .setOnClickListener(row -> Links.open(requireContext(), Links.PRIVACY_POLICY));
        return view;
    }

    @Override
    public void onStart() {
        super.onStart();
        TunnelState.addListener(this);
        store.addListener(this);
        render();
    }

    @Override
    public void onStop() {
        TunnelState.removeListener(this);
        store.removeListener(this);
        super.onStop();
    }

    @Override
    public void onTunnelChanged() {
        render();
    }

    @Override
    public void onConfigChanged() {
        render();
    }

    private void render() {
        TunnelState.Status current = TunnelState.status();
        toggle.setChecked(current != TunnelState.Status.OFF);
        toggle.setEnabled(current != TunnelState.Status.STARTING);
        status.setText(current == TunnelState.Status.ON ? R.string.status_on
                : current == TunnelState.Status.STARTING ? R.string.status_starting : R.string.status_off);

        String message = TunnelState.error();
        error.setText(message);
        error.setVisibility(message == null ? View.GONE : View.VISIBLE);

        AppConfig config = store.config();
        hint.setText(config.proxies.isEmpty() ? R.string.status_hint_empty : R.string.status_hint);
        TextView summary = appsRow.findViewById(R.id.subtitle);
        switch (config.appMode) {
            case ONLY_SELECTED:
                summary.setText(getString(R.string.apps_summary_only, config.packages.size()));
                break;
            case ALL_EXCEPT_SELECTED:
                summary.setText(getString(R.string.apps_summary_except, config.packages.size()));
                break;
            default:
                summary.setText(R.string.apps_all);
        }
    }

    /** Android asks for the VPN permission the first time, and gives no prompt afterwards. */
    private void requestTunnel() {
        Intent consent = VpnService.prepare(requireContext());
        if (consent == null) {
            startTunnel();
        } else {
            permission.launch(consent);
        }
    }

    private void startTunnel() {
        requireContext().startService(new Intent(requireContext(), ProxyVpnService.class));
    }

    private void stopTunnel() {
        requireContext().startService(new Intent(requireContext(), ProxyVpnService.class)
                .setAction(ProxyVpnService.ACTION_STOP));
    }

    private static View setRow(View root, int id, String title, @Nullable String subtitle) {
        View row = root.findViewById(id);
        ((TextView) row.findViewById(R.id.title)).setText(title);
        TextView sub = row.findViewById(R.id.subtitle);
        if (subtitle == null) {
            sub.setVisibility(View.GONE);
        } else {
            sub.setText(subtitle);
        }
        return row;
    }

    private String version() {
        Context context = requireContext();
        try {
            return context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionName;
        } catch (PackageManager.NameNotFoundException e) {
            return "";
        }
    }
}
