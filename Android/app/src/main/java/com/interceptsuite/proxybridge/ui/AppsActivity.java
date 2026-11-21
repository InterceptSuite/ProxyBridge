package com.interceptsuite.proxybridge.ui;

import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.RadioGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.appbar.MaterialToolbar;
import com.interceptsuite.proxybridge.R;
import com.interceptsuite.proxybridge.data.ConfigStore;
import com.interceptsuite.proxybridge.model.AppMode;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Chooses which apps have their traffic sent into the tunnel. Android applies this itself, before any packet is read. */
public final class AppsActivity extends AppCompatActivity {
    private static final class App {
        final String packageName;
        final CharSequence label;
        final Drawable icon;

        App(String packageName, CharSequence label, Drawable icon) {
            this.packageName = packageName;
            this.label = label;
            this.icon = icon;
        }
    }

    private ConfigStore store;
    private AppAdapter adapter;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        store = ConfigStore.get(this);
        setContentView(R.layout.activity_apps);
        ((MaterialToolbar) findViewById(R.id.toolbar)).setNavigationOnClickListener(view -> finish());

        RadioGroup mode = findViewById(R.id.mode);
        mode.check(radioFor(store.config().appMode));
        mode.setOnCheckedChangeListener((group, checkedId) -> {
            store.update(config -> config.appMode = modeFor(checkedId));
            adapter.notifyDataSetChanged();
        });

        adapter = new AppAdapter();
        RecyclerView list = findViewById(R.id.list);
        list.setLayoutManager(new LinearLayoutManager(this));
        list.setAdapter(adapter);
        load();
    }

    private static int radioFor(AppMode mode) {
        return mode == AppMode.ONLY_SELECTED ? R.id.mode_only
                : mode == AppMode.ALL_EXCEPT_SELECTED ? R.id.mode_except : R.id.mode_all;
    }

    private static AppMode modeFor(int radio) {
        return radio == R.id.mode_only ? AppMode.ONLY_SELECTED
                : radio == R.id.mode_except ? AppMode.ALL_EXCEPT_SELECTED : AppMode.ALL;
    }

    /** Lists the apps that have a launcher icon, which needs no special permission. */
    private void load() {
        new Thread(() -> {
            PackageManager packages = getPackageManager();
            Intent launcher = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
            Set<String> seen = new HashSet<>();
            List<App> apps = new ArrayList<>();
            for (ResolveInfo info : packages.queryIntentActivities(launcher, 0)) {
                String name = info.activityInfo.packageName;
                if (!name.equals(getPackageName()) && seen.add(name)) {
                    apps.add(new App(name, info.loadLabel(packages), info.loadIcon(packages)));
                }
            }
            apps.sort(Comparator.comparing(app -> app.label.toString().toLowerCase()));
            runOnUiThread(() -> {
                adapter.apps = apps;
                adapter.notifyDataSetChanged();
                findViewById(R.id.loading).setVisibility(View.GONE);
            });
        }, "apps-loader").start();
    }

    private final class AppAdapter extends RecyclerView.Adapter<AppAdapter.Holder> {
        List<App> apps = new ArrayList<>();

        final class Holder extends RecyclerView.ViewHolder {
            final ImageView icon;
            final TextView title;
            final TextView subtitle;
            final CheckBox check;

            Holder(View row) {
                super(row);
                icon = row.findViewById(R.id.icon);
                title = row.findViewById(R.id.title);
                subtitle = row.findViewById(R.id.subtitle);
                check = row.findViewById(R.id.check);
            }
        }

        @NonNull
        @Override
        public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            return new Holder(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_app, parent, false));
        }

        @Override
        public void onBindViewHolder(@NonNull Holder holder, int position) {
            App app = apps.get(position);
            boolean active = store.config().appMode != AppMode.ALL;
            holder.icon.setImageDrawable(app.icon);
            holder.title.setText(app.label);
            holder.subtitle.setText(app.packageName);
            holder.check.setChecked(store.config().packages.contains(app.packageName));
            holder.itemView.setEnabled(active);
            holder.itemView.setAlpha(active ? 1f : 0.5f);
            holder.itemView.setOnClickListener(row -> {
                store.update(config -> {
                    if (!config.packages.remove(app.packageName)) {
                        config.packages.add(app.packageName);
                    }
                });
                notifyItemChanged(holder.getBindingAdapterPosition());
            });
        }

        @Override
        public int getItemCount() {
            return apps.size();
        }
    }
}
