package com.interceptsuite.proxybridge.ui;

import android.content.Intent;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.interceptsuite.proxybridge.R;

public final class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.activity_main);
        BottomNavigationView navigation = findViewById(R.id.navigation);
        navigation.setOnItemSelectedListener(item -> {
            show(item.getItemId());
            return true;
        });
        if (state == null) {
            navigation.setSelectedItemId(R.id.tab_status);
        }
    }

    @Override
    protected void onStart() {
        super.onStart();
        if (!DisclosureActivity.accepted(this)) {
            startActivity(new Intent(this, DisclosureActivity.class));
        }
    }

    private void show(int tab) {
        Fragment fragment = tab == R.id.tab_rules ? new RulesFragment()
                : tab == R.id.tab_proxies ? new ProxiesFragment() : new StatusFragment();
        getSupportFragmentManager().beginTransaction().replace(R.id.container, fragment).commit();
    }
}
