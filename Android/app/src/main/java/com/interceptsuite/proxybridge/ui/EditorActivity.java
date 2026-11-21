package com.interceptsuite.proxybridge.ui;

import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.appbar.MaterialToolbar;
import com.interceptsuite.proxybridge.R;
import com.interceptsuite.proxybridge.data.ConfigStore;
import com.interceptsuite.proxybridge.model.AppConfig;

import java.util.List;
import java.util.function.Function;

/** A form for one item, with Save in the toolbar and Delete in its menu when the item already exists. */
abstract class EditorActivity extends AppCompatActivity {
    static final String EXTRA_ID = "id";

    private ConfigStore store;
    private String itemId;

    abstract int addTitle();

    abstract int editTitle();

    abstract int formLayout();

    /** Fills the form. {@code id} is the item being edited, or null for a new one. */
    abstract void bind(View form, @Nullable String id);

    /** Reads the form into the config. Returns false, after telling the user why, when the input is not valid. */
    abstract boolean save(ConfigStore store);

    abstract void delete(AppConfig config, String id);

    ConfigStore store() {
        return store;
    }

    @Override
    protected void onCreate(@Nullable Bundle state) {
        super.onCreate(state);
        store = ConfigStore.get(this);
        itemId = getIntent().getStringExtra(EXTRA_ID);
        setContentView(R.layout.activity_editor);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setTitle(itemId == null ? addTitle() : editTitle());
        toolbar.setNavigationOnClickListener(view -> finish());
        toolbar.inflateMenu(R.menu.editor);
        toolbar.getMenu().findItem(R.id.action_delete).setVisible(itemId != null);
        toolbar.setOnMenuItemClickListener(item -> {
            if (item.getItemId() == R.id.action_save && save(store)) {
                finish();
            } else if (item.getItemId() == R.id.action_delete) {
                store.update(config -> delete(config, itemId));
                finish();
            }
            return true;
        });

        ViewGroup content = findViewById(R.id.content);
        bind(getLayoutInflater().inflate(formLayout(), content, true), itemId);
    }

    /** Replaces the item with the same id, or adds it at the end. */
    static <T> void upsert(List<T> list, T item, Function<T, String> idOf) {
        for (int i = 0; i < list.size(); i++) {
            if (idOf.apply(list.get(i)).equals(idOf.apply(item))) {
                list.set(i, item);
                return;
            }
        }
        list.add(item);
    }
}
