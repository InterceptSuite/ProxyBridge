package com.interceptsuite.proxybridge.data;

import android.content.Context;
import android.util.AtomicFile;

import com.interceptsuite.proxybridge.model.AppConfig;
import com.interceptsuite.proxybridge.model.ConfigJson;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/** Keeps the config in a file in the app's private storage. Every change is saved and passed to the listeners. */
public final class ConfigStore {
    public interface Listener {
        void onConfigChanged();
    }

    public interface Change {
        void apply(AppConfig config);
    }

    private static ConfigStore instance;

    private final AtomicFile file;
    private final AppConfig config;
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();

    public static synchronized ConfigStore get(Context context) {
        if (instance == null) {
            instance = new ConfigStore(new File(context.getApplicationContext().getFilesDir(), "config.json"));
        }
        return instance;
    }

    private ConfigStore(File file) {
        this.file = new AtomicFile(file);
        this.config = load();
    }

    /** The live config. Change it only through {@link #update}, so the change is saved. */
    public AppConfig config() {
        return config;
    }

    public synchronized void update(Change change) {
        change.apply(config);
        save();
        for (Listener listener : listeners) {
            listener.onConfigChanged();
        }
    }

    public void addListener(Listener listener) {
        listeners.add(listener);
    }

    public void removeListener(Listener listener) {
        listeners.remove(listener);
    }

    private AppConfig load() {
        try {
            return ConfigJson.fromJson(new String(file.readFully(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            return new AppConfig();
        }
    }

    private void save() {
        FileOutputStream out = null;
        try {
            out = file.startWrite();
            out.write(ConfigJson.toJson(config).getBytes(StandardCharsets.UTF_8));
            file.finishWrite(out);
        } catch (IOException e) {
            file.failWrite(out);
        }
    }
}
