package com.interceptsuite.proxybridge.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.DividerItemDecoration;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.snackbar.Snackbar;
import com.interceptsuite.proxybridge.R;
import com.interceptsuite.proxybridge.data.ConfigStore;
import com.interceptsuite.proxybridge.model.AppConfig;

import java.util.Collections;
import java.util.List;

/** A screen with a list that can be added to, reordered by dragging and emptied by swiping. */
abstract class EditableListFragment<T> extends Fragment implements ConfigStore.Listener {
    private ConfigStore store;
    private RowAdapter<T> adapter;
    private TextView empty;
    /** True while this screen changes the config itself, so it does not refresh on its own change. */
    private boolean changing;

    abstract int titleRes();

    abstract int emptyRes();

    abstract int footerRes();

    abstract List<T> items(AppConfig config);

    abstract void bind(T item, TextView title, TextView subtitle);

    /** Opens the editor for the item, or for a new one when the item is null. */
    abstract void open(@Nullable T item);

    /** A view shown above the list, or null. */
    @Nullable
    View header(LayoutInflater inflater, ViewGroup parent) {
        return null;
    }

    void remove(AppConfig config, T item) {
        items(config).remove(item);
    }

    ConfigStore store() {
        return store;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle state) {
        store = ConfigStore.get(requireContext());
        View view = inflater.inflate(R.layout.fragment_list, container, false);
        ((TextView) view.findViewById(R.id.title)).setText(titleRes());
        ((TextView) view.findViewById(R.id.footer)).setText(footerRes());
        empty = view.findViewById(R.id.empty);
        empty.setText(emptyRes());
        view.findViewById(R.id.add).setOnClickListener(button -> open(null));

        FrameLayout headerHolder = view.findViewById(R.id.header);
        View header = header(inflater, headerHolder);
        if (header != null) {
            headerHolder.addView(header);
        }

        adapter = new RowAdapter<>(items(store.config()), this::bind, this::open);
        RecyclerView list = view.findViewById(R.id.list);
        list.setLayoutManager(new LinearLayoutManager(requireContext()));
        list.addItemDecoration(new DividerItemDecoration(requireContext(), DividerItemDecoration.VERTICAL));
        list.setAdapter(adapter);
        new ItemTouchHelper(new Touch(view)).attachToRecyclerView(list);
        return view;
    }

    @Override
    public void onStart() {
        super.onStart();
        store.addListener(this);
        refresh();
    }

    @Override
    public void onStop() {
        store.removeListener(this);
        super.onStop();
    }

    @Override
    public void onConfigChanged() {
        if (!changing) {
            refresh();
        }
    }

    private void refresh() {
        adapter.notifyDataSetChanged();
        updateEmpty();
    }

    private void updateEmpty() {
        empty.setVisibility(adapter.getItemCount() == 0 ? View.VISIBLE : View.GONE);
    }

    private void change(ConfigStore.Change change) {
        changing = true;
        store.update(change);
        changing = false;
    }

    private final class Touch extends ItemTouchHelper.SimpleCallback {
        private final View root;

        Touch(View root) {
            super(ItemTouchHelper.UP | ItemTouchHelper.DOWN, ItemTouchHelper.LEFT | ItemTouchHelper.RIGHT);
            this.root = root;
        }

        /** Reorders the live list while the row is dragged. It is saved when the drag ends. */
        @Override
        public boolean onMove(@NonNull RecyclerView list, @NonNull RecyclerView.ViewHolder from,
                              @NonNull RecyclerView.ViewHolder to) {
            Collections.swap(items(store.config()), from.getBindingAdapterPosition(), to.getBindingAdapterPosition());
            adapter.notifyItemMoved(from.getBindingAdapterPosition(), to.getBindingAdapterPosition());
            return true;
        }

        @Override
        public void clearView(@NonNull RecyclerView list, @NonNull RecyclerView.ViewHolder holder) {
            super.clearView(list, holder);
            change(config -> { });
        }

        @Override
        public void onSwiped(@NonNull RecyclerView.ViewHolder holder, int direction) {
            int position = holder.getBindingAdapterPosition();
            T item = items(store.config()).get(position);
            change(config -> remove(config, item));
            adapter.notifyItemRemoved(position);
            updateEmpty();
            Snackbar.make(root, R.string.deleted, Snackbar.LENGTH_LONG).setAction(R.string.undo, view -> {
                change(config -> items(config).add(Math.min(position, items(config).size()), item));
                refresh();
            }).show();
        }
    }
}
