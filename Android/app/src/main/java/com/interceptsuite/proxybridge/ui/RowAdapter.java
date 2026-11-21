package com.interceptsuite.proxybridge.ui;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.interceptsuite.proxybridge.R;

import java.util.List;
import java.util.function.Consumer;

/** A list of two-line rows. The list is the live one, so the adapter always shows its current content. */
final class RowAdapter<T> extends RecyclerView.Adapter<RowAdapter.Holder> {
    interface Binder<T> {
        void bind(T item, TextView title, TextView subtitle);
    }

    static final class Holder extends RecyclerView.ViewHolder {
        final TextView title;
        final TextView subtitle;

        Holder(View row) {
            super(row);
            title = row.findViewById(R.id.title);
            subtitle = row.findViewById(R.id.subtitle);
        }
    }

    private final List<T> items;
    private final Binder<T> binder;
    private final Consumer<T> onClick;

    RowAdapter(List<T> items, Binder<T> binder, Consumer<T> onClick) {
        this.items = items;
        this.binder = binder;
        this.onClick = onClick;
    }

    @NonNull
    @Override
    public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        return new Holder(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_row, parent, false));
    }

    @Override
    public void onBindViewHolder(@NonNull Holder holder, int position) {
        binder.bind(items.get(position), holder.title, holder.subtitle);
        holder.itemView.setOnClickListener(view -> onClick.accept(items.get(holder.getBindingAdapterPosition())));
    }

    @Override
    public int getItemCount() {
        return items.size();
    }
}
