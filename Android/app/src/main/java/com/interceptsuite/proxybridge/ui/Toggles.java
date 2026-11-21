package com.interceptsuite.proxybridge.ui;

import android.content.Context;
import android.view.View;
import android.widget.LinearLayout;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.button.MaterialButtonToggleGroup;

import java.util.function.IntConsumer;

final class Toggles {
    private Toggles() {
    }

    /** Fills a single-selection group with one button per label and reports the index of the chosen one. */
    static void fill(MaterialButtonToggleGroup group, String[] labels, int selected, IntConsumer onChange) {
        Context context = group.getContext();
        int[] ids = new int[labels.length];
        for (int i = 0; i < labels.length; i++) {
            MaterialButton button = new MaterialButton(context, null,
                    com.google.android.material.R.attr.materialButtonOutlinedStyle);
            button.setId(View.generateViewId());
            button.setText(labels[i]);
            button.setLayoutParams(new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
            group.addView(button);
            ids[i] = button.getId();
        }
        group.check(ids[selected]);
        group.addOnButtonCheckedListener((g, checkedId, isChecked) -> {
            for (int i = 0; isChecked && i < ids.length; i++) {
                if (ids[i] == checkedId) {
                    onChange.accept(i);
                }
            }
        });
    }
}
