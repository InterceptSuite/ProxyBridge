package com.interceptsuite.proxybridge.ui;

import android.content.Context;
import android.os.Bundle;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.color.MaterialColors;
import com.interceptsuite.proxybridge.R;
import com.interceptsuite.proxybridge.data.Prefs;

/**
 * Shown once before the tunnel can be used. A VPN app has to state, on a screen of the app and before the service is
 * used, what data is collected and how it is used.
 */
public final class DisclosureActivity extends AppCompatActivity {
    /** Raise this when the text changes, so everyone has to read it again. */
    private static final int VERSION = 1;

    private static final int[][] SECTIONS = {
            {R.string.disclosure_what_title, R.string.disclosure_what},
            {R.string.disclosure_traffic_title, R.string.disclosure_traffic},
            {R.string.disclosure_data_title, R.string.disclosure_data},
            {R.string.disclosure_sharing_title, R.string.disclosure_sharing},
            {R.string.disclosure_names_title, R.string.disclosure_names},
    };

    static boolean accepted(Context context) {
        return Prefs.disclosureAccepted(context, VERSION);
    }

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.activity_disclosure);
        LinearLayout sections = findViewById(R.id.sections);
        for (int[] section : SECTIONS) {
            sections.addView(textView(com.google.android.material.R.style.TextAppearance_Material3_TitleMedium, section[0], R.dimen.section_gap, 0));
            sections.addView(textView(com.google.android.material.R.style.TextAppearance_Material3_BodyLarge, section[1], R.dimen.title_gap,
                    com.google.android.material.R.attr.colorOnSurfaceVariant));
        }
        TextView link = textView(com.google.android.material.R.style.TextAppearance_Material3_BodyLarge, R.string.disclosure_policy,
                R.dimen.section_gap, androidx.appcompat.R.attr.colorPrimary);
        link.setOnClickListener(view -> Links.open(this, Links.PRIVACY_POLICY));
        sections.addView(link);

        findViewById(R.id.accept).setOnClickListener(view -> {
            Prefs.acceptDisclosure(this, VERSION);
            finish();
        });
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                finishAffinity();
            }
        });
    }

    /** A text view with the given style, spacing above it and, when colorAttr is not 0, a theme colour. */
    private TextView textView(int style, int text, int topMargin, int colorAttr) {
        TextView view = new TextView(this);
        view.setTextAppearance(style);
        view.setText(text);
        if (colorAttr != 0) {
            view.setTextColor(MaterialColors.getColor(view, colorAttr));
        }
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        params.topMargin = getResources().getDimensionPixelSize(topMargin);
        view.setLayoutParams(params);
        return view;
    }
}
