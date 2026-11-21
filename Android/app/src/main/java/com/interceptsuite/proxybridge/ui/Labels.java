package com.interceptsuite.proxybridge.ui;

import android.content.Context;

import com.interceptsuite.proxybridge.R;
import com.interceptsuite.proxybridge.model.RuleAction;
import com.interceptsuite.proxybridge.model.RuleProtocol;

/** Display names of the enums. The arrays in the resources are in the same order as the enums. */
final class Labels {
    private Labels() {
    }

    static String[] actions(Context context) {
        return context.getResources().getStringArray(R.array.rule_actions);
    }

    static String[] protocols(Context context) {
        return context.getResources().getStringArray(R.array.rule_protocols);
    }

    static String action(Context context, RuleAction action) {
        return actions(context)[action.ordinal()];
    }

    static String protocol(Context context, RuleProtocol protocol) {
        return protocols(context)[protocol.ordinal()];
    }
}
