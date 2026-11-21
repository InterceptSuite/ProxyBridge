package com.interceptsuite.proxybridge.model;

/** Which apps have their traffic sent into the tunnel at all. */
public enum AppMode {
    ALL,
    ONLY_SELECTED,
    ALL_EXCEPT_SELECTED
}
