# hev's JNI wrapper registers all four native methods by name, so none may be removed or renamed
-keep class com.interceptsuite.proxybridge.vpn.HevTunnel {
    native <methods>;
}
