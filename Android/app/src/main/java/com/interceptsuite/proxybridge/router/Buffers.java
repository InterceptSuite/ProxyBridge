package com.interceptsuite.proxybridge.router;

import java.nio.Buffer;
import java.nio.ByteBuffer;

/**
 * ByteBuffer's own clear, flip and position are not on every Android version, only the ones declared by Buffer are.
 * Calling them through Buffer keeps the code running on Android 10.
 */
final class Buffers {
    private Buffers() {
    }

    static void clear(ByteBuffer buffer) {
        ((Buffer) buffer).clear();
    }

    static void flip(ByteBuffer buffer) {
        ((Buffer) buffer).flip();
    }

    static void position(ByteBuffer buffer, int position) {
        ((Buffer) buffer).position(position);
    }
}
