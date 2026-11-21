package com.interceptsuite.proxybridge.router;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Copies bytes between connections on one thread, so a connection costs two sockets and no threads. A buffer is held
 * only while its data is waiting to be written, and writes that do not fit pause the reading side.
 */
final class RelayLoop implements Runnable, Closeable {
    private static final int BUFFER_SIZE = 16 * 1024;
    private static final int POOL_LIMIT = 64;
    private static final int READS_PER_EVENT = 4;
    private static final long IDLE_LIMIT_MS = 5 * 60_000;
    private static final long SWEEP_MS = 30_000;

    private final Selector selector = Selector.open();
    private final Queue<Pair> incoming = new ConcurrentLinkedQueue<>();
    private final ArrayDeque<ByteBuffer> pool = new ArrayDeque<>();
    private final Set<Pair> pairs = new HashSet<>();
    private volatile boolean running = true;

    RelayLoop() throws IOException {
    }

    /** Copies both ways between the two channels until both sides have finished or one fails. */
    void relay(SocketChannel a, SocketChannel b) {
        add(new Pair(a, b));
    }

    /** Reads and discards everything from a channel until it closes. */
    void drain(SocketChannel channel) {
        add(new Pair(channel, null));
    }

    private void add(Pair pair) {
        incoming.add(pair);
        selector.wakeup();
    }

    @Override
    public void run() {
        long nextSweep = now() + SWEEP_MS;
        while (running) {
            try {
                selector.select(SWEEP_MS);
            } catch (IOException e) {
                break;
            }
            registerIncoming();
            Iterator<SelectionKey> keys = selector.selectedKeys().iterator();
            while (keys.hasNext()) {
                SelectionKey key = keys.next();
                keys.remove();
                if (key.isValid()) {
                    handle((Pair) key.attachment(), key);
                }
            }
            if (now() >= nextSweep) {
                closeIdle();
                nextSweep = now() + SWEEP_MS;
            }
        }
        for (Pair pair : new HashSet<>(pairs)) {
            pair.close();
        }
        ProxyConnector.close(selector);
    }

    @Override
    public void close() {
        running = false;
        selector.wakeup();
    }

    private void registerIncoming() {
        for (Pair pair = incoming.poll(); pair != null; pair = incoming.poll()) {
            try {
                pair.register();
                pairs.add(pair);
            } catch (IOException e) {
                pair.close();
            }
        }
    }

    private void handle(Pair pair, SelectionKey key) {
        try {
            boolean sideA = key == pair.keyA;
            Direction reading = sideA ? pair.forward : pair.backward;
            Direction writing = sideA ? pair.backward : pair.forward;
            if (key.isWritable() && writing.pending != null) {
                flush(writing);
            }
            if (key.isReadable() && !reading.finished && reading.pending == null) {
                pump(pair, reading);
            }
            if (pair.done()) {
                pair.close();
            } else {
                pair.updateInterest();
            }
        } catch (IOException | RuntimeException e) {
            pair.close();
        }
    }

    private void pump(Pair pair, Direction direction) throws IOException {
        for (int i = 0; i < READS_PER_EVENT && !direction.finished && direction.pending == null; i++) {
            ByteBuffer buffer = acquire();
            int read = direction.from.read(buffer);
            if (read < 0) {
                release(buffer);
                direction.finish();
                return;
            }
            if (read == 0) {
                release(buffer);
                return;
            }
            pair.lastActive = now();
            if (direction.to == null) {
                release(buffer);
                continue;
            }
            Buffers.flip(buffer);
            direction.to.write(buffer);
            if (buffer.hasRemaining()) {
                direction.pending = buffer;
            } else {
                release(buffer);
            }
            if (read < BUFFER_SIZE) {
                return;
            }
        }
    }

    private void flush(Direction direction) throws IOException {
        direction.to.write(direction.pending);
        if (!direction.pending.hasRemaining()) {
            release(direction.pending);
            direction.pending = null;
        }
    }

    private void closeIdle() {
        long limit = now() - IDLE_LIMIT_MS;
        for (Pair pair : new HashSet<>(pairs)) {
            if (pair.lastActive < limit) {
                pair.close();
            }
        }
    }

    private ByteBuffer acquire() {
        ByteBuffer buffer = pool.poll();
        if (buffer == null) {
            return ByteBuffer.allocateDirect(BUFFER_SIZE);
        }
        Buffers.clear(buffer);
        return buffer;
    }

    private void release(ByteBuffer buffer) {
        if (pool.size() < POOL_LIMIT) {
            pool.add(buffer);
        }
    }

    private static long now() {
        return System.nanoTime() / 1_000_000;
    }

    /** One direction of a connection. A null target means the data is thrown away. */
    private static final class Direction {
        final SocketChannel from;
        final SocketChannel to;
        ByteBuffer pending;
        boolean finished;

        Direction(SocketChannel from, SocketChannel to) {
            this.from = from;
            this.to = to;
        }

        /** The sending side is done: pass the close on to the other end. */
        void finish() throws IOException {
            finished = true;
            if (to != null) {
                to.shutdownOutput();
            }
        }
    }

    private final class Pair {
        final SocketChannel a;
        final SocketChannel b;
        final Direction forward;
        final Direction backward;
        SelectionKey keyA;
        SelectionKey keyB;
        long lastActive = now();

        Pair(SocketChannel a, SocketChannel b) {
            this.a = a;
            this.b = b;
            forward = new Direction(a, b);
            backward = new Direction(b, a);
            if (b == null) {
                backward.finished = true;
            }
        }

        void register() throws IOException {
            a.configureBlocking(false);
            keyA = a.register(selector, SelectionKey.OP_READ, this);
            if (b != null) {
                b.configureBlocking(false);
                keyB = b.register(selector, SelectionKey.OP_READ, this);
            }
        }

        boolean done() {
            return forward.finished && backward.finished && forward.pending == null && backward.pending == null;
        }

        void updateInterest() {
            keyA.interestOps(interest(forward, backward));
            if (keyB != null) {
                keyB.interestOps(interest(backward, forward));
            }
        }

        /** Read while this side is the source of an unfinished direction with nothing waiting to be written. */
        private int interest(Direction reading, Direction writing) {
            int ops = 0;
            if (!reading.finished && reading.pending == null) {
                ops |= SelectionKey.OP_READ;
            }
            if (writing.pending != null) {
                ops |= SelectionKey.OP_WRITE;
            }
            return ops;
        }

        void close() {
            pairs.remove(this);
            for (Direction direction : new Direction[]{forward, backward}) {
                if (direction.pending != null) {
                    release(direction.pending);
                    direction.pending = null;
                }
            }
            ProxyConnector.close(a);
            if (b != null) {
                ProxyConnector.close(b);
            }
        }
    }
}
