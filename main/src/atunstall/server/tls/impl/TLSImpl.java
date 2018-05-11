package atunstall.server.tls.impl;

import atunstall.server.core.api.Module;
import atunstall.server.core.api.Version;
import atunstall.server.io.api.ByteBuffer;
import atunstall.server.io.api.InputStream;
import atunstall.server.io.api.OutputStream;
import atunstall.server.io.api.ParsableByteBuffer;
import atunstall.server.io.api.util.AppendableParsableByteBuffer;
import atunstall.server.io.api.util.ArrayStreams;
import atunstall.server.io.api.util.HandledInputStream;
import atunstall.server.tls.api.TLS;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class TLSImpl implements TLS, AutoCloseable {
    private final Executor executor;
    private final Object readLock;
    private final Object writeLock;
    private final Object handshakeLock;
    private OutputStream rawOutput;
    private AppendableParsableByteBuffer rawBuffer;
    private HandledInputStream applicationInput;
    private OutputStream applicationOutput;
    private AppendableParsableByteBuffer applicationBuffer;

    private final SSLEngine engine;
    private java.nio.ByteBuffer readInBuffer;
    private java.nio.ByteBuffer writeInBuffer;
    private java.nio.ByteBuffer readOutBuffer;
    private java.nio.ByteBuffer writeOutBuffer;

    private TLSImpl(ArrayStreams streams, InputStream input, OutputStream output, ConnectionSide side, SSLContext context) {
        executor = Executors.newSingleThreadExecutor(r -> new Thread(r, "TLS"));
        readLock = new Object();
        writeLock = new Object();
        handshakeLock = new Object();
        rawOutput = output;
        rawBuffer = streams.createByteBuffer(256);
        applicationInput = streams.createInputStream(this);
        applicationOutput = new OutputStreamImpl();
        applicationBuffer = streams.createByteBuffer(256);

        engine = context.createSSLEngine();
        switch (side) {
            case CLIENT:
                engine.setUseClientMode(true);
                break;
            case SERVER:
                engine.setUseClientMode(false);
        }
        int bufferSize = engine.getSession().getPacketBufferSize();
        readInBuffer = java.nio.ByteBuffer.allocate(bufferSize);
        writeInBuffer = java.nio.ByteBuffer.allocate(bufferSize);
        bufferSize = engine.getSession().getApplicationBufferSize();
        readOutBuffer = java.nio.ByteBuffer.allocate(bufferSize);
        writeOutBuffer = java.nio.ByteBuffer.allocate(bufferSize);
        try {
            engine.beginHandshake();
        } catch (SSLException e) {
            close();
        }

        input.queueConsumer(this::readRaw);
        //executor.execute(this::refreshHandshake);
    }

    @Override
    public InputStream getInputStream() {
        return applicationInput;
    }

    @Override
    public OutputStream getOutputStream() {
        return applicationOutput;
    }

    @Override
    public void close() {
        engine.closeOutbound();
        executor.execute(this::emptyBuffers);
    }

    private void readRaw(ParsableByteBuffer buffer) {
        synchronized (readLock) {
            while (true) {
                try {
                    int count = (int) Math.min(buffer.count(), readInBuffer.remaining());
                    buffer.get(0L, readInBuffer.array(), readInBuffer.position(), count);
                    readInBuffer.position(readInBuffer.position() + count);
                    readInBuffer.flip();
                    SSLEngineResult result = handleReadInput();
                    if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        throw new IllegalArgumentException("insufficient data");
                    } else if (result.getStatus() == SSLEngineResult.Status.OK && result.bytesConsumed() == 0) {
                        // Prevent the input stream from removing this consumer.
                        continue;
                    }
                    long consumed = result.bytesConsumed();
                    buffer.clear(0L, consumed);
                    buffer.consume(0L, consumed);
                } catch (SSLException e) {
                    // TODO
                    throw new IllegalStateException(e);
                } finally {
                    readInBuffer.clear();
                    readOutBuffer.clear();
                }
                break;
            }
        }
    }

    private void emptyBuffers() {
        if (applicationBuffer.count() > 0L) applicationInput.consumeSafe(applicationBuffer);
        if (rawBuffer.count() > 0L) {
            rawOutput.toParsableBufferConsumer().accept(rawBuffer);
            rawBuffer.updateBackup();
        }
        if (applicationBuffer.count() > 0L || rawBuffer.count() > 0L) executor.execute(this::emptyBuffers);
    }

    private boolean handleHandshakeStatus(SSLEngineResult.HandshakeStatus status) {
        synchronized (handshakeLock) {
            switch (status) {
                case NEED_TASK:
                    Runnable task = engine.getDelegatedTask();
                    if (task != null) task.run();
                case NEED_WRAP:
                    synchronized (writeLock) {
                        try {
                            writeInBuffer.flip();
                            handleWriteInput();
                        } catch (SSLException e) {
                            // TODO
                        } finally {
                            writeInBuffer.clear();
                            writeOutBuffer.clear();
                        }
                    }
                case NEED_UNWRAP:
                    break;
                case NEED_UNWRAP_AGAIN:
                    // TODO ???
                    break;
                default:
                    return false;
            }
        }
        return true;
    }

    private void handleReadStatus(SSLEngineResult.Status status) {
        java.nio.ByteBuffer[] state = new java.nio.ByteBuffer[] {readInBuffer, readOutBuffer};
        handleStatus(status, state);
        readInBuffer = state[0];
        readOutBuffer = state[1];
    }

    private boolean handleWriteStatus(SSLEngineResult.Status status) {
        java.nio.ByteBuffer[] state = new java.nio.ByteBuffer[] {writeInBuffer, writeOutBuffer};
        boolean repeat = handleStatus(status, state);
        writeInBuffer = state[0];
        writeOutBuffer = state[1];
        return repeat;
    }

    private SSLEngineResult handleReadInput() throws SSLException {
        SSLEngineResult result = engine.unwrap(readInBuffer, readOutBuffer);
        executor.execute(() -> handleHandshakeStatus(result.getHandshakeStatus()));
        handleReadStatus(result.getStatus());
        applicationBuffer.append(readOutBuffer.array(), readOutBuffer.position() - result.bytesProduced(), result.bytesProduced());
        applicationInput.consumeSafe(applicationBuffer);
        return result;
    }

    private SSLEngineResult handleWriteInput() throws SSLException {
        SSLEngineResult result;
        do {
            result = engine.wrap(writeInBuffer, writeOutBuffer);
        } while (handleWriteStatus(result.getStatus()));
        SSLEngineResult.HandshakeStatus handshakeStatus = result.getHandshakeStatus();
        executor.execute(() -> handleHandshakeStatus(handshakeStatus));
        rawBuffer.append(writeOutBuffer.array(), writeOutBuffer.position() - result.bytesProduced(), result.bytesProduced());
        rawOutput.toParsableBufferConsumer().accept(rawBuffer);
        rawBuffer.updateBackup();
        return result;
    }

    private boolean handleStatus(SSLEngineResult.Status status, java.nio.ByteBuffer[] buffers) {
        switch (status) {
            case CLOSED:
                close();
                break;
            case BUFFER_UNDERFLOW:
                if (engine.getSession().getPacketBufferSize() > buffers[0].capacity()) {
                    buffers[0] = java.nio.ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
                } else {
                    buffers[0].clear();
                }
                break;
            case BUFFER_OVERFLOW:
                if (engine.getSession().getPacketBufferSize() > buffers[1].capacity()) {
                    buffers[1] = java.nio.ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
                } else {
                    buffers[1].clear();
                }
                return true;
            case OK:
                break;
            default:
                System.out.println(status.name());
        }
        return false;
    }

    @Module
    public static class Builder implements TLS.Builder {
        private final ArrayStreams streams;
        private InputStream inputStream;
        private OutputStream outputStream;
        private ConnectionSide side;
        private SSLContext context;

        public Builder(@Version(major = 1, minor = 0) ArrayStreams streams) {
            this.streams = streams;
        }

        @Override
        public TLS.Builder inputStream(InputStream inputStream) {
            this.inputStream = inputStream;
            return this;
        }

        @Override
        public TLS.Builder outputStream(OutputStream outputStream) {
            this.outputStream = outputStream;
            return this;
        }

        @Override
        public TLS.Builder side(ConnectionSide side) {
            this.side = side;
            return this;
        }

        @Override
        public TLS.Builder context(SSLContext context) {
            this.context = context;
            return this;
        }

        @Override
        public TLS build() {
            if (inputStream == null || outputStream == null || side == null || context == null) {
                throw new IllegalStateException("missing mandatory parameters");
            }
            return new TLSImpl(streams, inputStream, outputStream, side, context);
        }
    }

    private class OutputStreamImpl implements OutputStream {
        @Override
        public void close() {
            TLSImpl.this.close();
        }

        @Override
        public void accept(ByteBuffer buffer) {
            synchronized (writeLock) {
                try {
                    for (long index = 0L; index < buffer.count(); index += writeInBuffer.limit()) {
                        int count = (int) Math.min(buffer.count() - index, writeInBuffer.limit());
                        buffer.get(index, writeInBuffer.array(), 0, count);
                        writeInBuffer.position(count);
                        writeInBuffer.flip();
                        handleWriteInput();
                    }
                } catch (SSLException e) {
                    // TODO
                } finally {
                    writeInBuffer.clear();
                    writeOutBuffer.clear();
                }
            }
        }
    }
}
