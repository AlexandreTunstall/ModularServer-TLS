package atunstall.server.tls.api;

import atunstall.server.core.api.Version;
import atunstall.server.io.api.InputStream;
import atunstall.server.io.api.OutputStream;

import javax.net.ssl.SSLContext;

/**
 * Models the TLS protocol.
 */
public interface TLS {
    /**
     * Returns an input stream from which the application data input should be read.
     * @return An input stream.
     */
    InputStream getInputStream();

    /**
     * Returns an output stream to which the application data output should be read.
     * @return An output stream.
     */
    OutputStream getOutputStream();

    /**
     * Creates a new instance of TLS using the given parameters.
     */
    @Version(major = 1, minor = 0)
    interface Builder {
        /**
         * The input stream from which to read data.
         * This parameter is mandatory.
         * @param inputStream The input stream from which to read.
         * @return This object for chaining.
         */
        Builder inputStream(InputStream inputStream);

        /**
         * The output stream to which to write data.
         * This parameter is mandatory.
         * @param outputStream The output stream to which to write.
         * @return This object for chaining.
         */
        Builder outputStream(OutputStream outputStream);

        /**
         * The side of this connection.
         * This parameter is mandatory.
         * @param side The side of this connection.
         * @return This object for chaining.
         */
        Builder side(ConnectionSide side);

        /**
         * The context from which to extract the security information.
         * This parameter is mandatory.
         * @param context The context of this connection.
         * @return This object for chaining.
         */
        Builder context(SSLContext context);

        /**
         * Creates a new instance of TLS using the parameters set with the other functions.
         * @return The created instance.
         * @throws IllegalStateException If any mandatory parameters are not set.
         */
        TLS build();
    }

    /**
     * Models a side of a connection.
     */
    enum ConnectionSide {
        /**
         * The client side. The side that initiates the connection.
         */
        CLIENT,

        /**
         * The server side. The side that accepts or denies connection requests.
         */
        SERVER
    }
}
