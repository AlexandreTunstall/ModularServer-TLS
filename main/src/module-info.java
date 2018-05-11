module atunstall.server.tls {
    requires atunstall.server.core;
    requires atunstall.server.io;
    exports atunstall.server.tls.api;
    exports atunstall.server.tls.impl to atunstall.server.core;
}