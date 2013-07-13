package com.hwlcn.security.authz;


public class HostUnauthorizedException extends UnauthorizedException {

    private String host;

    public HostUnauthorizedException() {
        super();
    }

    public HostUnauthorizedException(String message) {
        super(message);
    }

    public HostUnauthorizedException(Throwable cause) {
        super(cause);
    }

    public HostUnauthorizedException(String message, Throwable cause) {
        super(message, cause);
    }

    public String getHost() {
        return this.host;
    }

    public void setHostAddress(String host) {
        this.host = host;
    }
}
