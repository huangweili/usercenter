package com.hwlcn.security.web.filter.authz;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


public class SslFilter extends PortFilter {

    public static final int DEFAULT_HTTPS_PORT = 443;
    public static final String HTTPS_SCHEME = "https";

    public SslFilter() {
        setPort(DEFAULT_HTTPS_PORT);
    }

    @Override
    protected String getScheme(String requestScheme, int port) {
        if (port == DEFAULT_HTTP_PORT) {
            return PortFilter.HTTP_SCHEME;
        } else {
            return HTTPS_SCHEME;
        }
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        return super.isAccessAllowed(request, response, mappedValue) && request.isSecure();
    }
}
