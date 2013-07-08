package com.hwlcn.security.web.filter.authz;

import com.hwlcn.security.config.ConfigurationException;
import com.hwlcn.security.util.StringUtils;
import com.hwlcn.security.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class PortFilter extends AuthorizationFilter {

    public static final int DEFAULT_HTTP_PORT = 80;
    public static final String HTTP_SCHEME = "http";

    private int port = DEFAULT_HTTP_PORT;

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    protected int toPort(Object mappedValue) {
        String[] ports = (String[]) mappedValue;
        if (ports == null || ports.length == 0) {
            return getPort();
        }
        if (ports.length > 1) {
            throw new ConfigurationException("PortFilter can only be configured with a single port.  You have " +
                    "configured " + ports.length + ": " + StringUtils.toString(ports));
        }
        return Integer.parseInt(ports[0]);
    }

    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        int requiredPort = toPort(mappedValue);
        int requestPort = request.getServerPort();
        return requiredPort == requestPort;
    }

    protected String getScheme(String requestScheme, int port) {
        if (port == DEFAULT_HTTP_PORT) {
            return HTTP_SCHEME;
        } else if (port == SslFilter.DEFAULT_HTTPS_PORT) {
            return SslFilter.HTTPS_SCHEME;
        } else {
            return requestScheme;
        }
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response, Object mappedValue) throws IOException {
        int port = toPort(mappedValue);

        String scheme = getScheme(request.getScheme(), port);

        StringBuilder sb = new StringBuilder();
        sb.append(scheme).append("://");
        sb.append(request.getServerName());
        if (port != DEFAULT_HTTP_PORT && port != SslFilter.DEFAULT_HTTPS_PORT) {
            sb.append(":");
            sb.append(port);
        }
        if (request instanceof HttpServletRequest) {
            sb.append(WebUtils.toHttp(request).getRequestURI());
            String query = WebUtils.toHttp(request).getQueryString();
            if (query != null) {
                sb.append("?").append(query);
            }
        }

        WebUtils.issueRedirect(request, response, sb.toString());

        return false;
    }
}
