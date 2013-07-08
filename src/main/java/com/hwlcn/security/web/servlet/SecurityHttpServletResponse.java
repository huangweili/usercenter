package com.hwlcn.security.web.servlet;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

public class SecurityHttpServletResponse extends HttpServletResponseWrapper {

    private static final String DEFAULT_SESSION_ID_PARAMETER_NAME = SecurityHttpSession.DEFAULT_SESSION_ID_NAME;

    private ServletContext context = null;
    private SecurityHttpServletRequest request = null;

    public SecurityHttpServletResponse(HttpServletResponse wrapped, ServletContext context, SecurityHttpServletRequest request) {
        super(wrapped);
        this.context = context;
        this.request = request;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public ServletContext getContext() {
        return context;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setContext(ServletContext context) {
        this.context = context;
    }

    public SecurityHttpServletRequest getRequest() {
        return request;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setRequest(SecurityHttpServletRequest request) {
        this.request = request;
    }

    public String encodeRedirectURL(String url) {
        if (isEncodeable(toAbsolute(url))) {
            return toEncoded(url, request.getSession().getId());
        } else {
            return url;
        }
    }


    public String encodeRedirectUrl(String s) {
        return encodeRedirectURL(s);
    }


    public String encodeURL(String url) {
        String absolute = toAbsolute(url);
        if (isEncodeable(absolute)) {
            if (url.equalsIgnoreCase("")) {
                url = absolute;
            }
            return toEncoded(url, request.getSession().getId());
        } else {
            return url;
        }
    }

    public String encodeUrl(String s) {
        return encodeURL(s);
    }

    protected boolean isEncodeable(final String location) {

        if (location == null)
            return false;
        if (location.startsWith("#"))
            return false;
        final HttpServletRequest hreq = request;
        final HttpSession session = hreq.getSession(false);
        if (session == null)
            return false;
        if (hreq.isRequestedSessionIdFromCookie())
            return (false);

        return doIsEncodeable(hreq, session, location);
    }

    private boolean doIsEncodeable(HttpServletRequest hreq, HttpSession session, String location) {
        URL url;
        try {
            url = new URL(location);
        } catch (MalformedURLException e) {
            return false;
        }

        if (!hreq.getScheme().equalsIgnoreCase(url.getProtocol()))
            return false;
        if (!hreq.getServerName().equalsIgnoreCase(url.getHost()))
            return false;
        int serverPort = hreq.getServerPort();
        if (serverPort == -1) {
            if ("https".equals(hreq.getScheme()))
                serverPort = 443;
            else
                serverPort = 80;
        }
        int urlPort = url.getPort();
        if (urlPort == -1) {
            if ("https".equals(url.getProtocol()))
                urlPort = 443;
            else
                urlPort = 80;
        }
        if (serverPort != urlPort)
            return (false);

        String contextPath = getRequest().getContextPath();
        if (contextPath != null) {
            String file = url.getFile();
            if ((file == null) || !file.startsWith(contextPath))
                return (false);
            String tok = ";" + DEFAULT_SESSION_ID_PARAMETER_NAME + "=" + session.getId();
            if (file.indexOf(tok, contextPath.length()) >= 0)
                return (false);
        }
        return (true);
    }

    private String toAbsolute(String location) {

        if (location == null)
            return (location);

        boolean leadingSlash = location.startsWith("/");

        if (leadingSlash || !hasScheme(location)) {

            StringBuilder buf = new StringBuilder();

            String scheme = request.getScheme();
            String name = request.getServerName();
            int port = request.getServerPort();

            try {
                buf.append(scheme).append("://").append(name);
                if ((scheme.equals("http") && port != 80)
                        || (scheme.equals("https") && port != 443)) {
                    buf.append(':').append(port);
                }
                if (!leadingSlash) {
                    String relativePath = request.getRequestURI();
                    int pos = relativePath.lastIndexOf('/');
                    relativePath = relativePath.substring(0, pos);

                    String encodedURI = URLEncoder.encode(relativePath, getCharacterEncoding());
                    buf.append(encodedURI).append('/');
                }
                buf.append(location);
            } catch (IOException e) {
                IllegalArgumentException iae = new IllegalArgumentException(location);
                iae.initCause(e);
                throw iae;
            }

            return buf.toString();

        } else {
            return location;
        }
    }

    public static boolean isSchemeChar(char c) {
        return Character.isLetterOrDigit(c) ||
                c == '+' || c == '-' || c == '.';
    }

    private boolean hasScheme(String uri) {
        int len = uri.length();
        for (int i = 0; i < len; i++) {
            char c = uri.charAt(i);
            if (c == ':') {
                return i > 0;
            } else if (!isSchemeChar(c)) {
                return false;
            }
        }
        return false;
    }

    protected String toEncoded(String url, String sessionId) {
        if ((url == null) || (sessionId == null))
            return (url);
        String path = url;
        String query = "";
        String anchor = "";
        int question = url.indexOf('?');
        if (question >= 0) {
            path = url.substring(0, question);
            query = url.substring(question);
        }
        int pound = path.indexOf('#');
        if (pound >= 0) {
            anchor = path.substring(pound);
            path = path.substring(0, pound);
        }
        StringBuilder sb = new StringBuilder(path);
        if (sb.length() > 0) {
            sb.append(";");
            sb.append(DEFAULT_SESSION_ID_PARAMETER_NAME);
            sb.append("=");
            sb.append(sessionId);
        }
        sb.append(anchor);
        sb.append(query);
        return (sb.toString());
    }
}
