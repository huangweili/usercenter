package com.hwlcn.security.web.util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;


public class RedirectView {

    public static final String DEFAULT_ENCODING_SCHEME = "UTF-8";

    private String url;

    private boolean contextRelative = false;

    private boolean http10Compatible = true;    //http 1.0 协议 适配

    private String encodingScheme = DEFAULT_ENCODING_SCHEME;


    public RedirectView() {
        setUrl("/");
    }


    public RedirectView(String url) {
        setUrl(url);
    }


    public RedirectView(String url, boolean contextRelative) {
        this(url);
        this.contextRelative = contextRelative;
    }


    public RedirectView(String url, boolean contextRelative, boolean http10Compatible) {
        this(url);
        this.contextRelative = contextRelative;
        this.http10Compatible = http10Compatible;
    }


    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }


    public void setContextRelative(boolean contextRelative) {
        this.contextRelative = contextRelative;
    }


    public void setHttp10Compatible(boolean http10Compatible) {
        this.http10Compatible = http10Compatible;
    }


    @SuppressWarnings({"UnusedDeclaration"})
    public void setEncodingScheme(String encodingScheme) {
        this.encodingScheme = encodingScheme;
    }


    public final void renderMergedOutputModel(
            Map model, HttpServletRequest request, HttpServletResponse response) throws IOException {

        StringBuilder targetUrl = new StringBuilder();
        if (this.contextRelative && getUrl().startsWith("/")) {
            targetUrl.append(request.getContextPath());
        }
        targetUrl.append(getUrl());
        appendQueryProperties(targetUrl, model, this.encodingScheme);
        sendRedirect(request, response, targetUrl.toString(), this.http10Compatible);
    }

    //构造查询
    protected void appendQueryProperties(StringBuilder targetUrl, Map model, String encodingScheme)
            throws UnsupportedEncodingException {

        String fragment = null;
        int anchorIndex = targetUrl.toString().indexOf('#');
        if (anchorIndex > -1) {
            fragment = targetUrl.substring(anchorIndex);
            targetUrl.delete(anchorIndex, targetUrl.length());
        }

        boolean first = (getUrl().indexOf('?') < 0);
        Map queryProps = queryProperties(model);

        if (queryProps != null) {
            for (Object o : queryProps.entrySet()) {
                if (first) {
                    targetUrl.append('?');
                    first = false;
                } else {
                    targetUrl.append('&');
                }
                Map.Entry entry = (Map.Entry) o;
                String encodedKey = urlEncode(entry.getKey().toString(), encodingScheme);
                String encodedValue =
                        (entry.getValue() != null ? urlEncode(entry.getValue().toString(), encodingScheme) : "");
                targetUrl.append(encodedKey).append('=').append(encodedValue);
            }
        }

        if (fragment != null) {
            targetUrl.append(fragment);
        }
    }


    protected String urlEncode(String input, String encodingScheme) throws UnsupportedEncodingException {
        return URLEncoder.encode(input, encodingScheme);
    }

    protected Map queryProperties(Map model) {
        return model;
    }


    @SuppressWarnings({"UnusedDeclaration"})
    protected void sendRedirect(HttpServletRequest request, HttpServletResponse response,
                                String targetUrl, boolean http10Compatible) throws IOException {
        if (http10Compatible) {
            response.sendRedirect(response.encodeRedirectURL(targetUrl));
        } else {
            //ajax 处理
            response.setStatus(303);
            response.setHeader("Location", response.encodeRedirectURL(targetUrl));
        }
    }

}
