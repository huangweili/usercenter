package com.hwlcn.security.web.util;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;

public class SavedRequest implements Serializable {

    private String method;
    private String queryString;
    private String requestURI;

    public SavedRequest(HttpServletRequest request) {
        this.method = request.getMethod();
        this.queryString = request.getQueryString();
        this.requestURI = request.getRequestURI();
    }

    public String getMethod() {
        return method;
    }

    public String getQueryString() {
        return queryString;
    }

    public String getRequestURI() {
        return requestURI;
    }

    public String getRequestUrl() {
        StringBuilder requestUrl = new StringBuilder(getRequestURI());
        if (getQueryString() != null) {
            requestUrl.append("?").append(getQueryString());
        }
        return requestUrl.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SavedRequest that = (SavedRequest) o;

        if (method != null ? !method.equals(that.method) : that.method != null) return false;
        if (queryString != null ? !queryString.equals(that.queryString) : that.queryString != null) return false;
        if (requestURI != null ? !requestURI.equals(that.requestURI) : that.requestURI != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = method != null ? method.hashCode() : 0;
        result = 31 * result + (queryString != null ? queryString.hashCode() : 0);
        result = 31 * result + (requestURI != null ? requestURI.hashCode() : 0);
        return result;
    }
}
