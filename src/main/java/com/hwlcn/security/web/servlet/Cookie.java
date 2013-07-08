package com.hwlcn.security.web.servlet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface Cookie {

    public static final String DELETED_COOKIE_VALUE = "deleteMe";

    public static final int ONE_YEAR = 60 * 60 * 24 * 365;

    public static final String ROOT_PATH = "/";

    String getName();

    void setName(String name);

    String getValue();

    void setValue(String value);

    String getComment();

    void setComment(String comment);

    String getDomain();

    void setDomain(String domain);

    int getMaxAge();

    void setMaxAge(int maxAge);

    String getPath();

    void setPath(String path);

    boolean isSecure();

    void setSecure(boolean secure);

    int getVersion();

    void setVersion(int version);

    void setHttpOnly(boolean httpOnly);

    boolean isHttpOnly();

    void saveTo(HttpServletRequest request, HttpServletResponse response);

    void removeFrom(HttpServletRequest request, HttpServletResponse response);

    String readValue(HttpServletRequest request, HttpServletResponse response);
}
