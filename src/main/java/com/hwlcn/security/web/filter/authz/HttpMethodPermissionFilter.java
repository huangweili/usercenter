package com.hwlcn.security.web.filter.authz;

import com.hwlcn.security.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class HttpMethodPermissionFilter extends PermissionsAuthorizationFilter {

    private static final Logger log = LoggerFactory.getLogger(HttpMethodPermissionFilter.class);

    private final Map<String, String> httpMethodActions = new HashMap<String, String>();

    private static final String CREATE_ACTION = "create";
    private static final String READ_ACTION = "read";
    private static final String UPDATE_ACTION = "update";
    private static final String DELETE_ACTION = "delete";

    private static enum HttpMethodAction {

        DELETE(DELETE_ACTION),
        GET(READ_ACTION),
        HEAD(READ_ACTION),
        MKCOL(CREATE_ACTION),
        OPTIONS(READ_ACTION),
        POST(CREATE_ACTION),
        PUT(UPDATE_ACTION),
        TRACE(READ_ACTION);

        private final String action;

        private HttpMethodAction(String action) {
            this.action = action;
        }

        public String getAction() {
            return this.action;
        }
    }

    public HttpMethodPermissionFilter() {
        for (HttpMethodAction methodAction : HttpMethodAction.values()) {
            httpMethodActions.put(methodAction.name().toLowerCase(), methodAction.getAction());
        }
    }


    protected Map<String, String> getHttpMethodActions() {
        return this.httpMethodActions;
    }


    protected String getHttpMethodAction(ServletRequest request) {
        String method = ((HttpServletRequest) request).getMethod();
        return getHttpMethodAction(method);
    }


    protected String getHttpMethodAction(String method) {
        String lc = method.toLowerCase();
        String resolved = getHttpMethodActions().get(lc);
        return resolved != null ? resolved : method;
    }


    protected String[] buildPermissions(HttpServletRequest request, String[] configuredPerms, String action) {
        return buildPermissions(configuredPerms, action);
    }

    protected String[] buildPermissions(String[] configuredPerms, String action) {
        if (configuredPerms == null || configuredPerms.length <= 0 || !StringUtils.hasText(action)) {
            return configuredPerms;
        }

        String[] mappedPerms = new String[configuredPerms.length];

        for (int i = 0; i < configuredPerms.length; i++) {
            mappedPerms[i] = configuredPerms[i] + ":" + action;
        }

        if (log.isTraceEnabled()) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < mappedPerms.length; i++) {
                if (i > 0) {
                    sb.append(", ");
                }
                sb.append(mappedPerms[i]);
            }
            log.trace("MAPPED '{}' action to permission(s) '{}'", action, sb);
        }

        return mappedPerms;
    }

    @Override
    public boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws IOException {
        String[] perms = (String[]) mappedValue;
        String action = getHttpMethodAction(request);
        String[] resolvedPerms = buildPermissions(perms, action);
        return super.isAccessAllowed(request, response, resolvedPerms);
    }
}
