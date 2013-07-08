package com.hwlcn.security.web.filter;

import com.hwlcn.security.util.AntPathMatcher;
import com.hwlcn.security.util.PatternMatcher;
import com.hwlcn.security.util.StringUtils;
import com.hwlcn.security.web.servlet.AdviceFilter;
import com.hwlcn.security.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.LinkedHashMap;
import java.util.Map;

public abstract class PathMatchingFilter extends AdviceFilter implements PathConfigProcessor {


    private static final Logger log = LoggerFactory.getLogger(PathMatchingFilter.class);

    protected PatternMatcher pathMatcher = new AntPathMatcher();

    protected Map<String, Object> appliedPaths = new LinkedHashMap<String, Object>();

    public Filter processPathConfig(String path, String config) {
        String[] values = null;
        if (config != null) {
            values = StringUtils.split(config);
        }

        this.appliedPaths.put(path, values);
        return this;
    }


    protected String getPathWithinApplication(ServletRequest request) {
        return WebUtils.getPathWithinApplication(WebUtils.toHttp(request));
    }

    protected boolean pathsMatch(String path, ServletRequest request) {
        String requestURI = getPathWithinApplication(request);
        if (log.isTraceEnabled()) {
            log.trace("Attempting to match pattern '{}' with current requestURI '{}'...", path, requestURI);
        }
        return pathsMatch(path, requestURI);
    }

    protected boolean pathsMatch(String pattern, String path) {
        return pathMatcher.matches(pattern, path);
    }

    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {

        if (this.appliedPaths == null || this.appliedPaths.isEmpty()) {
            if (log.isTraceEnabled()) {
                log.trace("appliedPaths property is null or empty.  This Filter will passthrough immediately.");
            }
            return true;
        }

        for (String path : this.appliedPaths.keySet()) {
            if (pathsMatch(path, request)) {
                if (log.isTraceEnabled()) {
                    log.trace("Current requestURI matches pattern '{}'.  Determining filter chain execution...", path);
                }
                Object config = this.appliedPaths.get(path);
                return isFilterChainContinued(request, response, path, config);
            }
        }

        return true;
    }


    private boolean isFilterChainContinued(ServletRequest request, ServletResponse response,
                                           String path, Object pathConfig) throws Exception {

        if (isEnabled(request, response, path, pathConfig)) {
            if (log.isTraceEnabled()) {
                log.trace("Filter '{}' is enabled for the current request under path '{}' with config [{}].  " +
                        "Delegating to subclass implementation for 'onPreHandle' check.",
                        new Object[]{getName(), path, pathConfig});
            }
            return onPreHandle(request, response, pathConfig);
        }

        if (log.isTraceEnabled()) {
            log.trace("Filter '{}' is disabled for the current request under path '{}' with config [{}].  " +
                    "The next element in the FilterChain will be called immediately.",
                    new Object[]{getName(), path, pathConfig});
        }
        return true;
    }

    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        return true;
    }

    protected boolean isEnabled(ServletRequest request, ServletResponse response, String path, Object mappedValue)
            throws Exception {
        return isEnabled(request, response);
    }
}
