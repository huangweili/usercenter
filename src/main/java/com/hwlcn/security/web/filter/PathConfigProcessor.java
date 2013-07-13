package com.hwlcn.security.web.filter;

import javax.servlet.Filter;


public interface PathConfigProcessor {

    Filter processPathConfig(String path, String config);
}
