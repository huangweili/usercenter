
package com.hwlcn.security.web.util;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


public interface RequestPairSource {
    //获取ServletRequest 对象
    ServletRequest getServletRequest();

    //获取ServletResponse 对象
    ServletResponse getServletResponse();
}
