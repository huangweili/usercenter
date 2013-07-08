package com.hwlcn.security.web.mgt;

import com.hwlcn.security.mgt.SecurityManager;


/**
 * Web 应用的安全管理类 接口
 */
public interface WebSecurityManager extends SecurityManager {


    boolean isHttpSessionMode();
}
