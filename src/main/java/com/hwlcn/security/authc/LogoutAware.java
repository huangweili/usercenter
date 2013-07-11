package com.hwlcn.security.authc;

import com.hwlcn.security.subject.PrincipalCollection;

public interface LogoutAware {


    public void onLogout(PrincipalCollection principals);
}
