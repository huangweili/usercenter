package com.hwlcn.security.authc;

import com.hwlcn.security.subject.PrincipalCollection;

public interface AuthenticationListener {


    void onSuccess(AuthenticationToken token, AuthenticationInfo info);

    void onFailure(AuthenticationToken token, AuthenticationException ae);

    void onLogout(PrincipalCollection principals);
}
