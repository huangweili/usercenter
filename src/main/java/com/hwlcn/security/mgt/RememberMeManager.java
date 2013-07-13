package com.hwlcn.security.mgt;

import com.hwlcn.security.authc.AuthenticationException;
import com.hwlcn.security.authc.AuthenticationInfo;
import com.hwlcn.security.authc.AuthenticationToken;
import com.hwlcn.security.subject.PrincipalCollection;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.subject.SubjectContext;

public interface RememberMeManager {

    PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext);

    void forgetIdentity(SubjectContext subjectContext);

    void onSuccessfulLogin(Subject subject, AuthenticationToken token, AuthenticationInfo info);

    void onFailedLogin(Subject subject, AuthenticationToken token, AuthenticationException ae);

    void onLogout(Subject subject);
}
