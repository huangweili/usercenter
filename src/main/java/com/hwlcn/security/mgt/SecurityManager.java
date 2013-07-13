package com.hwlcn.security.mgt;

import com.hwlcn.security.authc.AuthenticationException;
import com.hwlcn.security.authc.AuthenticationToken;
import com.hwlcn.security.authc.Authenticator;
import com.hwlcn.security.session.mgt.SessionManager;
import com.hwlcn.security.authz.Authorizer;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.subject.SubjectContext;


public interface SecurityManager extends Authenticator, Authorizer, SessionManager {

    Subject login(Subject subject, AuthenticationToken authenticationToken) throws AuthenticationException;

    void logout(Subject subject);

    Subject createSubject(SubjectContext context);

}
