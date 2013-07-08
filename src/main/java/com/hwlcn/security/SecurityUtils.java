package com.hwlcn.security;

import com.hwlcn.security.mgt.SecurityManager;
import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.subject.SubjectBuilder;
import com.hwlcn.security.util.ThreadContext;


public abstract class SecurityUtils {


    private static SecurityManager securityManager;

    //获取线程内的对象
    public static Subject getSubject() {
        Subject subject = ThreadContext.getSubject();
        if (subject == null) {
            subject = (new SubjectBuilder()).buildSubject();
            ThreadContext.bind(subject);
        }
        return subject;
    }


    public static void setSecurityManager(SecurityManager securityManager) {
        SecurityUtils.securityManager = securityManager;
    }


    public static SecurityManager getSecurityManager() throws UnavailableSecurityManagerException {
        SecurityManager securityManager = ThreadContext.getSecurityManager();
        if (securityManager == null) {
            securityManager = SecurityUtils.securityManager;
        }
        if (securityManager == null) {
            String msg = "No SecurityManager accessible to the calling code, either bound to the " +
                    ThreadContext.class.getName() + " or as a vm static singleton.  This is an invalid application " +
                    "configuration.";
            throw new UnavailableSecurityManagerException(msg);
        }
        return securityManager;
    }
}
