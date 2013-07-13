package com.hwlcn.security.mgt;

import com.hwlcn.security.subject.Subject;


public interface SessionStorageEvaluator {

    boolean isSessionStorageEnabled(Subject subject);

}
