package com.hwlcn.security.mgt;

import com.hwlcn.security.subject.Subject;
import com.hwlcn.security.subject.SubjectContext;

public interface SubjectFactory {


    Subject createSubject(SubjectContext context);

}
