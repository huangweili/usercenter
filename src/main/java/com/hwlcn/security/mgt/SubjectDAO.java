package com.hwlcn.security.mgt;

import com.hwlcn.security.subject.Subject;


public interface SubjectDAO {

    Subject save(Subject subject);

    void delete(Subject subject);
}
