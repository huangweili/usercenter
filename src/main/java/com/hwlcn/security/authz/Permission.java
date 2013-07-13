
package com.hwlcn.security.authz;

public interface Permission {


    boolean implies(Permission p);
}
