package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum OperationType
{

  ABANDON,

  ADD,

  BIND,

  COMPARE,

  DELETE,

  EXTENDED,

  MODIFY,

  MODIFY_DN,

  SEARCH,

  UNBIND;
}
