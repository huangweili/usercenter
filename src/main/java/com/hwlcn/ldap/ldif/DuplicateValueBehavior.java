package com.hwlcn.ldap.ldif;



import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum DuplicateValueBehavior
{

  STRIP,



  RETAIN,


  REJECT;
}
