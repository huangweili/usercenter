package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;

import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class PasswordProvider
       implements Serializable
{

  private static final long serialVersionUID = -1582416755360005908L;



  public abstract byte[] getPasswordBytes()
         throws LDAPException;
}
