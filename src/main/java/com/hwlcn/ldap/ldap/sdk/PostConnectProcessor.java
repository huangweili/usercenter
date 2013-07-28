package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface PostConnectProcessor
{

  void processPreAuthenticatedConnection(final LDAPConnection connection)
       throws LDAPException;


  void processPostAuthenticatedConnection(final LDAPConnection connection)
       throws LDAPException;
}
