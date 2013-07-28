package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

@InternalUseOnly()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
interface ResponseAcceptor
{

  void responseReceived(final LDAPResponse response)
       throws LDAPException;
}
