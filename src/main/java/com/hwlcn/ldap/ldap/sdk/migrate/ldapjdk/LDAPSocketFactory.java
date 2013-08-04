package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import java.net.Socket;

import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface LDAPSocketFactory
{

  Socket makeSocket(final String host, final int port)
         throws LDAPException;
}
