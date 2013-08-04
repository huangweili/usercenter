package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface LDAPRebind
{

  LDAPRebindAuth getRebindAuthentication(final String host, final int port);
}
