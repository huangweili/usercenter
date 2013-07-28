package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;



@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface DisconnectHandler
{

  void handleDisconnect(final LDAPConnection connection, final String host,
                        final int port, final DisconnectType disconnectType,
                        final String message, final Throwable cause);
}
