package com.hwlcn.ldap.ldap.sdk;



import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface UnsolicitedNotificationHandler
{

  void handleUnsolicitedNotification(final LDAPConnection connection,
                                     final ExtendedResult notification);
}
