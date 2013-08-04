
package com.hwlcn.ldap.ldap.protocol;



import com.hwlcn.ldap.ldap.sdk.Control;
import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

@InternalUseOnly()
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface LDAPResponse
{

  Control[] NO_CONTROLS = new Control[0];


  int getMessageID();

  void toString(final StringBuilder buffer);
}
