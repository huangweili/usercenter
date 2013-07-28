package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.util.List;

import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface ReadOnlyLDAPRequest
       extends Serializable
{

  List<Control> getControlList();


  boolean hasControl();


  boolean hasControl(final String oid);


  Control getControl(final String oid);


  long getResponseTimeoutMillis(final LDAPConnection connection);



  boolean followReferrals(final LDAPConnection connection);


  LDAPRequest duplicate();


  LDAPRequest duplicate(final Control[] controls);

  @Override()
  String toString();

  void toString(final StringBuilder buffer);
}
