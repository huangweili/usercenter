package com.hwlcn.ldap.ldap.sdk;



import java.util.List;

import com.hwlcn.core.annotation.NotExtensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface ReadOnlySearchRequest
       extends ReadOnlyLDAPRequest
{

  String getBaseDN();


  SearchScope getScope();


  DereferencePolicy getDereferencePolicy();


  int getSizeLimit();


  int getTimeLimitSeconds();


  boolean typesOnly();


  Filter getFilter();

  List<String> getAttributeList();

  SearchRequest duplicate();


  SearchRequest duplicate(final Control[] controls);
}
