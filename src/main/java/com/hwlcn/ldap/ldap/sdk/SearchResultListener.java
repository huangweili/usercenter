package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;

import com.hwlcn.core.annotation.Extensible;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface SearchResultListener
       extends Serializable
{

  void searchEntryReturned(final SearchResultEntry searchEntry);


  void searchReferenceReturned(final SearchResultReference searchReference);
}
