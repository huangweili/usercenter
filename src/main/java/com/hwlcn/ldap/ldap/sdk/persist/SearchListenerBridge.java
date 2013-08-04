
package com.hwlcn.ldap.ldap.sdk.persist;



import com.hwlcn.ldap.ldap.sdk.SearchResultEntry;
import com.hwlcn.ldap.ldap.sdk.SearchResultListener;
import com.hwlcn.ldap.ldap.sdk.SearchResultReference;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;



@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class SearchListenerBridge<T>
      implements SearchResultListener
{

  private static final long serialVersionUID = 1939354785788059032L;

  private final LDAPPersister<T> persister;

  private final ObjectSearchListener<T> listener;

  SearchListenerBridge(final LDAPPersister<T> persister,
                       final ObjectSearchListener<T> listener)
  {
    this.persister = persister;
    this.listener  = listener;
  }


  public void searchEntryReturned(final SearchResultEntry searchEntry)
  {
    try
    {
      listener.objectReturned(persister.decode(searchEntry));
    }
    catch (LDAPPersistException lpe)
    {
      debugException(lpe);
      listener.unparsableEntryReturned(searchEntry, lpe);
    }
  }


  public void searchReferenceReturned(
                   final SearchResultReference searchReference)
  {
    listener.searchReferenceReturned(searchReference);
  }
}
