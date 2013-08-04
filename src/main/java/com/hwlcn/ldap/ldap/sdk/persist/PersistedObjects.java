
package com.hwlcn.ldap.ldap.sdk.persist;



import java.io.Serializable;

import com.hwlcn.ldap.ldap.sdk.Entry;
import com.hwlcn.ldap.ldap.sdk.EntrySource;
import com.hwlcn.ldap.ldap.sdk.LDAPEntrySource;
import com.hwlcn.ldap.ldap.sdk.LDAPException;
import com.hwlcn.ldap.ldap.sdk.SearchResult;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.persist.PersistMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;



@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class PersistedObjects<T>
       implements Serializable
{

  private static final long serialVersionUID = 7430494946944736169L;

  private final EntrySource entrySource;

  private final LDAPPersister<T> persister;


  PersistedObjects(final LDAPPersister<T> persister,
                   final EntrySource entrySource)
  {
    this.persister   = persister;
    this.entrySource = entrySource;
  }


  public T next()
         throws LDAPPersistException
  {
    final Entry entry;
    try
    {
      entry = entrySource.nextEntry();
    }
    catch (Exception e)
    {
      debugException(e);

      final Throwable cause = e.getCause();
      if ((cause != null) && (cause instanceof LDAPException))
      {
        throw new LDAPPersistException((LDAPException) cause);
      }
      else
      {
        throw new LDAPPersistException(
             ERR_OBJECT_SEARCH_RESULTS_ENTRY_SOURCE_EXCEPTION.get(
                  getExceptionMessage(e)), e);
      }
    }

    if (entry == null)
    {
      return null;
    }
    else
    {
      return persister.decode(entry);
    }
  }


  public void close()
  {
    entrySource.close();
  }


  public SearchResult getSearchResult()
  {
    if (entrySource instanceof LDAPEntrySource)
    {
      return ((LDAPEntrySource) entrySource).getSearchResult();
    }
    else
    {
      return null;
    }
  }
}
