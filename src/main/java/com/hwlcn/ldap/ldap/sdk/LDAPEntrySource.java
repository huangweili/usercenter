package com.hwlcn.ldap.ldap.sdk;



import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import com.hwlcn.core.annotation.InternalUseOnly;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides an {@link com.hwlcn.ldap.ldap.sdk.EntrySource} that will read entries matching a
 * given set of search criteria from an LDAP directory server.  It may
 * optionally close the associated connection after all entries have been read.
 * <BR><BR>
 * This implementation processes the search asynchronously, which provides two
 * benefits:
 * <UL>
 *   <LI>It makes it easier to provide a throttling mechanism to prevent the
 *       entries from piling up and causing the client to run out of memory if
 *       the server returns them faster than the client can process them.  If
 *       this occurs, then the client will queue up a small number of entries
 *       but will then push back against the server to block it from sending
 *       additional entries until the client can catch up.  In this case, no
 *       entries should be lost, although some servers may impose limits on how
 *       long a search may be active or other forms of constraints.</LI>
 *   <LI>It makes it possible to abandon the search if the entry source is no
 *       longer needed (as signified by calling the {@link #close} method) and
 *       the caller intends to stop iterating through the results.</LI>
 * </UL>
 * <H2>Example</H2>
 * The following example demonstrates the process that may be used for iterating
 * across all entries containing the {@code person} object class using the LDAP
 * entry source API:
 * <PRE>
 *   SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
 *        SearchScope.SUB, "(objectClass=person)");
 *   LDAPEntrySource entrySource = new LDAPEntrySource(connection,
 *        searchRequest, false);
 *
 *   try
 *   {
 *     while (true)
 *     {
 *       try
 *       {
 *         Entry entry = entrySource.nextEntry();
 *         if (entry == null)
 *         {
 *           // There are no more entries to be read.
 *           break;
 *         }
 *         else
 *         {
 *           // Do something with the entry here.
 *         }
 *       }
 *       catch (SearchResultReferenceEntrySourceException e)
 *       {
 *         // The directory server returned a search result reference.
 *         SearchResultReference searchReference = e.getSearchReference();
 *       }
 *       catch (EntrySourceException e)
 *       {
 *         // Some kind of problem was encountered (e.g., the connection is no
 *         // longer valid).  See if we can continue reading entries.
 *         if (! e.mayContinueReading())
 *         {
 *           break;
 *         }
 *       }
 *     }
 *   }
 *   finally
 *   {
 *     entrySource.close();
 *   }
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDAPEntrySource
       extends EntrySource
       implements AsyncSearchResultListener
{

  private static final String END_OF_RESULTS = "END OF RESULTS";



  private static final long serialVersionUID = 1080386705549149135L;



  private final AsyncRequestID asyncRequestID;

  private final AtomicBoolean closed;

  private final AtomicReference<SearchResult> searchResult;

  private final boolean closeConnection;

  private final LDAPConnection connection;

  private final LinkedBlockingQueue<Object> queue;



  public LDAPEntrySource(final LDAPConnection connection,
                         final SearchRequest searchRequest,
                         final boolean closeConnection)
         throws LDAPException
  {
    this(connection, searchRequest, closeConnection, 100);
  }


  public LDAPEntrySource(final LDAPConnection connection,
                         final SearchRequest searchRequest,
                         final boolean closeConnection,
                         final int queueSize)
         throws LDAPException
  {
    ensureNotNull(connection, searchRequest);
    ensureTrue(queueSize > 0,
               "LDAPEntrySource.queueSize must be greater than 0.");

    this.connection      = connection;
    this.closeConnection = closeConnection;

    if (searchRequest.getSearchResultListener() != null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
                              ERR_LDAP_ENTRY_SOURCE_REQUEST_HAS_LISTENER.get());
    }

    closed       = new AtomicBoolean(false);
    searchResult = new AtomicReference<SearchResult>();
    queue        = new LinkedBlockingQueue<Object>(queueSize);

    final SearchRequest r = new SearchRequest(this, searchRequest.getControls(),
         searchRequest.getBaseDN(), searchRequest.getScope(),
         searchRequest.getDereferencePolicy(), searchRequest.getSizeLimit(),
         searchRequest.getTimeLimitSeconds(), searchRequest.typesOnly(),
         searchRequest.getFilter(), searchRequest.getAttributes());
    asyncRequestID = connection.asyncSearch(r);
  }



  @Override()
  public Entry nextEntry()
         throws EntrySourceException
  {
    while (true)
    {
      if (closed.get() && queue.isEmpty())
      {
        return null;
      }

      final Object o;
      try
      {
        o = queue.poll(10L, TimeUnit.MILLISECONDS);
      }
      catch (InterruptedException ie)
      {
        debugException(ie);
        continue;
      }

      if (o != null)
      {
        if (o == END_OF_RESULTS)
        {
          return null;
        }
        else if (o instanceof Entry)
        {
          return (Entry) o;
        }
        else
        {
          throw (EntrySourceException) o;
        }
      }
    }
  }



  @Override()
  public void close()
  {
    closeInternal(true);
  }



  private void closeInternal(final boolean abandon)
  {
    addToQueue(END_OF_RESULTS);

    if (closed.compareAndSet(false, true))
    {
      if (abandon)
      {
        try
        {
          connection.abandon(asyncRequestID);
        }
        catch (Exception e)
        {
          debugException(e);
        }
      }

      if (closeConnection)
      {
        connection.close();
      }
    }
  }



  public SearchResult getSearchResult()
  {
    return searchResult.get();
  }


  @InternalUseOnly()
  public void searchEntryReturned(final SearchResultEntry searchEntry)
  {
    addToQueue(searchEntry);
  }

  @InternalUseOnly()
  public void searchReferenceReturned(
                   final SearchResultReference searchReference)
  {
    addToQueue(new SearchResultReferenceEntrySourceException(searchReference));
  }


  @InternalUseOnly()
  public void searchResultReceived(final AsyncRequestID requestID,
                                   final SearchResult searchResult)
  {
    this.searchResult.set(searchResult);

    if (! searchResult.getResultCode().equals(ResultCode.SUCCESS))
    {
      addToQueue(new EntrySourceException(false,
           new LDAPSearchException(searchResult)));
    }

    closeInternal(false);
  }


  private void addToQueue(final Object o)
  {
    while (true)
    {
      if (closed.get())
      {
        return;
      }

      try
      {
        if (queue.offer(o, 100L, TimeUnit.MILLISECONDS))
        {
          return;
        }
      }
      catch (InterruptedException ie)
      {
        debugException(ie);
      }
    }
  }
}
