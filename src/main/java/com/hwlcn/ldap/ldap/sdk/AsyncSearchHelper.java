package com.hwlcn.ldap.ldap.sdk;



import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;

import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.ldap.util.DebugType;
import com.hwlcn.core.annotation.InternalUseOnly;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;


@InternalUseOnly()
final class AsyncSearchHelper
      implements CommonAsyncHelper, IntermediateResponseListener
{

  private static final long serialVersionUID = 1006163445423767824L;

  private final AsyncRequestID asyncRequestID;

  private final AsyncSearchResultListener resultListener;

  private final AtomicBoolean responseReturned;

  private int numEntries;

  private int numReferences;

  private final IntermediateResponseListener intermediateResponseListener;

  private final LDAPConnection connection;

  private final long createTime;

  @InternalUseOnly()
  AsyncSearchHelper(final LDAPConnection connection, final int messageID,
       final AsyncSearchResultListener resultListener,
       final IntermediateResponseListener intermediateResponseListener)
  {
    this.connection                   = connection;
    this.resultListener               = resultListener;
    this.intermediateResponseListener = intermediateResponseListener;

    numEntries       = 0;
    numReferences    = 0;
    asyncRequestID   = new AsyncRequestID(messageID, connection);
    responseReturned = new AtomicBoolean(false);
    createTime       = System.nanoTime();
  }

  public AsyncRequestID getAsyncRequestID()
  {
    return asyncRequestID;
  }

  public LDAPConnection getConnection()
  {
    return connection;
  }

  public long getCreateTimeNanos()
  {
    return createTime;
  }

  public OperationType getOperationType()
  {
    return OperationType.SEARCH;
  }

  int getNumEntries()
  {
    return numEntries;
  }

  int getNumReferences()
  {
    return numReferences;
  }

  @InternalUseOnly()
  public void responseReceived(final LDAPResponse response)
         throws LDAPException
  {
    if (responseReturned.get())
    {
      return;
    }

    if (response instanceof ConnectionClosedResponse)
    {
      final ConnectionClosedResponse ccr = (ConnectionClosedResponse) response;
      final String message = ccr.getMessage();
      if (message == null)
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_ASYNC_RESPONSE.get());
      }
      else
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_ASYNC_RESPONSE_WITH_MESSAGE.get(
                  message));
      }
    }
    else if (response instanceof SearchResultEntry)
    {
      numEntries++;
      resultListener.searchEntryReturned((SearchResultEntry) response);
    }
    else if (response instanceof SearchResultReference)
    {
      numReferences++;
      resultListener.searchReferenceReturned((SearchResultReference) response);
    }
    else
    {
      if (! responseReturned.compareAndSet(false, true))
      {
        return;
      }

      connection.getConnectionStatistics().incrementNumSearchResponses(
           numEntries, numReferences, System.nanoTime() - createTime);

      final SearchResult searchResult = (SearchResult) response;
      searchResult.setCounts(numEntries, null, numReferences, null);
      resultListener.searchResultReceived(asyncRequestID, searchResult);
      asyncRequestID.setResult(searchResult);
    }
  }

  @InternalUseOnly()
  public void intermediateResponseReturned(
                   final IntermediateResponse intermediateResponse)
  {
    if (intermediateResponseListener == null)
    {
      debug(Level.WARNING, DebugType.LDAP,
            WARN_INTERMEDIATE_RESPONSE_WITH_NO_LISTENER.get(
                 String.valueOf(intermediateResponse)));
    }
    else
    {
      intermediateResponseListener.intermediateResponseReturned(
           intermediateResponse);
    }
  }
}
