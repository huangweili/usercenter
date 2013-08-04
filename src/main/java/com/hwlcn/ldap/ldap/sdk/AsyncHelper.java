package com.hwlcn.ldap.ldap.sdk;



import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;

import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.ldap.util.DebugType;
import com.hwlcn.core.annotation.InternalUseOnly;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;



@InternalUseOnly()
final class AsyncHelper
      implements CommonAsyncHelper, IntermediateResponseListener
{

  private static final long serialVersionUID = 7186731025240177443L;


  private final AsyncRequestID asyncRequestID;

  private final AsyncResultListener resultListener;

  private final AtomicBoolean responseReturned;

  private final OperationType operationType;

  private final IntermediateResponseListener intermediateResponseListener;

  private final LDAPConnection connection;

  private final long createTime;



  @InternalUseOnly()
  AsyncHelper(final LDAPConnection connection,
              final OperationType operationType, final int messageID,
              final AsyncResultListener resultListener,
              final IntermediateResponseListener intermediateResponseListener)
  {
    this.connection                   = connection;
    this.operationType                = operationType;
    this.resultListener               = resultListener;
    this.intermediateResponseListener = intermediateResponseListener;

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
    return operationType;
  }

  @InternalUseOnly()
  public void responseReceived(final LDAPResponse response)
         throws LDAPException
  {
    if (! responseReturned.compareAndSet(false, true))
    {
      return;
    }

    final long responseTime = System.nanoTime() - createTime;
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

    switch (operationType)
    {
      case ADD:
        connection.getConnectionStatistics().incrementNumAddResponses(
             responseTime);
        break;
      case DELETE:
        connection.getConnectionStatistics().incrementNumDeleteResponses(
             responseTime);
        break;
      case MODIFY:
        connection.getConnectionStatistics().incrementNumModifyResponses(
             responseTime);
        break;
      case MODIFY_DN:
        connection.getConnectionStatistics().incrementNumModifyDNResponses(
             responseTime);
        break;
    }

    final LDAPResult result = (LDAPResult) response;
    resultListener.ldapResultReceived(asyncRequestID, result);
    asyncRequestID.setResult(result);
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
