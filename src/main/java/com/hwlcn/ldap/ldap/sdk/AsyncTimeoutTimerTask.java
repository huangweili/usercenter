package com.hwlcn.ldap.ldap.sdk;



import java.util.TimerTask;

import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.ldap.util.Debug;
import com.hwlcn.ldap.util.StaticUtils;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;


final class AsyncTimeoutTimerTask
      extends TimerTask
{
  private final CommonAsyncHelper helper;



  AsyncTimeoutTimerTask(final CommonAsyncHelper helper)
  {
    this.helper = helper;
  }

  @Override()
  public void run()
  {
    final long waitTimeNanos = System.nanoTime() - helper.getCreateTimeNanos();
    final long waitTimeMillis = waitTimeNanos / 1000000L;

    final LDAPConnection conn = helper.getConnection();
    final boolean abandon = conn.getConnectionOptions().abandonOnTimeout();

    final String message;
    if (abandon)
    {
      message = INFO_ASYNC_OPERATION_TIMEOUT_WITH_ABANDON.get(waitTimeMillis);
    }
    else
    {
      message =
           INFO_ASYNC_OPERATION_TIMEOUT_WITHOUT_ABANDON.get(waitTimeMillis);
    }

    final LDAPResponse response;
    switch (helper.getOperationType())
    {
      case ADD:
      case DELETE:
      case MODIFY:
      case MODIFY_DN:
        response = new LDAPResult(helper.getAsyncRequestID().getMessageID(),
             ResultCode.TIMEOUT, message, null, StaticUtils.NO_STRINGS,
             StaticUtils.NO_CONTROLS);
        break;
      case COMPARE:
        response = new CompareResult(helper.getAsyncRequestID().getMessageID(),
             ResultCode.TIMEOUT, message, null, StaticUtils.NO_STRINGS,
             StaticUtils.NO_CONTROLS);
        break;
      case SEARCH:
        final AsyncSearchHelper searchHelper = (AsyncSearchHelper) helper;
        response = new SearchResult(helper.getAsyncRequestID().getMessageID(),
             ResultCode.TIMEOUT, message, null, StaticUtils.NO_STRINGS,
             searchHelper.getNumEntries(), searchHelper.getNumReferences(),
             StaticUtils.NO_CONTROLS);
        break;
      default:
        return;
    }

    try
    {
      helper.responseReceived(response);
      if (abandon)
      {
        conn.abandon(helper.getAsyncRequestID());
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
    }
  }
}
