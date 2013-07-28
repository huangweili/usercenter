package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import com.hwlcn.ldap.util.Debug;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;



/**
 * This class defines an object that provides information about a request that
 * was initiated asynchronously.  It may be used to abandon or cancel the
 * associated request.  This class also implements the
 * {@code java.util.concurrent.Future} interface, so it may be used in that
 * manner.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example initiates an asynchronous modify operation and then
 * attempts to abandon it:
 * <PRE>
 *   Modification mod = new Modification(ModificationType.REPLACE,
 *        "description", "This is the new description.");
 *   ModifyRequest modifyRequest =
 *        new ModifyRequest("dc=example,dc=com", mod);
 *
 *   AsyncRequestID asyncRequestID =
 *        connection.asyncModify(modifyRequest, myAsyncResultListener);
 *
 *   // Assume that we've waited a reasonable amount of time but the modify
 *   // hasn't completed yet so we'll try to abandon it.
 *
 *   connection.abandon(asyncRequestID);
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AsyncRequestID
       implements Serializable, Future<LDAPResult>
{

  private static final long serialVersionUID = 8244005138437962030L;


  private final ArrayBlockingQueue<LDAPResult> resultQueue;

  private final AtomicBoolean cancelRequested;

  private final AtomicReference<LDAPResult> result;


  private final int messageID;

  private final LDAPConnection connection;

  private volatile AsyncTimeoutTimerTask timerTask;



  AsyncRequestID(final int messageID, final LDAPConnection connection)
  {
    this.messageID  = messageID;
    this.connection = connection;

    resultQueue     = new ArrayBlockingQueue<LDAPResult>(1);
    cancelRequested = new AtomicBoolean(false);
    result          = new AtomicReference<LDAPResult>();
    timerTask       = null;
  }


  public int getMessageID()
  {
    return messageID;
  }




  public boolean cancel(final boolean mayInterruptIfRunning)
  {

    if (isDone())
    {
      return false;
    }


    try
    {
      cancelRequested.set(true);
      result.compareAndSet(null,
           new LDAPResult(messageID, ResultCode.USER_CANCELED,
                INFO_ASYNC_REQUEST_USER_CANCELED.get(), null,
                StaticUtils.NO_STRINGS, StaticUtils.NO_CONTROLS));

      connection.abandon(this);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    return true;
  }



  public boolean isCancelled()
  {
    return cancelRequested.get();
  }




  public boolean isDone()
  {
    if (cancelRequested.get())
    {
      return true;
    }

    if (result.get() != null)
    {
      return true;
    }

    final LDAPResult newResult = resultQueue.poll();
    if (newResult != null)
    {
      result.set(newResult);
      return true;
    }

    return false;
  }




  public LDAPResult get()
         throws InterruptedException
  {
    final long maxWaitTime =
         connection.getConnectionOptions().getResponseTimeoutMillis();

    try
    {
      return get(maxWaitTime, TimeUnit.MILLISECONDS);
    }
    catch (final TimeoutException te)
    {
      Debug.debugException(te);
      return new LDAPResult(messageID, ResultCode.TIMEOUT, te.getMessage(),
           null, StaticUtils.NO_STRINGS, StaticUtils.NO_CONTROLS);
    }
  }



  public LDAPResult get(final long timeout, final TimeUnit timeUnit)
         throws InterruptedException, TimeoutException
  {
    final LDAPResult newResult = resultQueue.poll();
    if (newResult != null)
    {
      result.set(newResult);
      return newResult;
    }

    final LDAPResult previousResult = result.get();
    if (previousResult != null)
    {
      return previousResult;
    }

    final LDAPResult resultAfterWaiting = resultQueue.poll(timeout, timeUnit);
    if (resultAfterWaiting == null)
    {
      final long timeoutMillis = timeUnit.toMillis(timeout);
      throw new TimeoutException(
           WARN_ASYNC_REQUEST_GET_TIMEOUT.get(timeoutMillis));
    }
    else
    {
      result.set(resultAfterWaiting);
      return resultAfterWaiting;
    }
  }




  void setTimerTask(final AsyncTimeoutTimerTask timerTask)
  {
    this.timerTask = timerTask;
  }



  void setResult(final LDAPResult result)
  {
    resultQueue.offer(result);

    final AsyncTimeoutTimerTask t = timerTask;
    if (t != null)
    {
      t.cancel();
      connection.getTimer().purge();
      timerTask = null;
    }
  }



  @Override()
  public int hashCode()
  {
    return messageID;
  }




  @Override()
  public boolean equals(final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (o instanceof AsyncRequestID)
    {
      return (((AsyncRequestID) o).messageID == messageID);
    }
    else
    {
      return false;
    }
  }


  @Override()
  public String toString()
  {
    return "AsyncRequestID(messageID=" + messageID + ')';
  }
}
