package com.hwlcn.ldap.ldap.sdk;



import java.io.Serializable;
import java.util.concurrent.atomic.AtomicLong;

import com.hwlcn.core.annotation.Mutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;


@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.MOSTLY_THREADSAFE)
public final class LDAPConnectionPoolStatistics
       implements Serializable
{

  private static final long serialVersionUID = 1493039391352814874L;



  private final AtomicLong numConnectionsClosedDefunct;

  private final AtomicLong numConnectionsClosedExpired;

  private final AtomicLong numConnectionsClosedUnneeded;

  private final AtomicLong numFailedCheckouts;

  private final AtomicLong numFailedConnectionAttempts;

  private final AtomicLong numReleasedValid;

  private final AtomicLong numSuccessfulCheckouts;


  private final AtomicLong numSuccessfulCheckoutsAfterWait;


  private final AtomicLong numSuccessfulCheckoutsNewConnection;


  private final AtomicLong numSuccessfulCheckoutsWithoutWait;

  private final AtomicLong numSuccessfulConnectionAttempts;

  private final AbstractConnectionPool pool;




  public LDAPConnectionPoolStatistics(final AbstractConnectionPool pool)
  {
    this.pool = pool;

    numSuccessfulConnectionAttempts     = new AtomicLong(0L);
    numFailedConnectionAttempts         = new AtomicLong(0L);
    numConnectionsClosedDefunct         = new AtomicLong(0L);
    numConnectionsClosedExpired         = new AtomicLong(0L);
    numConnectionsClosedUnneeded        = new AtomicLong(0L);
    numSuccessfulCheckouts              = new AtomicLong(0L);
    numSuccessfulCheckoutsAfterWait     = new AtomicLong(0L);
    numSuccessfulCheckoutsNewConnection = new AtomicLong(0L);
    numSuccessfulCheckoutsWithoutWait   = new AtomicLong(0L);
    numFailedCheckouts                  = new AtomicLong(0L);
    numReleasedValid                    = new AtomicLong(0L);
  }




  public void reset()
  {
    numSuccessfulConnectionAttempts.set(0L);
    numFailedConnectionAttempts.set(0L);
    numConnectionsClosedDefunct.set(0L);
    numConnectionsClosedExpired.set(0L);
    numConnectionsClosedUnneeded.set(0L);
    numSuccessfulCheckouts.set(0L);
    numSuccessfulCheckoutsAfterWait.set(0L);
    numSuccessfulCheckoutsNewConnection.set(0L);
    numSuccessfulCheckoutsWithoutWait.set(0L);
    numFailedCheckouts.set(0L);
    numReleasedValid.set(0L);
  }



  public long getNumSuccessfulConnectionAttempts()
  {
    return numSuccessfulConnectionAttempts.get();
  }



  void incrementNumSuccessfulConnectionAttempts()
  {
    numSuccessfulConnectionAttempts.incrementAndGet();
  }




  public long getNumFailedConnectionAttempts()
  {
    return numFailedConnectionAttempts.get();
  }



  void incrementNumFailedConnectionAttempts()
  {
    numFailedConnectionAttempts.incrementAndGet();
  }




  public long getNumConnectionsClosedDefunct()
  {
    return numConnectionsClosedDefunct.get();
  }


  void incrementNumConnectionsClosedDefunct()
  {
    numConnectionsClosedDefunct.incrementAndGet();
  }




  public long getNumConnectionsClosedExpired()
  {
    return numConnectionsClosedExpired.get();
  }


  void incrementNumConnectionsClosedExpired()
  {
    numConnectionsClosedExpired.incrementAndGet();
  }




  public long getNumConnectionsClosedUnneeded()
  {
    return numConnectionsClosedUnneeded.get();
  }


  void incrementNumConnectionsClosedUnneeded()
  {
    numConnectionsClosedUnneeded.incrementAndGet();
  }




  public long getNumSuccessfulCheckouts()
  {
    return numSuccessfulCheckouts.get();
  }




  public long getNumSuccessfulCheckoutsWithoutWaiting()
  {
    return numSuccessfulCheckoutsWithoutWait.get();
  }



  public long getNumSuccessfulCheckoutsAfterWaiting()
  {
    return numSuccessfulCheckoutsAfterWait.get();
  }



  public long getNumSuccessfulCheckoutsNewConnection()
  {
    return numSuccessfulCheckoutsNewConnection.get();
  }




  void incrementNumSuccessfulCheckoutsWithoutWaiting()
  {
   numSuccessfulCheckouts.incrementAndGet();
   numSuccessfulCheckoutsWithoutWait.incrementAndGet();
  }



  void incrementNumSuccessfulCheckoutsAfterWaiting()
  {
   numSuccessfulCheckouts.incrementAndGet();
   numSuccessfulCheckoutsAfterWait.incrementAndGet();
  }

  void incrementNumSuccessfulCheckoutsNewConnection()
  {
   numSuccessfulCheckouts.incrementAndGet();
   numSuccessfulCheckoutsNewConnection.incrementAndGet();
  }


  public long getNumFailedCheckouts()
  {
    return numFailedCheckouts.get();
  }



  void incrementNumFailedCheckouts()
  {
   numFailedCheckouts.incrementAndGet();
  }


  public long getNumReleasedValid()
  {
    return numReleasedValid.get();
  }



  void incrementNumReleasedValid()
  {
   numReleasedValid.incrementAndGet();
  }




  public int getNumAvailableConnections()
  {
    return pool.getCurrentAvailableConnections();
  }


  public int getMaximumAvailableConnections()
  {
    return pool.getMaximumAvailableConnections();
  }




  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }


  public void toString(final StringBuilder buffer)
  {
    final long availableConns      = pool.getCurrentAvailableConnections();
    final long maxConns            = pool.getMaximumAvailableConnections();
    final long successfulConns     = numSuccessfulConnectionAttempts.get();
    final long failedConns         = numFailedConnectionAttempts.get();
    final long connsClosedDefunct  = numConnectionsClosedDefunct.get();
    final long connsClosedExpired  = numConnectionsClosedExpired.get();
    final long connsClosedUnneeded = numConnectionsClosedUnneeded.get();
    final long successfulCheckouts = numSuccessfulCheckouts.get();
    final long failedCheckouts     = numFailedCheckouts.get();
    final long releasedValid       = numReleasedValid.get();

    buffer.append("LDAPConnectionPoolStatistics(numAvailableConnections=");
    buffer.append(availableConns);
    buffer.append(", maxAvailableConnections=");
    buffer.append(maxConns);
    buffer.append(", numSuccessfulConnectionAttempts=");
    buffer.append(successfulConns);
    buffer.append(", numFailedConnectionAttempts=");
    buffer.append(failedConns);
    buffer.append(", numConnectionsClosedDefunct=");
    buffer.append(connsClosedDefunct);
    buffer.append(", numConnectionsClosedExpired=");
    buffer.append(connsClosedExpired);
    buffer.append(", numConnectionsClosedUnneeded=");
    buffer.append(connsClosedUnneeded);
    buffer.append(", numSuccessfulCheckouts=");
    buffer.append(successfulCheckouts);
    buffer.append(", numFailedCheckouts=");
    buffer.append(failedCheckouts);
    buffer.append(", numReleasedValid=");
    buffer.append(releasedValid);
    buffer.append(')');
  }
}
