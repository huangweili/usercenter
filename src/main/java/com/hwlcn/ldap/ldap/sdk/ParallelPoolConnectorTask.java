package com.hwlcn.ldap.ldap.sdk;



import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import com.hwlcn.ldap.util.Debug;



final class ParallelPoolConnectorTask
      implements Runnable
{

  private final AtomicReference<LDAPException> firstException;


  private final boolean throwOnConnectFailure;

  private final LDAPConnectionPool pool;

  private final List<LDAPConnection> connList;


  ParallelPoolConnectorTask(final LDAPConnectionPool pool,
                            final List<LDAPConnection> connList,
                            final AtomicReference<LDAPException> firstException,
                            final boolean throwOnConnectFailure)
  {
    this.pool                  = pool;
    this.connList              = connList;
    this.firstException        = firstException;
    this.throwOnConnectFailure = throwOnConnectFailure;
  }


  public void run()
  {
    try
    {
      if (throwOnConnectFailure && (firstException.get() != null))
      {
        return;
      }

      connList.add(pool.createConnection());
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      if (throwOnConnectFailure)
      {
        firstException.compareAndSet(null, le);
      }
    }
  }
}
