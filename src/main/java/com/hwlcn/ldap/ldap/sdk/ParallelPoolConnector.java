package com.hwlcn.ldap.ldap.sdk;



import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import com.hwlcn.ldap.util.Debug;


final class ParallelPoolConnector
{

  private final boolean throwOnConnectFailure;


  private final int numConnections;

  private final int numThreads;

  private final LDAPConnectionPool pool;

  private final List<LDAPConnection> connList;




  ParallelPoolConnector(final LDAPConnectionPool pool,
                        final List<LDAPConnection> connList,
                        final int numConnections,
                        final int numThreads,
                        final boolean throwOnConnectFailure)
  {
    this.pool                  = pool;
    this.connList              = connList;
    this.numConnections        = numConnections;
    this.numThreads            = numThreads;
    this.throwOnConnectFailure = throwOnConnectFailure;
  }



  void establishConnections()
       throws LDAPException
  {
    final ArrayBlockingQueue<Runnable> queue =
         new ArrayBlockingQueue<Runnable>(numConnections);
    final ThreadPoolExecutor executor = new ThreadPoolExecutor(numThreads,
         numThreads, 0L, TimeUnit.MILLISECONDS, queue);

    final AtomicReference<LDAPException> firstException =
         new AtomicReference<LDAPException>();

    final ArrayList<Future<?>> results =
         new ArrayList<Future<?>>(numConnections);
    for (int i=0; i < numConnections; i++)
    {
      results.add(executor.submit(new ParallelPoolConnectorTask(pool, connList,
           firstException, throwOnConnectFailure)));
    }

    for (final Future<?> f : results)
    {
      try
      {
        f.get();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    executor.shutdown();

    if (throwOnConnectFailure)
    {
      final LDAPException le = firstException.get();
      if (le != null)
      {
        for (final LDAPConnection c : connList)
        {
          c.terminate(null);
        }
        connList.clear();
        throw le;
      }
    }
  }
}
