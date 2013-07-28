package com.hwlcn.ldap.ldap.sdk;



import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import com.hwlcn.ldap.util.Debug;


final class ParallelPoolCloser
{
  private final boolean unbind;

  private final Collection<LDAPConnection> connections;

  private final int numThreads;

 ParallelPoolCloser(final Collection<LDAPConnection> connections,
                     final boolean unbind, final int numThreads)
  {
    this.connections = connections;
    this.unbind      = unbind;
    this.numThreads  = numThreads;
  }


  void closeConnections()
  {
    final int numConnections = connections.size();

    final ArrayBlockingQueue<Runnable> queue =
         new ArrayBlockingQueue<Runnable>(numConnections);
    final ThreadPoolExecutor executor = new ThreadPoolExecutor(numThreads,
         numThreads, 0L, TimeUnit.MILLISECONDS, queue);

    final ArrayList<Future<?>> results =
         new ArrayList<Future<?>>(numConnections);
    for (final LDAPConnection conn : connections)
    {
      results.add(executor.submit(new ParallelPoolCloserTask(conn, unbind)));
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
  }
}
