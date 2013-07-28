package com.hwlcn.ldap.ldap.sdk;



import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.hwlcn.ldap.util.Debug.*;



class LDAPConnectionPoolHealthCheckThread
      extends Thread
{

  private final AtomicBoolean stopRequested;

  private final AbstractConnectionPool pool;

  private final LinkedBlockingQueue<Object> queue;

  private volatile Thread thread;



  LDAPConnectionPoolHealthCheckThread(final AbstractConnectionPool pool)
  {
    setName("Health Check Thread for " + pool.toString());
    setDaemon(true);

    this.pool = pool;

    stopRequested = new AtomicBoolean(false);
    queue = new LinkedBlockingQueue<Object>(1);
    thread = null;
  }




  @Override()
  public void run()
  {
    thread = Thread.currentThread();
    long lastCheckTime = System.currentTimeMillis();

    while (! stopRequested.get())
    {
      final long timeSinceLastCheck =
           System.currentTimeMillis() - lastCheckTime;
      if (timeSinceLastCheck >= pool.getHealthCheckIntervalMillis())
      {
        try
        {
          pool.doHealthCheck();
        }
        catch (Exception e)
        {
          debugException(e);
        }
        lastCheckTime = System.currentTimeMillis();
      }
      else
      {
        final long sleepTime = Math.min(
             (pool.getHealthCheckIntervalMillis() - timeSinceLastCheck),
             30000L);
        try
        {
          queue.poll(sleepTime, TimeUnit.MILLISECONDS);
        }
        catch (Exception e)
        {
          debugException(e);
        }
      }
    }

    thread = null;
  }



  void stopRunning()
  {
    stopRequested.set(true);
    wakeUp();

    final Thread t = thread;
    if (t != null)
    {
      try
      {
        t.join();
      }
      catch (Exception e)
      {
        debugException(e);
      }
    }
  }


  void wakeUp()
  {
    queue.offer(new Object());
  }
}
