package com.hwlcn.ldap.ldap.sdk;



import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.SocketFactory;

import com.hwlcn.ldap.util.Debug;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class FastestConnectThread
      extends Thread
{
  private final AtomicBoolean connectionSelected;

  private final BlockingQueue<Object> resultQueue;

  private final int port;

  private final LDAPConnection connection;

  private final LDAPConnectionPoolHealthCheck healthCheck;

  private final String address;

  FastestConnectThread(final String address, final int port,
                       final SocketFactory socketFactory,
                       final LDAPConnectionOptions connectionOptions,
                       final LDAPConnectionPoolHealthCheck healthCheck,
                       final BlockingQueue<Object> resultQueue,
                       final AtomicBoolean connectionSelected)
  {
    super("Fastest Connect Thread for " + address + ':' + port);
    setDaemon(true);

    this.address            = address;
    this.port               = port;
    this.healthCheck        = healthCheck;
    this.resultQueue        = resultQueue;
    this.connectionSelected = connectionSelected;

    connection = new LDAPConnection(socketFactory, connectionOptions);
  }

  @Override()
  public void run()
  {
    boolean returned = false;

    try
    {
      connection.connect(address, port);

      if (healthCheck != null)
      {
        healthCheck.ensureNewConnectionValid(connection);
      }

      returned = (connectionSelected.compareAndSet(false, true) &&
          resultQueue.offer(connection));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      resultQueue.offer(e);
    }
    finally
    {
      if (! returned)
      {
        connection.close();
      }
    }
  }
}
