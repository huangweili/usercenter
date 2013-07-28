package com.hwlcn.ldap.ldap.sdk;


final class ParallelPoolCloserTask
      implements Runnable
{

  private final boolean unbind;

  private final LDAPConnection connection;


  ParallelPoolCloserTask(final LDAPConnection connection, final boolean unbind)
  {
    this.connection = connection;
    this.unbind     = unbind;
  }


  public void run()
  {
    final AbstractConnectionPool pool = connection.getConnectionPool();
    if (pool != null)
    {
      final LDAPConnectionPoolStatistics stats =
           pool.getConnectionPoolStatistics();
      if (stats != null)
      {
        stats.incrementNumConnectionsClosedUnneeded();
      }
    }

    connection.setDisconnectInfo(DisconnectType.POOL_CLOSED, null, null);
    if (unbind)
    {
      connection.terminate(null);
    }
    else
    {
      connection.setClosed();
    }
  }
}
