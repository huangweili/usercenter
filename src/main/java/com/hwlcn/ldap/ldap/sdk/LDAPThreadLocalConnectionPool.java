package com.hwlcn.ldap.ldap.sdk;



import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.ldap.util.ObjectPair;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;


@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPThreadLocalConnectionPool
       extends AbstractConnectionPool
{

  private static final long DEFAULT_HEALTH_CHECK_INTERVAL = 60000L;


  private final AtomicReference<Set<OperationType>> retryOperationTypes;


  private volatile boolean closed;


  private final BindRequest bindRequest;

  private final ConcurrentHashMap<Thread,LDAPConnection> connections;

  private LDAPConnectionPoolHealthCheck healthCheck;

  private final LDAPConnectionPoolHealthCheckThread healthCheckThread;

  private final LDAPConnectionPoolStatistics poolStatistics;

  private volatile long healthCheckInterval;

  private volatile long lastExpiredDisconnectTime;

  private volatile long maxConnectionAge;

  private volatile long minDisconnectInterval;

  private volatile ObjectPair<Long,Schema> pooledSchema;

  private final PostConnectProcessor postConnectProcessor;

  private final ServerSet serverSet;

  private String connectionPoolName;




  public LDAPThreadLocalConnectionPool(final LDAPConnection connection)
         throws LDAPException
  {
    this(connection, null);
  }



  public LDAPThreadLocalConnectionPool(final LDAPConnection connection,
              final PostConnectProcessor postConnectProcessor)
         throws LDAPException
  {
    ensureNotNull(connection);

    this.postConnectProcessor = postConnectProcessor;

    healthCheck               = new LDAPConnectionPoolHealthCheck();
    healthCheckInterval       = DEFAULT_HEALTH_CHECK_INTERVAL;
    poolStatistics            = new LDAPConnectionPoolStatistics(this);
    connectionPoolName        = null;
    retryOperationTypes       = new AtomicReference<Set<OperationType>>(
         Collections.unmodifiableSet(EnumSet.noneOf(OperationType.class)));

    if (! connection.isConnected())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
                              ERR_POOL_CONN_NOT_ESTABLISHED.get());
    }


    serverSet = new SingleServerSet(connection.getConnectedAddress(),
                                    connection.getConnectedPort(),
                                    connection.getLastUsedSocketFactory(),
                                    connection.getConnectionOptions());
    bindRequest = connection.getLastBindRequest();

    connections = new ConcurrentHashMap<Thread,LDAPConnection>();
    connections.put(Thread.currentThread(), connection);

    lastExpiredDisconnectTime = 0L;
    maxConnectionAge          = 0L;
    closed                    = false;
    minDisconnectInterval     = 0L;

    healthCheckThread = new LDAPConnectionPoolHealthCheckThread(this);
    healthCheckThread.start();

    final LDAPConnectionOptions opts = connection.getConnectionOptions();
    if (opts.usePooledSchema())
    {
      try
      {
        final Schema schema = connection.getSchema();
        if (schema != null)
        {
          connection.setCachedSchema(schema);

          final long currentTime = System.currentTimeMillis();
          final long timeout = opts.getPooledSchemaTimeoutMillis();
          if ((timeout <= 0L) || (timeout+currentTime <= 0L))
          {
            pooledSchema = new ObjectPair<Long,Schema>(Long.MAX_VALUE, schema);
          }
          else
          {
            pooledSchema =
                 new ObjectPair<Long,Schema>(timeout+currentTime, schema);
          }
        }
      }
      catch (final Exception e)
      {
        debugException(e);
      }
    }
  }


  public LDAPThreadLocalConnectionPool(final ServerSet serverSet,
                                       final BindRequest bindRequest)
  {
    this(serverSet, bindRequest, null);
  }



  public LDAPThreadLocalConnectionPool(final ServerSet serverSet,
              final BindRequest bindRequest,
              final PostConnectProcessor postConnectProcessor)
  {
    ensureNotNull(serverSet);

    this.serverSet            = serverSet;
    this.bindRequest          = bindRequest;
    this.postConnectProcessor = postConnectProcessor;

    healthCheck               = new LDAPConnectionPoolHealthCheck();
    healthCheckInterval       = DEFAULT_HEALTH_CHECK_INTERVAL;
    poolStatistics            = new LDAPConnectionPoolStatistics(this);
    connectionPoolName        = null;
    retryOperationTypes       = new AtomicReference<Set<OperationType>>(
         Collections.unmodifiableSet(EnumSet.noneOf(OperationType.class)));

    connections = new ConcurrentHashMap<Thread,LDAPConnection>();

    lastExpiredDisconnectTime = 0L;
    maxConnectionAge          = 0L;
    minDisconnectInterval     = 0L;
    closed                    = false;

    healthCheckThread = new LDAPConnectionPoolHealthCheckThread(this);
    healthCheckThread.start();
  }


  private LDAPConnection createConnection()
          throws LDAPException
  {
    final LDAPConnection c = serverSet.getConnection(healthCheck);
    c.setConnectionPool(this);
   LDAPConnectionOptions opts = c.getConnectionOptions();
    if (opts.autoReconnect())
    {
      opts = opts.duplicate();
      opts.setAutoReconnect(false);
      c.setConnectionOptions(opts);
    }

    if (postConnectProcessor != null)
    {
      try
      {
        postConnectProcessor.processPreAuthenticatedConnection(c);
      }
      catch (Exception e)
      {
        debugException(e);

        try
        {
          poolStatistics.incrementNumFailedConnectionAttempts();
          c.setDisconnectInfo(DisconnectType.POOL_CREATION_FAILURE, null, e);
          c.terminate(null);
        }
        catch (Exception e2)
        {
          debugException(e2);
        }

        if (e instanceof LDAPException)
        {
          throw ((LDAPException) e);
        }
        else
        {
          throw new LDAPException(ResultCode.CONNECT_ERROR,
               ERR_POOL_POST_CONNECT_ERROR.get(getExceptionMessage(e)), e);
        }
      }
    }

    try
    {
      if (bindRequest != null)
      {
        c.bind(bindRequest.duplicate());
      }
    }
    catch (Exception e)
    {
      debugException(e);
      try
      {
        poolStatistics.incrementNumFailedConnectionAttempts();
        c.setDisconnectInfo(DisconnectType.BIND_FAILED, null, e);
        c.terminate(null);
      }
      catch (Exception e2)
      {
        debugException(e2);
      }

      if (e instanceof LDAPException)
      {
        throw ((LDAPException) e);
      }
      else
      {
        throw new LDAPException(ResultCode.CONNECT_ERROR,
             ERR_POOL_CONNECT_ERROR.get(getExceptionMessage(e)), e);
      }
    }

    if (postConnectProcessor != null)
    {
      try
      {
        postConnectProcessor.processPostAuthenticatedConnection(c);
      }
      catch (Exception e)
      {
        debugException(e);
        try
        {
          poolStatistics.incrementNumFailedConnectionAttempts();
          c.setDisconnectInfo(DisconnectType.POOL_CREATION_FAILURE, null, e);
          c.terminate(null);
        }
        catch (Exception e2)
        {
          debugException(e2);
        }

        if (e instanceof LDAPException)
        {
          throw ((LDAPException) e);
        }
        else
        {
          throw new LDAPException(ResultCode.CONNECT_ERROR,
               ERR_POOL_POST_CONNECT_ERROR.get(getExceptionMessage(e)), e);
        }
      }
    }

    if (opts.usePooledSchema())
    {
      final long currentTime = System.currentTimeMillis();
      if ((pooledSchema == null) || (currentTime > pooledSchema.getFirst()))
      {
        try
        {
          final Schema schema = c.getSchema();
          if (schema != null)
          {
            c.setCachedSchema(schema);

            final long timeout = opts.getPooledSchemaTimeoutMillis();
            if ((timeout <= 0L) || (currentTime + timeout <= 0L))
            {
              pooledSchema =
                   new ObjectPair<Long,Schema>(Long.MAX_VALUE, schema);
            }
            else
            {
              pooledSchema =
                   new ObjectPair<Long,Schema>((currentTime+timeout), schema);
            }
          }
        }
        catch (final Exception e)
        {
          debugException(e);

          // There was a problem retrieving the schema from the server, but if
          // we have an earlier copy then we can assume it's still valid.
          if (pooledSchema != null)
          {
            c.setCachedSchema(pooledSchema.getSecond());
          }
        }
      }
      else
      {
        c.setCachedSchema(pooledSchema.getSecond());
      }
    }

    c.setConnectionPoolName(connectionPoolName);
    poolStatistics.incrementNumSuccessfulConnectionAttempts();
    return c;
  }

  @Override()
  public void close()
  {
    close(true, 1);
  }

  @Override()
  public void close(final boolean unbind, final int numThreads)
  {
    closed = true;
    healthCheckThread.stopRunning();

    if (numThreads > 1)
    {
      final ArrayList<LDAPConnection> connList =
           new ArrayList<LDAPConnection>(connections.size());
      final Iterator<LDAPConnection> iterator = connections.values().iterator();
      while (iterator.hasNext())
      {
        connList.add(iterator.next());
        iterator.remove();
      }

      final ParallelPoolCloser closer =
           new ParallelPoolCloser(connList, unbind, numThreads);
      closer.closeConnections();
    }
    else
    {
      final Iterator<Map.Entry<Thread,LDAPConnection>> iterator =
           connections.entrySet().iterator();
      while (iterator.hasNext())
      {
        final LDAPConnection conn = iterator.next().getValue();
        iterator.remove();

        poolStatistics.incrementNumConnectionsClosedUnneeded();
        conn.setDisconnectInfo(DisconnectType.POOL_CLOSED, null, null);
        if (unbind)
        {
          conn.terminate(null);
        }
        else
        {
          conn.setClosed();
        }
      }
    }
  }

  @Override()
  public boolean isClosed()
  {
    return closed;
  }


  public BindResult bindAndRevertAuthentication(final String bindDN,
                                                final String password,
                                                final Control... controls)
         throws LDAPException
  {
    return bindAndRevertAuthentication(
         new SimpleBindRequest(bindDN, password, controls));
  }


  public BindResult bindAndRevertAuthentication(final BindRequest bindRequest)
         throws LDAPException
  {
    LDAPConnection conn = getConnection();

    try
    {
      final BindResult result = conn.bind(bindRequest);
      releaseAndReAuthenticateConnection(conn);
      return result;
    }
    catch (final Throwable t)
    {
      debugException(t);

      if (t instanceof LDAPException)
      {
        final LDAPException le = (LDAPException) t;

        boolean shouldThrow;
        try
        {
          healthCheck.ensureConnectionValidAfterException(conn, le);
          releaseAndReAuthenticateConnection(conn);
          shouldThrow = true;
        }
        catch (final Exception e)
        {
          debugException(e);
          if (! getOperationTypesToRetryDueToInvalidConnections().contains(
                     OperationType.BIND))
          {
            releaseDefunctConnection(conn);
            shouldThrow = true;
          }
          else
          {
            shouldThrow = false;
          }
        }

        if (shouldThrow)
        {
          throw le;
        }
      }
      else
      {
        releaseDefunctConnection(conn);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_POOL_OP_EXCEPTION.get(getExceptionMessage(t)), t);
      }
    }

    conn = replaceDefunctConnection(conn);

    try
    {
      final BindResult result = conn.bind(bindRequest);
      releaseAndReAuthenticateConnection(conn);
      return result;
    }
    catch (final Throwable t)
    {
      debugException(t);

      if (t instanceof LDAPException)
      {
        final LDAPException le = (LDAPException) t;

        try
        {
          healthCheck.ensureConnectionValidAfterException(conn, le);
          releaseAndReAuthenticateConnection(conn);
        }
        catch (final Exception e)
        {
          debugException(e);
          releaseDefunctConnection(conn);
        }

        throw le;
      }
      else
      {
        releaseDefunctConnection(conn);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_POOL_OP_EXCEPTION.get(getExceptionMessage(t)), t);
      }
    }
  }


  @Override()
  public LDAPConnection getConnection()
         throws LDAPException
  {
    final Thread t = Thread.currentThread();
    LDAPConnection conn = connections.get(t);

    if (closed)
    {
      if (conn != null)
      {
        conn.terminate(null);
        connections.remove(t);
      }

      poolStatistics.incrementNumFailedCheckouts();
      throw new LDAPException(ResultCode.CONNECT_ERROR,
                              ERR_POOL_CLOSED.get());
    }

    boolean created = false;
    if (conn == null)
    {
      conn = createConnection();
      connections.put(t, conn);
      created = true;
    }

    try
    {
      healthCheck.ensureConnectionValidForCheckout(conn);
      if (created)
      {
        poolStatistics.incrementNumSuccessfulCheckoutsNewConnection();
      }
      else
      {
        poolStatistics.incrementNumSuccessfulCheckoutsWithoutWaiting();
      }
      return conn;
    }
    catch (LDAPException le)
    {
      debugException(le);

      conn.terminate(null);
      connections.remove(t);

      if (created)
      {
        poolStatistics.incrementNumFailedCheckouts();
        throw le;
      }
    }

    try
    {
      conn = createConnection();
      healthCheck.ensureConnectionValidForCheckout(conn);
      connections.put(t, conn);
      poolStatistics.incrementNumSuccessfulCheckoutsNewConnection();
      return conn;
    }
    catch (LDAPException le)
    {
      debugException(le);

      poolStatistics.incrementNumFailedCheckouts();

      if (conn != null)
      {
        conn.terminate(null);
      }

      throw le;
    }
  }

  @Override()
  public void releaseConnection(final LDAPConnection connection)
  {
    if (connection == null)
    {
      return;
    }

    connection.setConnectionPoolName(connectionPoolName);
    if (connectionIsExpired(connection))
    {
      try
      {
        final LDAPConnection newConnection = createConnection();
        connections.put(Thread.currentThread(), newConnection);

        connection.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_EXPIRED,
             null, null);
        connection.terminate(null);
        poolStatistics.incrementNumConnectionsClosedExpired();
        lastExpiredDisconnectTime = System.currentTimeMillis();
      }
      catch (final LDAPException le)
      {
        debugException(le);
      }
    }

    try
    {
      healthCheck.ensureConnectionValidForRelease(connection);
    }
    catch (LDAPException le)
    {
      releaseDefunctConnection(connection);
      return;
    }

    poolStatistics.incrementNumReleasedValid();

    if (closed)
    {
      close();
    }
  }

  public void releaseAndReAuthenticateConnection(
       final LDAPConnection connection)
  {
    if (connection == null)
    {
      return;
    }

    try
    {
      if (bindRequest == null)
      {
        connection.bind("", "");
      }
      else
      {
        connection.bind(bindRequest);
      }

      releaseConnection(connection);
    }
    catch (final Exception e)
    {
      debugException(e);
      releaseDefunctConnection(connection);
    }
  }

  @Override()
  public void releaseDefunctConnection(final LDAPConnection connection)
  {
    if (connection == null)
    {
      return;
    }

    connection.setConnectionPoolName(connectionPoolName);
    poolStatistics.incrementNumConnectionsClosedDefunct();
    handleDefunctConnection(connection);
  }

  private void handleDefunctConnection(final LDAPConnection connection)
  {
    final Thread t = Thread.currentThread();

    connection.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT, null,
                                 null);
    connection.terminate(null);
    connections.remove(t);

    if (closed)
    {
      return;
    }

    try
    {
      final LDAPConnection conn = createConnection();
      connections.put(t, conn);
    }
    catch (LDAPException le)
    {
      debugException(le);
    }
  }

  @Override()
  public LDAPConnection replaceDefunctConnection(
                             final LDAPConnection connection)
         throws LDAPException
  {
    connection.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT, null,
                                 null);
    connection.terminate(null);
    connections.remove(Thread.currentThread(), connection);

    if (closed)
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR, ERR_POOL_CLOSED.get());
    }

    final LDAPConnection newConnection = createConnection();
    connections.put(Thread.currentThread(), newConnection);
    return newConnection;
  }

  @Override()
  public Set<OperationType> getOperationTypesToRetryDueToInvalidConnections()
  {
    return retryOperationTypes.get();
  }

  @Override()
  public void setRetryFailedOperationsDueToInvalidConnections(
                   final Set<OperationType> operationTypes)
  {
    if ((operationTypes == null) || operationTypes.isEmpty())
    {
      retryOperationTypes.set(
           Collections.unmodifiableSet(EnumSet.noneOf(OperationType.class)));
    }
    else
    {
      final EnumSet<OperationType> s = EnumSet.noneOf(OperationType.class);
      s.addAll(operationTypes);
      retryOperationTypes.set(Collections.unmodifiableSet(s));
    }
  }

  private boolean connectionIsExpired(final LDAPConnection connection)
  {
    if (maxConnectionAge <= 0L)
    {
      return false;
    }
    final long currentTime = System.currentTimeMillis();
    if ((currentTime - lastExpiredDisconnectTime) < minDisconnectInterval)
    {
      return false;
    }
  final long connectionAge = currentTime - connection.getConnectTime();
    return (connectionAge > maxConnectionAge);
  }


  @Override()
  public String getConnectionPoolName()
  {
    return connectionPoolName;
  }


  @Override()
  public void setConnectionPoolName(final String connectionPoolName)
  {
    this.connectionPoolName = connectionPoolName;
  }


  public long getMaxConnectionAgeMillis()
  {
    return maxConnectionAge;
  }

  public void setMaxConnectionAgeMillis(final long maxConnectionAge)
  {
    if (maxConnectionAge > 0L)
    {
      this.maxConnectionAge = maxConnectionAge;
    }
    else
    {
      this.maxConnectionAge = 0L;
    }
  }

  public long getMinDisconnectIntervalMillis()
  {
    return minDisconnectInterval;
  }

  public void setMinDisconnectIntervalMillis(final long minDisconnectInterval)
  {
    if (minDisconnectInterval > 0)
    {
      this.minDisconnectInterval = minDisconnectInterval;
    }
    else
    {
      this.minDisconnectInterval = 0L;
    }
  }

  @Override()
  public LDAPConnectionPoolHealthCheck getHealthCheck()
  {
    return healthCheck;
  }

  public void setHealthCheck(final LDAPConnectionPoolHealthCheck healthCheck)
  {
    ensureNotNull(healthCheck);
    this.healthCheck = healthCheck;
  }


  @Override()
  public long getHealthCheckIntervalMillis()
  {
    return healthCheckInterval;
  }

  @Override()
  public void setHealthCheckIntervalMillis(final long healthCheckInterval)
  {
    ensureTrue(healthCheckInterval > 0L,
         "LDAPConnectionPool.healthCheckInterval must be greater than 0.");
    this.healthCheckInterval = healthCheckInterval;
    healthCheckThread.wakeUp();
  }

  @Override()
  protected void doHealthCheck()
  {
    final Iterator<Map.Entry<Thread,LDAPConnection>> iterator =
         connections.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<Thread,LDAPConnection> e = iterator.next();
      final Thread                           t = e.getKey();
      final LDAPConnection                   c = e.getValue();

      if (! t.isAlive())
      {
        c.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_UNNEEDED, null,
                            null);
        c.terminate(null);
        iterator.remove();
      }
    }
  }


  @Override()
  public int getCurrentAvailableConnections()
  {
    return -1;
  }


  @Override()
  public int getMaximumAvailableConnections()
  {
    return -1;
  }


  @Override()
  public LDAPConnectionPoolStatistics getConnectionPoolStatistics()
  {
    return poolStatistics;
  }

  @Override()
  protected void finalize()
            throws Throwable
  {
    super.finalize();

    close();
  }


  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDAPThreadLocalConnectionPool(");

    final String name = connectionPoolName;
    if (name != null)
    {
      buffer.append("name='");
      buffer.append(name);
      buffer.append("', ");
    }

    buffer.append("serverSet=");
    serverSet.toString(buffer);
    buffer.append(')');
  }
}
