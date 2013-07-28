package com.hwlcn.ldap.ldap.sdk;



import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.ldap.util.ObjectPair;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides an implementation of an LDAP connection pool, which is a
 * structure that can hold multiple connections established to a given server
 * that can be reused for multiple operations rather than creating and
 * destroying connections for each operation.  This connection pool
 * implementation provides traditional methods for checking out and releasing
 * connections, but it also provides wrapper methods that make it easy to
 * perform operations using pooled connections without the need to explicitly
 * check out or release the connections.
 * <BR><BR>
 * Note that both the {@code LDAPConnectionPool} class and the
 * {@link com.hwlcn.ldap.ldap.sdk.LDAPConnection} class implement the {@link com.hwlcn.ldap.ldap.sdk.LDAPInterface} interface.
 * This is a common interface that defines a number of common methods for
 * processing LDAP requests.  This means that in many cases, an application can
 * use an object of type {@link com.hwlcn.ldap.ldap.sdk.LDAPInterface} rather than
 * {@link com.hwlcn.ldap.ldap.sdk.LDAPConnection}, which makes it possible to work with either a single
 * standalone connection or with a connection pool.
 * <BR><BR>
 * <H2>Creating a Connection Pool</H2>
 * An LDAP connection pool can be created from either a single
 * {@link com.hwlcn.ldap.ldap.sdk.LDAPConnection} (for which an appropriate number of copies will be
 * created to fill out the pool) or using a {@link com.hwlcn.ldap.ldap.sdk.ServerSet} to create
 * connections that may span multiple servers.  For example:
 * <BR><BR>
 * <PRE>
 *   // Create a new LDAP connection pool with ten connections established and
 *   // authenticated to the same server:
 *   LDAPConnection connection = new LDAPConnection(address, port);
 *   BindResult bindResult = connection.bind(bindDN, password);
 *   LDAPConnectionPool connectionPool = new LDAPConnectionPool(connection, 10);
 *
 *   // Create a new LDAP connection pool with 10 connections spanning multiple
 *   // servers using a server set.
 *   RoundRobinServerSet serverSet = new RoundRobinServerSet(addresses, ports);
 *   SimpleBindRequest bindRequest = new SimpleBindRequest(bindDN, password);
 *   LDAPConnectionPool connectionPool =
 *        new LDAPConnectionPool(serverSet, bindRequest, 10);
 * </PRE>
 * Note that in some cases, such as when using StartTLS, it may be necessary to
 * perform some additional processing when a new connection is created for use
 * in the connection pool.  In this case, a {@link PostConnectProcessor} should
 * be provided to accomplish this.  See the documentation for the
 * {@link StartTLSPostConnectProcessor} class for an example that demonstrates
 * its use for creating a connection pool with connections secured using
 * StartTLS.
 * <BR><BR>
 * <H2>Processing Operations with a Connection Pool</H2>
 * If a single operation is to be processed using a connection from the
 * connection pool, then it can be used without the need to check out or release
 * a connection or perform any validity checking on the connection.  This can
 * be accomplished via the {@link com.hwlcn.ldap.ldap.sdk.LDAPInterface} interface that allows a
 * connection pool to be treated like a single connection.  For example, to
 * perform a search using a pooled connection:
 * <PRE>
 *   SearchResult searchResult =
 *        connectionPool.search("dc=example,dc=com", SearchScope.SUB,
 *                              "(uid=john.doe)");
 * </PRE>
 * If an application needs to process multiple operations using a single
 * connection, then it may be beneficial to obtain a connection from the pool
 * to use for processing those operations and then return it back to the pool
 * when it is no longer needed.  This can be done using the
 * {@link #getConnection} and {@link #releaseConnection} methods.  If during
 * processing it is determined that the connection is no longer valid, then the
 * connection should be released back to the pool using the
 * {@link #releaseDefunctConnection} method, which will ensure that the
 * connection is closed and a new connection will be established to take its
 * place in the pool.
 * <BR><BR>
 * Note that it is also possible to process multiple operations on a single
 * connection using the {@link #processRequests} method.  This may be useful if
 * a fixed set of operations should be processed over the same connection and
 * none of the subsequent requests depend upon the results of the earlier
 * operations.
 * <BR><BR>
 * Connection pools should generally not be used when performing operations that
 * may change the state of the underlying connections.  This is particularly
 * true for bind operations and the StartTLS extended operation, but it may
 * apply to other types of operations as well.
 * <BR><BR>
 * Performing a bind operation using a connection from the pool will invalidate
 * any previous authentication on that connection, and if that connection is
 * released back to the pool without first being re-authenticated as the
 * original user, then subsequent operation attempts may fail or be processed in
 * an incorrect manner.  Bind operations should only be performed in a
 * connection pool if the pool is to be used exclusively for processing binds,
 * if the bind request is specially crafted so that it will not change the
 * identity of the associated connection (e.g., by including the retain identity
 * request control in the bind request if using the Commercial Edition of the
 * LDAP SDK with an UnboundID Directory Server), or if the code using the
 * connection pool makes sure to re-authenticate the connection as the
 * appropriate user whenever its identity has been changed.
 * <BR><BR>
 * The StartTLS extended operation should never be invoked on a connection which
 * is part of a connection pool.  It is acceptable for the pool to maintain
 * connections which have been configured with StartTLS security prior to being
 * added to the pool (via the use of the {@link StartTLSPostConnectProcessor}).
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPConnectionPool
       extends AbstractConnectionPool
{

  private static final long DEFAULT_HEALTH_CHECK_INTERVAL = 60000L;

  private final AtomicInteger failedReplaceCount;


  private final AtomicReference<Set<OperationType>> retryOperationTypes;

  private volatile boolean closed;

  private boolean createIfNecessary;

  private volatile boolean trySynchronousReadDuringHealthCheck;

  private final BindRequest bindRequest;

  private final int numConnections;

  private LDAPConnectionPoolHealthCheck healthCheck;


  private final LDAPConnectionPoolHealthCheckThread healthCheckThread;

  private final LDAPConnectionPoolStatistics poolStatistics;

  private final LinkedBlockingQueue<LDAPConnection> availableConnections;

  private volatile long healthCheckInterval;

  private volatile long lastExpiredDisconnectTime;


  private volatile long maxConnectionAge;

  private long maxWaitTime;

  private volatile long minDisconnectInterval;

  private volatile ObjectPair<Long,Schema> pooledSchema;

  private final PostConnectProcessor postConnectProcessor;

  private final ServerSet serverSet;

  private String connectionPoolName;





  public LDAPConnectionPool(final LDAPConnection connection,
                            final int numConnections)
         throws LDAPException
  {
    this(connection, 1, numConnections, null);
  }




  public LDAPConnectionPool(final LDAPConnection connection,
                            final int initialConnections,
                            final int maxConnections)
         throws LDAPException
  {
    this(connection, initialConnections, maxConnections, null);
  }


  public LDAPConnectionPool(final LDAPConnection connection,
                            final int initialConnections,
                            final int maxConnections,
                            final PostConnectProcessor postConnectProcessor)
         throws LDAPException
  {
    this(connection, initialConnections, maxConnections,  postConnectProcessor,
         true);
  }



  public LDAPConnectionPool(final LDAPConnection connection,
                            final int initialConnections,
                            final int maxConnections,
                            final PostConnectProcessor postConnectProcessor,
                            final boolean throwOnConnectFailure)
         throws LDAPException
  {
    this(connection, initialConnections, maxConnections, 1,
         postConnectProcessor, throwOnConnectFailure);
  }


  public LDAPConnectionPool(final LDAPConnection connection,
                            final int initialConnections,
                            final int maxConnections,
                            final int initialConnectThreads,
                            final PostConnectProcessor postConnectProcessor,
                            final boolean throwOnConnectFailure)
         throws LDAPException
  {
    ensureNotNull(connection);
    ensureTrue(initialConnections >= 1,
               "LDAPConnectionPool.initialConnections must be at least 1.");
    ensureTrue(maxConnections >= initialConnections,
               "LDAPConnectionPool.initialConnections must not be greater " +
                    "than maxConnections.");

    this.postConnectProcessor = postConnectProcessor;

    trySynchronousReadDuringHealthCheck = true;
    healthCheck               = new LDAPConnectionPoolHealthCheck();
    healthCheckInterval       = DEFAULT_HEALTH_CHECK_INTERVAL;
    poolStatistics            = new LDAPConnectionPoolStatistics(this);
    pooledSchema              = null;
    connectionPoolName        = null;
    retryOperationTypes       = new AtomicReference<Set<OperationType>>(
         Collections.unmodifiableSet(EnumSet.noneOf(OperationType.class)));
    numConnections            = maxConnections;
    availableConnections      =
         new LinkedBlockingQueue<LDAPConnection>(numConnections);

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

    final List<LDAPConnection> connList;
    if (initialConnectThreads > 1)
    {
      connList = Collections.synchronizedList(
           new ArrayList<LDAPConnection>(initialConnections));
      final ParallelPoolConnector connector = new ParallelPoolConnector(this,
           connList, initialConnections, initialConnectThreads,
           throwOnConnectFailure);
      connector.establishConnections();
    }
    else
    {
      connList = new ArrayList<LDAPConnection>(initialConnections);
      connection.setConnectionName(null);
      connection.setConnectionPool(this);
      connList.add(connection);
      for (int i=1; i < initialConnections; i++)
      {
        try
        {
          connList.add(createConnection());
        }
        catch (LDAPException le)
        {
          debugException(le);

          if (throwOnConnectFailure)
          {
            for (final LDAPConnection c : connList)
            {
              try
              {
                c.setDisconnectInfo(DisconnectType.POOL_CREATION_FAILURE, null,
                     le);
                c.terminate(null);
              }
              catch (Exception e)
              {
                debugException(e);
              }
            }

            throw le;
          }
        }
      }
    }

    availableConnections.addAll(connList);

    failedReplaceCount        =
         new AtomicInteger(maxConnections - availableConnections.size());
    createIfNecessary         = true;
    maxConnectionAge          = 0L;
    minDisconnectInterval     = 0L;
    lastExpiredDisconnectTime = 0L;
    maxWaitTime               = 5000L;
    closed                    = false;

    healthCheckThread = new LDAPConnectionPoolHealthCheckThread(this);
    healthCheckThread.start();
  }



  public LDAPConnectionPool(final ServerSet serverSet,
                            final BindRequest bindRequest,
                            final int numConnections)
         throws LDAPException
  {
    this(serverSet, bindRequest, 1, numConnections, null);
  }



  public LDAPConnectionPool(final ServerSet serverSet,
                            final BindRequest bindRequest,
                            final int initialConnections,
                            final int maxConnections)
         throws LDAPException
  {
    this(serverSet, bindRequest, initialConnections, maxConnections, null);
  }



  public LDAPConnectionPool(final ServerSet serverSet,
                            final BindRequest bindRequest,
                            final int initialConnections,
                            final int maxConnections,
                            final PostConnectProcessor postConnectProcessor)
         throws LDAPException
  {
    this(serverSet, bindRequest, initialConnections, maxConnections,
         postConnectProcessor, true);
  }



  public LDAPConnectionPool(final ServerSet serverSet,
                            final BindRequest bindRequest,
                            final int initialConnections,
                            final int maxConnections,
                            final PostConnectProcessor postConnectProcessor,
                            final boolean throwOnConnectFailure)
         throws LDAPException
  {
    this(serverSet, bindRequest, initialConnections, maxConnections, 1,
         postConnectProcessor, throwOnConnectFailure);
  }



  public LDAPConnectionPool(final ServerSet serverSet,
                            final BindRequest bindRequest,
                            final int initialConnections,
                            final int maxConnections,
                            final int initialConnectThreads,
                            final PostConnectProcessor postConnectProcessor,
                            final boolean throwOnConnectFailure)
         throws LDAPException
  {
    ensureNotNull(serverSet);
    ensureTrue(initialConnections >= 0,
               "LDAPConnectionPool.initialConnections must be greater than " +
                    "or equal to 0.");
    ensureTrue(maxConnections > 0,
               "LDAPConnectionPool.maxConnections must be greater than 0.");
    ensureTrue(maxConnections >= initialConnections,
               "LDAPConnectionPool.initialConnections must not be greater " +
                    "than maxConnections.");

    this.serverSet            = serverSet;
    this.bindRequest          = bindRequest;
    this.postConnectProcessor = postConnectProcessor;

    healthCheck               = new LDAPConnectionPoolHealthCheck();
    healthCheckInterval       = DEFAULT_HEALTH_CHECK_INTERVAL;
    poolStatistics            = new LDAPConnectionPoolStatistics(this);
    connectionPoolName        = null;
    retryOperationTypes       = new AtomicReference<Set<OperationType>>(
         Collections.unmodifiableSet(EnumSet.noneOf(OperationType.class)));

    final List<LDAPConnection> connList;
    if (initialConnectThreads > 1)
    {
      connList = Collections.synchronizedList(
           new ArrayList<LDAPConnection>(initialConnections));
      final ParallelPoolConnector connector = new ParallelPoolConnector(this,
           connList, initialConnections, initialConnectThreads,
           throwOnConnectFailure);
      connector.establishConnections();
    }
    else
    {
      connList = new ArrayList<LDAPConnection>(initialConnections);
      for (int i=0; i < initialConnections; i++)
      {
        try
        {
          connList.add(createConnection());
        }
        catch (LDAPException le)
        {
          debugException(le);

          if (throwOnConnectFailure)
          {
            for (final LDAPConnection c : connList)
            {
              try
              {
                c.setDisconnectInfo(DisconnectType.POOL_CREATION_FAILURE, null,
                     le);
                c.terminate(null);
              } catch (Exception e)
              {
                debugException(e);
              }
            }

            throw le;
          }
        }
      }
    }

    numConnections = maxConnections;

    availableConnections =
         new LinkedBlockingQueue<LDAPConnection>(numConnections);
    availableConnections.addAll(connList);

    failedReplaceCount        =
         new AtomicInteger(maxConnections - availableConnections.size());
    createIfNecessary         = true;
    maxConnectionAge          = 0L;
    minDisconnectInterval     = 0L;
    lastExpiredDisconnectTime = 0L;
    maxWaitTime               = 5000L;
    closed                    = false;

    healthCheckThread = new LDAPConnectionPoolHealthCheckThread(this);
    healthCheckThread.start();
  }



  LDAPConnection createConnection()
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
           new ArrayList<LDAPConnection>(availableConnections.size());
      availableConnections.drainTo(connList);

      final ParallelPoolCloser closer =
           new ParallelPoolCloser(connList, unbind, numThreads);
      closer.closeConnections();
    }
    else
    {
      while (true)
      {
        final LDAPConnection conn = availableConnections.poll();
        if (conn == null)
        {
          return;
        }
        else
        {
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
    if (closed)
    {
      poolStatistics.incrementNumFailedCheckouts();
      throw new LDAPException(ResultCode.CONNECT_ERROR,
                              ERR_POOL_CLOSED.get());
    }

    LDAPConnection conn = availableConnections.poll();
    if (conn != null)
    {
      if (conn.isConnected())
      {
        try
        {
          healthCheck.ensureConnectionValidForCheckout(conn);
          poolStatistics.incrementNumSuccessfulCheckoutsWithoutWaiting();
          return conn;
        }
        catch (LDAPException le)
        {
          debugException(le);
        }
      }

      handleDefunctConnection(conn);
      for (int i=0; i < numConnections; i++)
      {
        conn = availableConnections.poll();
        if (conn == null)
        {
          break;
        }
        else if (conn.isConnected())
        {
          try
          {
            healthCheck.ensureConnectionValidForCheckout(conn);
            poolStatistics.incrementNumSuccessfulCheckoutsWithoutWaiting();
            return conn;
          }
          catch (LDAPException le)
          {
            debugException(le);
            handleDefunctConnection(conn);
          }
        }
        else
        {
          handleDefunctConnection(conn);
        }
      }
    }

    if (failedReplaceCount.get() > 0)
    {
      final int newReplaceCount = failedReplaceCount.getAndDecrement();
      if (newReplaceCount > 0)
      {
        try
        {
          conn = createConnection();
          poolStatistics.incrementNumSuccessfulCheckoutsNewConnection();
          return conn;
        }
        catch (LDAPException le)
        {
          debugException(le);
          failedReplaceCount.incrementAndGet();
          poolStatistics.incrementNumFailedCheckouts();
          throw le;
        }
      }
      else
      {
        failedReplaceCount.incrementAndGet();
        poolStatistics.incrementNumFailedCheckouts();
        throw new LDAPException(ResultCode.CONNECT_ERROR,
                                ERR_POOL_NO_CONNECTIONS.get());
      }
    }

    if (maxWaitTime > 0)
    {
      try
      {
        conn = availableConnections.poll(maxWaitTime, TimeUnit.MILLISECONDS);
        if (conn != null)
        {
          try
          {
            healthCheck.ensureConnectionValidForCheckout(conn);
            poolStatistics.incrementNumSuccessfulCheckoutsAfterWaiting();
            return conn;
          }
          catch (LDAPException le)
          {
            debugException(le);
            handleDefunctConnection(conn);
          }
        }
      }
      catch (InterruptedException ie)
      {
        debugException(ie);
      }
    }

    if (createIfNecessary)
    {
      try
      {
        conn = createConnection();
        poolStatistics.incrementNumSuccessfulCheckoutsNewConnection();
        return conn;
      }
      catch (LDAPException le)
      {
        debugException(le);
        poolStatistics.incrementNumFailedCheckouts();
        throw le;
      }
    }
    else
    {
      poolStatistics.incrementNumFailedCheckouts();
      throw new LDAPException(ResultCode.CONNECT_ERROR,
                              ERR_POOL_NO_CONNECTIONS.get());
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
        if (availableConnections.offer(newConnection))
        {
          connection.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_EXPIRED,
               null, null);
          connection.terminate(null);
          poolStatistics.incrementNumConnectionsClosedExpired();
          lastExpiredDisconnectTime = System.currentTimeMillis();
          return;
        }
        else
        {
          newConnection.setDisconnectInfo(
               DisconnectType.POOLED_CONNECTION_UNNEEDED, null, null);
          newConnection.terminate(null);
          poolStatistics.incrementNumConnectionsClosedUnneeded();
        }
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

    if (availableConnections.offer(connection))
    {
      poolStatistics.incrementNumReleasedValid();
    }
    else
    {

      connection.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_UNNEEDED,
                                   null, null);
      poolStatistics.incrementNumConnectionsClosedUnneeded();
      connection.terminate(null);
      return;
    }

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




  private LDAPConnection handleDefunctConnection(
                              final LDAPConnection connection)
  {
    connection.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT, null,
                                 null);
    connection.terminate(null);

    if (closed)
    {
      return null;
    }

    if (createIfNecessary && (availableConnections.remainingCapacity() <= 0))
    {
      return null;
    }

    try
    {
      final LDAPConnection conn = createConnection();
      if (! availableConnections.offer(conn))
      {
        conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_UNNEEDED,
                               null, null);
        conn.terminate(null);
        return null;
      }

      return conn;
    }
    catch (LDAPException le)
    {
      debugException(le);
      failedReplaceCount.incrementAndGet();
      return null;
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

    if (closed)
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR, ERR_POOL_CLOSED.get());
    }

    return createConnection();
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
    for (final LDAPConnection c : availableConnections)
    {
      c.setConnectionPoolName(connectionPoolName);
    }
  }



  public boolean getCreateIfNecessary()
  {
    return createIfNecessary;
  }


  public void setCreateIfNecessary(final boolean createIfNecessary)
  {
    this.createIfNecessary = createIfNecessary;
  }




  public long getMaxWaitTimeMillis()
  {
    return maxWaitTime;
  }



  public void setMaxWaitTimeMillis(final long maxWaitTime)
  {
    if (maxWaitTime > 0L)
    {
      this.maxWaitTime = maxWaitTime;
    }
    else
    {
      this.maxWaitTime = 0L;
    }
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


  public boolean trySynchronousReadDuringHealthCheck()
  {
    return trySynchronousReadDuringHealthCheck;
  }



  public void setTrySynchronousReadDuringHealthCheck(
                   final boolean trySynchronousReadDuringHealthCheck)
  {
    this.trySynchronousReadDuringHealthCheck =
         trySynchronousReadDuringHealthCheck;
  }


  @Override()
  protected void doHealthCheck()
  {

    final HashSet<LDAPConnection> examinedConnections =
         new HashSet<LDAPConnection>(numConnections);

    for (int i=0; i < numConnections; i++)
    {
      LDAPConnection conn = availableConnections.poll();
      if (conn == null)
      {
        break;
      }
      else if (examinedConnections.contains(conn))
      {
        if (! availableConnections.offer(conn))
        {
          conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_UNNEEDED,
                                 null, null);
          poolStatistics.incrementNumConnectionsClosedUnneeded();
          conn.terminate(null);
        }
        break;
      }

      if (! conn.isConnected())
      {
        conn = handleDefunctConnection(conn);
        if (conn != null)
        {
          examinedConnections.add(conn);
        }
      }
      else
      {
        if (connectionIsExpired(conn))
        {
          try
          {
            final LDAPConnection newConnection = createConnection();
            if (availableConnections.offer(newConnection))
            {
              examinedConnections.add(newConnection);
              conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_EXPIRED,
                   null, null);
              conn.terminate(null);
              poolStatistics.incrementNumConnectionsClosedExpired();
              lastExpiredDisconnectTime = System.currentTimeMillis();
              continue;
            }
            else
            {
              newConnection.setDisconnectInfo(
                   DisconnectType.POOLED_CONNECTION_UNNEEDED, null, null);
              newConnection.terminate(null);
              poolStatistics.incrementNumConnectionsClosedUnneeded();
            }
          }
          catch (final LDAPException le)
          {
            debugException(le);
          }
        }



        if (trySynchronousReadDuringHealthCheck && conn.synchronousMode())
        {
          int previousTimeout = Integer.MIN_VALUE;
          Socket s = null;
          try
          {
            s = conn.getConnectionInternals(true).getSocket();
            previousTimeout = s.getSoTimeout();
            s.setSoTimeout(1);

            final LDAPResponse response = conn.readResponse(0);
            if (response instanceof ConnectionClosedResponse)
            {
              conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT,
                   ERR_POOL_HEALTH_CHECK_CONN_CLOSED.get(), null);
              poolStatistics.incrementNumConnectionsClosedDefunct();
              conn = handleDefunctConnection(conn);
              if (conn != null)
              {
                examinedConnections.add(conn);
              }
              continue;
            }
            else if (response instanceof ExtendedResult)
            {

              final UnsolicitedNotificationHandler h = conn.
                   getConnectionOptions().getUnsolicitedNotificationHandler();
              if (h != null)
              {
                h.handleUnsolicitedNotification(conn,
                     (ExtendedResult) response);
              }
            }
            else if (response instanceof LDAPResult)
            {
              final LDAPResult r = (LDAPResult) response;
              if (r.getResultCode() == ResultCode.SERVER_DOWN)
              {
                conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT,
                     ERR_POOL_HEALTH_CHECK_CONN_CLOSED.get(), null);
                poolStatistics.incrementNumConnectionsClosedDefunct();
                conn = handleDefunctConnection(conn);
                if (conn != null)
                {
                  examinedConnections.add(conn);
                }
                continue;
              }
            }
          }
          catch (final LDAPException le)
          {
            if (le.getResultCode() == ResultCode.TIMEOUT)
            {
              debugException(Level.FINEST, le);
            }
            else
            {
              debugException(le);
              conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT,
                   ERR_POOL_HEALTH_CHECK_READ_FAILURE.get(
                        getExceptionMessage(le)), le);
              poolStatistics.incrementNumConnectionsClosedDefunct();
              conn = handleDefunctConnection(conn);
              if (conn != null)
              {
                examinedConnections.add(conn);
              }
              continue;
            }
          }
          catch (final Exception e)
          {
            debugException(e);
            conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT,
                 ERR_POOL_HEALTH_CHECK_READ_FAILURE.get(getExceptionMessage(e)),
                 e);
            poolStatistics.incrementNumConnectionsClosedDefunct();
            conn = handleDefunctConnection(conn);
            if (conn != null)
            {
              examinedConnections.add(conn);
            }
            continue;
          }
          finally
          {
            if (previousTimeout != Integer.MIN_VALUE)
            {
              try
              {
                s.setSoTimeout(previousTimeout);
              }
              catch (final Exception e)
              {
                debugException(e);
                conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT,
                     null, e);
                poolStatistics.incrementNumConnectionsClosedDefunct();
                conn = handleDefunctConnection(conn);
                if (conn != null)
                {
                  examinedConnections.add(conn);
                }
                continue;
              }
            }
          }
        }

        try
        {
          healthCheck.ensureConnectionValidForContinuedUse(conn);
          if (availableConnections.offer(conn))
          {
            examinedConnections.add(conn);
          }
          else
          {
            conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_UNNEEDED,
                                   null, null);
            poolStatistics.incrementNumConnectionsClosedUnneeded();
            conn.terminate(null);
          }
        }
        catch (Exception e)
        {
          debugException(e);
          conn = handleDefunctConnection(conn);
          if (conn != null)
          {
            examinedConnections.add(conn);
          }
        }
      }
    }
  }




  @Override()
  public int getCurrentAvailableConnections()
  {
    return availableConnections.size();
  }


  @Override()
  public int getMaximumAvailableConnections()
  {
    return numConnections;
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
    buffer.append("LDAPConnectionPool(");

    final String name = connectionPoolName;
    if (name != null)
    {
      buffer.append("name='");
      buffer.append(name);
      buffer.append("', ");
    }

    buffer.append("serverSet=");
    serverSet.toString(buffer);
    buffer.append(", maxConnections=");
    buffer.append(numConnections);
    buffer.append(')');
  }
}
