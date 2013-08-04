package com.hwlcn.ldap.ldap.sdk;



import java.util.Collection;
import java.util.List;
import java.util.Timer;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import com.hwlcn.ldap.asn1.ASN1OctetString;
import com.hwlcn.ldap.ldap.protocol.AbandonRequestProtocolOp;
import com.hwlcn.ldap.ldap.protocol.LDAPMessage;
import com.hwlcn.ldap.ldap.protocol.LDAPResponse;
import com.hwlcn.ldap.ldap.protocol.UnbindRequestProtocolOp;
import com.hwlcn.ldap.ldap.sdk.schema.Schema;
import com.hwlcn.ldap.ldif.LDIFException;
import com.hwlcn.ldap.util.DebugType;
import com.hwlcn.ldap.util.SynchronizedSocketFactory;
import com.hwlcn.ldap.util.SynchronizedSSLSocketFactory;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;
import com.hwlcn.ldap.util.WeakHashSet;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;
import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.StaticUtils.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides a facility for interacting with an LDAPv3 directory
 * server.  It provides a means of establishing a connection to the server,
 * sending requests, and reading responses.  See
 * <A HREF="http://www.ietf.org/rfc/rfc4511.txt">RFC 4511</A> for the LDAPv3
 * protocol specification and more information about the types of operations
 * defined in LDAP.
 * <BR><BR>
 * <H2>Creating, Establishing, and Authenticating Connections</H2>
 * An LDAP connection can be established either at the time that the object is
 * created or as a separate step.  Similarly, authentication can be performed on
 * the connection at the time it is created, at the time it is established, or
 * as a separate process.  For example:
 * <BR><BR>
 * <PRE>
 *   // Create a new, unestablished connection.  Then connect and perform a
 *   // simple bind as separate operations.
 *   LDAPConnection c = new LDAPConnection();
 *   c.connect(address, port);
 *   BindResult bindResult = c.bind(bindDN, password);
 *
 *   // Create a new connection that is established at creation time, and then
 *   // authenticate separately using simple authentication.
 *   LDAPConnection c = new LDAPConnection(address, port);
 *   BindResult bindResult = c.bind(bindDN, password);
 *
 *   // Create a new connection that is established and bound using simple
 *   // authentication all in one step.
 *   LDAPConnection c = new LDAPConnection(address, port, bindDN, password);
 * </PRE>
 * <BR><BR>
 * When authentication is performed at the time that the connection is
 * established, it is only possible to perform a simple bind and it is not
 * possible to include controls in the bind request, nor is it possible to
 * receive response controls if the bind was successful.  Therefore, it is
 * recommended that authentication be performed as a separate step if the server
 * may return response controls even in the event of a successful authentication
 * (e.g., a control that may indicate that the user's password will soon
 * expire).  See the {@link com.hwlcn.ldap.ldap.sdk.BindRequest} class for more information about
 * authentication in the UnboundID LDAP SDK for Java.
 * <BR><BR>
 * By default, connections will use standard unencrypted network sockets.
 * However, it may be desirable to create connections that use SSL/TLS to
 * encrypt communication.  This can be done by specifying a
 * {@link javax.net.SocketFactory} that should be used to create the socket to
 * use to communicate with the directory server.  The
 * {@link javax.net.ssl.SSLSocketFactory#getDefault} method or the
 * {@link javax.net.ssl.SSLContext#getSocketFactory} method may be used to
 * obtain a socket factory for performing SSL communication.  See the
 * <A HREF=
 * "http://java.sun.com/j2se/1.5.0/docs/guide/security/jsse/JSSERefGuide.html">
 * JSSE Reference Guide</A> for more information on using these classes.
 * Alternately, you may use the {@link com.hwlcn.ldap.util.ssl.SSLUtil} class to
 * simplify the process.
 * <BR><BR>
 * Whenever the connection is no longer needed, it may be terminated using the
 * {@link com.hwlcn.ldap.ldap.sdk.LDAPConnection#close} method.
 * <BR><BR>
 * <H2>Processing LDAP Operations</H2>
 * This class provides a number of methods for processing the different types of
 * operations.  The types of operations that can be processed include:
 * <UL>
 *   <LI>Abandon -- This may be used to request that the server stop processing
 *      on an operation that has been invoked asynchronously.</LI>
 *   <LI>Add -- This may be used to add a new entry to the directory
 *       server.  See the {@link AddRequest} class for more information about
 *       processing add operations.</LI>
 *   <LI>Bind -- This may be used to authenticate to the directory server.  See
 *       the {@link com.hwlcn.ldap.ldap.sdk.BindRequest} class for more information about processing
 *       bind operations.</LI>
 *   <LI>Compare -- This may be used to determine whether a specified entry has
 *       a given attribute value.  See the {@link com.hwlcn.ldap.ldap.sdk.CompareRequest} class for more
 *       information about processing compare operations.</LI>
 *   <LI>Delete -- This may be used to remove an entry from the directory
 *       server.  See the {@link com.hwlcn.ldap.ldap.sdk.DeleteRequest} class for more information about
 *       processing delete operations.</LI>
 *   <LI>Extended -- This may be used to process an operation which is not
 *       part of the core LDAP protocol but is a custom extension supported by
 *       the directory server.  See the {@link ExtendedRequest} class for more
 *       information about processing extended operations.</LI>
 *   <LI>Modify -- This may be used to alter an entry in the directory
 *       server.  See the {@link com.hwlcn.ldap.ldap.sdk.ModifyRequest} class for more information about
 *       processing modify operations.</LI>
 *   <LI>Modify DN -- This may be used to rename an entry or subtree and/or move
 *       that entry or subtree below a new parent in the directory server.  See
 *       the {@link ModifyDNRequest} class for more information about processing
 *       modify DN operations.</LI>
 *   <LI>Search -- This may be used to retrieve a set of entries in the server
 *       that match a given set of criteria.  See the {@link com.hwlcn.ldap.ldap.sdk.SearchRequest}
 *       class for more information about processing search operations.</LI>
 * </UL>
 * <BR><BR>
 * Most of the methods in this class used to process operations operate in a
 * synchronous manner.  In these cases, the SDK will send a request to the
 * server and wait for a response to arrive before returning to the caller.  In
 * these cases, the value returned will include the contents of that response,
 * including the result code, diagnostic message, matched DN, referral URLs, and
 * any controls that may have been included.  However, it also possible to
 * process operations asynchronously, in which case the SDK will return control
 * back to the caller after the request has been sent to the server but before
 * the response has been received.  In this case, the SDK will return an
 * {@link com.hwlcn.ldap.ldap.sdk.AsyncRequestID} object which may be used to later abandon or cancel
 * that operation if necessary, and will notify the client when the response
 * arrives via a listener interface.
 * <BR><BR>
 * This class is mostly threadsafe.  It is possible to process multiple
 * concurrent operations over the same connection as long as the methods being
 * invoked will not change the state of the connection in a way that might
 * impact other operations in progress in unexpected ways.  In particular, the
 * following should not be attempted while any other operations may be in
 * progress on this connection:
 * <UL>
 *   <LI>
 *     Using one of the {@code connect} methods to re-establish the connection.
 *   </LI>
 *   <LI>
 *     Using one of the {@code close} methods to terminate the connection.
 *   </LI>
 *   <LI>
 *     Using one of the {@code bind} methods to attempt to authenticate the
 *     connection (unless you are certain that the bind will not impact the
 *     identity of the associated connection, for example by including the
 *     retain identity request control in the bind request if using the
 *     Commercial Edition of the LDAP SDK in conjunction with an UnboundID
 *     Directory Server).
 *   </LI>
 *   <LI>
 *     Attempting to make a change to the way that the underlying communication
 *     is processed (e.g., by using the StartTLS extended operation to convert
 *     an insecure connection into a secure one).
 *   </LI>
 * </UL>
 */
@ThreadSafety(level=ThreadSafetyLevel.MOSTLY_THREADSAFE)
public final class LDAPConnection
       implements LDAPInterface, ReferralConnector
{

  private static final AtomicLong NEXT_CONNECTION_ID = new AtomicLong(0L);

  private static final SocketFactory DEFAULT_SOCKET_FACTORY =
                                          SocketFactory.getDefault();

  private static final WeakHashSet<Schema> SCHEMA_SET =
       new WeakHashSet<Schema>();

  private AbstractConnectionPool connectionPool;

  private final AtomicBoolean needsReconnect;

  private BindRequest lastBindRequest;

  private volatile boolean closeRequested;

  private volatile boolean unbindRequestSent;

  private final AtomicReference<DisconnectInfo> disconnectInfo;

  private int reconnectPort = -1;

  private volatile LDAPConnectionInternals connectionInternals;

  private LDAPConnectionOptions connectionOptions;

  private final LDAPConnectionStatistics connectionStatistics;

  private final long connectionID;

  private long lastReconnectTime;

  private volatile ReferralConnector referralConnector;

  private volatile Schema cachedSchema;

  private SocketFactory lastUsedSocketFactory;

  private volatile SocketFactory socketFactory;

  private StackTraceElement[] connectStackTrace;

  private String connectionName;

  private String connectionPoolName;

  private String hostPort;

  private String reconnectAddress;

  private Timer timer;

  public LDAPConnection()
  {
    this(null, null);
  }


  public LDAPConnection(final LDAPConnectionOptions connectionOptions)
  {
    this(null, connectionOptions);
  }

  public LDAPConnection(final SocketFactory socketFactory)
  {
    this(socketFactory, null);
  }


  public LDAPConnection(final SocketFactory socketFactory,
                        final LDAPConnectionOptions connectionOptions)
  {
    needsReconnect = new AtomicBoolean(false);
    disconnectInfo = new AtomicReference<DisconnectInfo>();

    connectionID = NEXT_CONNECTION_ID.getAndIncrement();

    if (connectionOptions == null)
    {
      this.connectionOptions = new LDAPConnectionOptions();
    }
    else
    {
      this.connectionOptions = connectionOptions.duplicate();
    }

    final SocketFactory f;
    if (socketFactory == null)
    {
      f = DEFAULT_SOCKET_FACTORY;
    }
    else
    {
      f = socketFactory;
    }

    if (this.connectionOptions.allowConcurrentSocketFactoryUse())
    {
      this.socketFactory = f;
    }
    else
    {
      if (f instanceof SSLSocketFactory)
      {
        this.socketFactory =
             new SynchronizedSSLSocketFactory((SSLSocketFactory) f);
      }
      else
      {
        this.socketFactory = new SynchronizedSocketFactory(f);
      }
    }

    connectionStatistics = new LDAPConnectionStatistics();
    connectionName       = null;
    connectionPoolName   = null;
    cachedSchema         = null;
    timer                = null;

    referralConnector = this.connectionOptions.getReferralConnector();
    if (referralConnector == null)
    {
      referralConnector = this;
    }
  }


  public LDAPConnection(final String host, final int port)
         throws LDAPException
  {
    this(null, null, host, port);
  }


  public LDAPConnection(final LDAPConnectionOptions connectionOptions,
                        final String host, final int port)
         throws LDAPException
  {
    this(null, connectionOptions, host, port);
  }


  public LDAPConnection(final SocketFactory socketFactory, final String host,
                        final int port)
         throws LDAPException
  {
    this(socketFactory, null, host, port);
  }

  public LDAPConnection(final SocketFactory socketFactory,
                        final LDAPConnectionOptions connectionOptions,
                        final String host, final int port)
         throws LDAPException
  {
    this(socketFactory, connectionOptions);

    connect(host, port);
  }

  public LDAPConnection(final String host, final int port, final String bindDN,
                        final String bindPassword)
         throws LDAPException
  {
    this(null, null, host, port, bindDN, bindPassword);
  }


  public LDAPConnection(final LDAPConnectionOptions connectionOptions,
                        final String host, final int port, final String bindDN,
                        final String bindPassword)
         throws LDAPException
  {
    this(null, connectionOptions, host, port, bindDN, bindPassword);
  }


  public LDAPConnection(final SocketFactory socketFactory, final String host,
                        final int port, final String bindDN,
                        final String bindPassword)
         throws LDAPException
  {
    this(socketFactory, null, host, port, bindDN, bindPassword);
  }


  public LDAPConnection(final SocketFactory socketFactory,
                        final LDAPConnectionOptions connectionOptions,
                        final String host, final int port, final String bindDN,
                        final String bindPassword)
         throws LDAPException
  {
    this(socketFactory, connectionOptions, host, port);

    try
    {
      bind(new SimpleBindRequest(bindDN, bindPassword));
    }
    catch (LDAPException le)
    {
      debugException(le);
      setDisconnectInfo(DisconnectType.BIND_FAILED, null, le);
      close();
      throw le;
    }
  }


  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public void connect(final String host, final int port)
         throws LDAPException
  {
    connect(host, port, connectionOptions.getConnectTimeoutMillis());
  }

  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public void connect(final String host, final int port, final int timeout)
         throws LDAPException
  {
    ensureNotNull(host, port);

    needsReconnect.set(false);
    hostPort = host + ':' + port;

    if (isConnected())
    {
      setDisconnectInfo(DisconnectType.RECONNECT, null, null);
      close();
    }

    lastUsedSocketFactory = socketFactory;
    reconnectAddress      = host;
    reconnectPort         = port;
    cachedSchema          = null;
    unbindRequestSent     = false;

    disconnectInfo.set(null);

    try
    {
      connectionStatistics.incrementNumConnects();
      connectionInternals = new LDAPConnectionInternals(this, connectionOptions,
           lastUsedSocketFactory, host, port, timeout);
      connectionInternals.startConnectionReader();
    }
    catch (Exception e)
    {
      debugException(e);
      setDisconnectInfo(DisconnectType.LOCAL_ERROR, null, e);
      connectionInternals = null;
      throw new LDAPException(ResultCode.CONNECT_ERROR,
           ERR_CONN_CONNECT_ERROR.get(getHostPort(), getExceptionMessage(e)),
           e);
    }

    if (connectionOptions.useSchema())
    {
      try
      {
        cachedSchema = getCachedSchema(this);
      }
      catch (Exception e)
      {
        debugException(e);
      }
    }
  }


  public void reconnect()
         throws LDAPException
  {
    needsReconnect.set(false);
    if ((System.currentTimeMillis() - lastReconnectTime) < 1000L)
    {
      throw new LDAPException(ResultCode.SERVER_DOWN,
                              ERR_CONN_MULTIPLE_FAILURES.get());
    }

    BindRequest bindRequest = null;
    if (lastBindRequest != null)
    {
      bindRequest = lastBindRequest.getRebindRequest(reconnectAddress,
                                                     reconnectPort);
      if (bindRequest == null)
      {
        throw new LDAPException(ResultCode.SERVER_DOWN,
             ERR_CONN_CANNOT_REAUTHENTICATE.get(getHostPort()));
      }
    }

    setDisconnectInfo(DisconnectType.RECONNECT, null, null);
    terminate(null);

    try
    {
      Thread.sleep(10);
    } catch (final Exception e) {}

    connect(reconnectAddress, reconnectPort);

    if (bindRequest != null)
    {
      try
      {
        bind(bindRequest);
      }
      catch (LDAPException le)
      {
        debugException(le);
        setDisconnectInfo(DisconnectType.BIND_FAILED, null, le);
        terminate(null);

        throw le;
      }
    }

    lastReconnectTime = System.currentTimeMillis();
  }

  void setNeedsReconnect()
  {
    needsReconnect.set(true);
  }


  public boolean isConnected()
  {
    final LDAPConnectionInternals internals = connectionInternals;

    if (internals == null)
    {
      return false;
    }

    if (! internals.isConnected())
    {
      setClosed();
      return false;
    }

    return (! needsReconnect.get());
  }


  void convertToTLS(final SSLContext sslContext)
       throws LDAPException
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals == null)
    {
      throw new LDAPException(ResultCode.SERVER_DOWN,
                              ERR_CONN_NOT_ESTABLISHED.get());
    }
    else
    {
      internals.convertToTLS(sslContext);
    }
  }

  public LDAPConnectionOptions getConnectionOptions()
  {
    return connectionOptions;
  }

  public void setConnectionOptions(
                   final LDAPConnectionOptions connectionOptions)
  {
    if (connectionOptions == null)
    {
      this.connectionOptions = new LDAPConnectionOptions();
    }
    else
    {
      final LDAPConnectionOptions newOptions = connectionOptions.duplicate();
      if (debugEnabled(DebugType.LDAP) && newOptions.useSynchronousMode() &&
          (! connectionOptions.useSynchronousMode()) && isConnected())
      {
        debug(Level.WARNING, DebugType.LDAP,
              "A call to LDAPConnection.setConnectionOptions() with " +
              "useSynchronousMode=true will have no effect for this " +
              "connection because it is already established.  The " +
              "useSynchronousMode option must be set before the connection " +
              "is established to have any effect.");
      }

      this.connectionOptions = newOptions;
    }

    final ReferralConnector rc = this.connectionOptions.getReferralConnector();
    if (rc == null)
    {
      referralConnector = this;
    }
    else
    {
      referralConnector = rc;
    }
  }



  public SocketFactory getLastUsedSocketFactory()
  {
    return lastUsedSocketFactory;
  }



  public SocketFactory getSocketFactory()
  {
    return socketFactory;
  }


  public void setSocketFactory(final SocketFactory socketFactory)
  {
    if (socketFactory == null)
    {
      this.socketFactory = DEFAULT_SOCKET_FACTORY;
    }
    else
    {
      this.socketFactory = socketFactory;
    }
  }

  public long getConnectionID()
  {
    return connectionID;
  }


  public String getConnectionName()
  {
    return connectionName;
  }


  public void setConnectionName(final String connectionName)
  {
    if (connectionPool == null)
    {
      this.connectionName = connectionName;
      if (connectionInternals != null)
      {
        final LDAPConnectionReader reader =
             connectionInternals.getConnectionReader();
        reader.updateThreadName();
      }
    }
  }


  AbstractConnectionPool getConnectionPool()
  {
    return connectionPool;
  }


  public String getConnectionPoolName()
  {
    return connectionPoolName;
  }


  void setConnectionPoolName(final String connectionPoolName)
  {
    this.connectionPoolName = connectionPoolName;
    if (connectionInternals != null)
    {
      final LDAPConnectionReader reader =
           connectionInternals.getConnectionReader();
      reader.updateThreadName();
    }
  }


  String getHostPort()
  {
    if (hostPort == null)
    {
      return "";
    }
    else
    {
      return hostPort;
    }
  }


  public String getConnectedAddress()
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals == null)
    {
      return null;
    }
    else
    {
      return internals.getHost();
    }
  }



  public int getConnectedPort()
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals == null)
    {
      return -1;
    }
    else
    {
      return internals.getPort();
    }
  }


  public StackTraceElement[] getConnectStackTrace()
  {
    return connectStackTrace;
  }


  void setConnectStackTrace(final StackTraceElement[] connectStackTrace)
  {
    this.connectStackTrace = connectStackTrace;
  }


  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public void close()
  {
    closeRequested = true;
    setDisconnectInfo(DisconnectType.UNBIND, null, null);

    if (connectionPool == null)
    {
      terminate(null);
    }
    else
    {
      connectionPool.releaseDefunctConnection(this);
    }
  }


  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public void close(final Control[] controls)
  {
    closeRequested = true;
    setDisconnectInfo(DisconnectType.UNBIND, null, null);

    if (connectionPool == null)
    {
      terminate(controls);
    }
    else
    {
      connectionPool.releaseDefunctConnection(this);
    }
  }

  void terminate(final Control[] controls)
  {
    if (isConnected() && (! unbindRequestSent))
    {
      try
      {
        unbindRequestSent = true;
        setDisconnectInfo(DisconnectType.UNBIND, null, null);
        if (debugEnabled(DebugType.LDAP))
        {
          debug(Level.INFO, DebugType.LDAP, "Sending LDAP unbind request.");
        }

        connectionStatistics.incrementNumUnbindRequests();
        sendMessage(new LDAPMessage(nextMessageID(),
             new UnbindRequestProtocolOp(), controls));
      }
      catch (Exception e)
      {
        debugException(e);
      }
    }

    setClosed();
  }


  boolean closeRequested()
  {
    return closeRequested;
  }


  boolean unbindRequestSent()
  {
    return unbindRequestSent;
  }


  void setConnectionPool(final AbstractConnectionPool connectionPool)
  {
    this.connectionPool = connectionPool;
  }


  public RootDSE getRootDSE()
         throws LDAPException
  {
    return RootDSE.getRootDSE(this);
  }


  public Schema getSchema()
         throws LDAPException
  {
    return Schema.getSchema(this, "");
  }


  public Schema getSchema(final String entryDN)
         throws LDAPException
  {
    return Schema.getSchema(this, entryDN);
  }

  public SearchResultEntry getEntry(final String dn)
         throws LDAPException
  {
    return getEntry(dn, (String[]) null);
  }


  public SearchResultEntry getEntry(final String dn, final String... attributes)
         throws LDAPException
  {
    final Filter filter = Filter.createPresenceFilter("objectClass");

    final SearchResult result;
    try
    {
      final SearchRequest searchRequest =
           new SearchRequest(dn, SearchScope.BASE, DereferencePolicy.NEVER, 1,
                             0, false, filter, attributes);
      result = search(searchRequest);
    }
    catch (LDAPException le)
    {
      if (le.getResultCode().equals(ResultCode.NO_SUCH_OBJECT))
      {
        return null;
      }
      else
      {
        throw le;
      }
    }

    if (! result.getResultCode().equals(ResultCode.SUCCESS))
    {
      throw new LDAPException(result);
    }

    final List<SearchResultEntry> entryList = result.getSearchEntries();
    if (entryList.isEmpty())
    {
      return null;
    }
    else
    {
      return entryList.get(0);
    }
  }

  public void abandon(final AsyncRequestID requestID)
         throws LDAPException
  {
    abandon(requestID, null);
  }


  public void abandon(final AsyncRequestID requestID, final Control[] controls)
         throws LDAPException
  {
    if (debugEnabled(DebugType.LDAP))
    {
      debug(Level.INFO, DebugType.LDAP,
            "Sending LDAP abandon request for message ID " + requestID);
    }

    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ABANDON_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    connectionStatistics.incrementNumAbandonRequests();
    sendMessage(new LDAPMessage(nextMessageID(),
         new AbandonRequestProtocolOp(requestID.getMessageID()), controls));
  }



  void abandon(final int messageID, final Control... controls)
       throws LDAPException
  {
    if (debugEnabled(DebugType.LDAP))
    {
      debug(Level.INFO, DebugType.LDAP,
            "Sending LDAP abandon request for message ID " + messageID);
    }

    connectionStatistics.incrementNumAbandonRequests();
    sendMessage(new LDAPMessage(nextMessageID(),
         new AbandonRequestProtocolOp(messageID), controls));
  }


  public LDAPResult add(final String dn, final Attribute... attributes)
         throws LDAPException
  {
    ensureNotNull(dn, attributes);

    return add(new AddRequest(dn, attributes));
  }


  public LDAPResult add(final String dn, final Collection<Attribute> attributes)
         throws LDAPException
  {
    ensureNotNull(dn, attributes);

    return add(new AddRequest(dn, attributes));
  }


  public LDAPResult add(final Entry entry)
         throws LDAPException
  {
    ensureNotNull(entry);

    return add(new AddRequest(entry));
  }


  public LDAPResult add(final String... ldifLines)
         throws LDIFException, LDAPException
  {
    return add(new AddRequest(ldifLines));
  }


  public LDAPResult add(final AddRequest addRequest)
         throws LDAPException
  {
    ensureNotNull(addRequest);

    final LDAPResult ldapResult = addRequest.process(this, 1);

    switch (ldapResult.getResultCode().intValue())
    {
      case ResultCode.SUCCESS_INT_VALUE:
      case ResultCode.NO_OPERATION_INT_VALUE:
        return ldapResult;

      default:
        throw new LDAPException(ldapResult);
    }
  }


  public LDAPResult add(final ReadOnlyAddRequest addRequest)
         throws LDAPException
  {
    return add((AddRequest) addRequest);
  }


  public AsyncRequestID asyncAdd(final AddRequest addRequest,
                                 final AsyncResultListener resultListener)
         throws LDAPException
  {
    ensureNotNull(addRequest, resultListener);

    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return addRequest.processAsync(this, resultListener);
  }


  public AsyncRequestID asyncAdd(final ReadOnlyAddRequest addRequest,
                                 final AsyncResultListener resultListener)
         throws LDAPException
  {
    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return asyncAdd((AddRequest) addRequest, resultListener);
  }



  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public BindResult bind(final String bindDN, final String password)
         throws LDAPException
  {
    return bind(new SimpleBindRequest(bindDN, password));
  }


  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public BindResult bind(final BindRequest bindRequest)
         throws LDAPException
  {
    ensureNotNull(bindRequest);

    lastBindRequest = null;

    final BindResult bindResult = bindRequest.process(this, 1);

    if (bindResult.getResultCode().equals(ResultCode.SUCCESS))
    {

      boolean hasRetainIdentityControl = false;
      for (final Control c : bindRequest.getControls())
      {
        if (c.getOID().equals("1.3.6.1.4.1.30221.2.5.3"))
        {
          hasRetainIdentityControl = true;
          break;
        }
      }

      if (! hasRetainIdentityControl)
      {
        lastBindRequest = bindRequest;

        if (connectionOptions.useSchema())
        {
          try
          {
            cachedSchema = getCachedSchema(this);
          }
          catch (Exception e)
          {
            debugException(e);
          }
        }
      }

      return bindResult;
    }

    if (bindResult.getResultCode().equals(ResultCode.SASL_BIND_IN_PROGRESS))
    {
      throw new SASLBindInProgressException(bindResult);
    }
    else
    {
      throw new LDAPException(bindResult);
    }
  }


  public CompareResult compare(final String dn, final String attributeName,
                               final String assertionValue)
         throws LDAPException
  {
    ensureNotNull(dn, attributeName, assertionValue);

    return compare(new CompareRequest(dn, attributeName, assertionValue));
  }


  public CompareResult compare(final CompareRequest compareRequest)
         throws LDAPException
  {
    ensureNotNull(compareRequest);

    final LDAPResult result = compareRequest.process(this, 1);
    switch (result.getResultCode().intValue())
    {
      case ResultCode.COMPARE_FALSE_INT_VALUE:
      case ResultCode.COMPARE_TRUE_INT_VALUE:
        return new CompareResult(result);

      default:
        throw new LDAPException(result);
    }
  }


  public CompareResult compare(final ReadOnlyCompareRequest compareRequest)
         throws LDAPException
  {
    return compare((CompareRequest) compareRequest);
  }


  public AsyncRequestID asyncCompare(final CompareRequest compareRequest,
                             final AsyncCompareResultListener resultListener)
         throws LDAPException
  {
    ensureNotNull(compareRequest, resultListener);

    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return compareRequest.processAsync(this, resultListener);
  }

  public AsyncRequestID asyncCompare(
                             final ReadOnlyCompareRequest compareRequest,
                             final AsyncCompareResultListener resultListener)
         throws LDAPException
  {
    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return asyncCompare((CompareRequest) compareRequest, resultListener);
  }


  public LDAPResult delete(final String dn)
         throws LDAPException
  {
    return delete(new DeleteRequest(dn));
  }


  public LDAPResult delete(final DeleteRequest deleteRequest)
         throws LDAPException
  {
    ensureNotNull(deleteRequest);

    final LDAPResult ldapResult = deleteRequest.process(this, 1);

    switch (ldapResult.getResultCode().intValue())
    {
      case ResultCode.SUCCESS_INT_VALUE:
      case ResultCode.NO_OPERATION_INT_VALUE:
        return ldapResult;

      default:
        throw new LDAPException(ldapResult);
    }
  }


  public LDAPResult delete(final ReadOnlyDeleteRequest deleteRequest)
         throws LDAPException
  {
    return delete((DeleteRequest) deleteRequest);
  }



  public AsyncRequestID asyncDelete(final DeleteRequest deleteRequest,
                             final AsyncResultListener resultListener)
         throws LDAPException
  {
    ensureNotNull(deleteRequest, resultListener);

    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return deleteRequest.processAsync(this, resultListener);
  }


  public AsyncRequestID asyncDelete(final ReadOnlyDeleteRequest deleteRequest,
                             final AsyncResultListener resultListener)
         throws LDAPException
  {
    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return asyncDelete((DeleteRequest) deleteRequest, resultListener);
  }


  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public ExtendedResult processExtendedOperation(final String requestOID)
         throws LDAPException
  {
    ensureNotNull(requestOID);

    return processExtendedOperation(new ExtendedRequest(requestOID));
  }


  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public ExtendedResult processExtendedOperation(final String requestOID,
                             final ASN1OctetString requestValue)
         throws LDAPException
  {
    ensureNotNull(requestOID);

    return processExtendedOperation(new ExtendedRequest(requestOID,
                                                        requestValue));
  }


  @ThreadSafety(level=ThreadSafetyLevel.METHOD_NOT_THREADSAFE)
  public ExtendedResult processExtendedOperation(
                               final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    ensureNotNull(extendedRequest);

    final ExtendedResult extendedResult = extendedRequest.process(this, 1);

    if ((extendedResult.getOID() == null) &&
        (extendedResult.getValue() == null))
    {
      switch (extendedResult.getResultCode().intValue())
      {
        case ResultCode.OPERATIONS_ERROR_INT_VALUE:
        case ResultCode.PROTOCOL_ERROR_INT_VALUE:
        case ResultCode.BUSY_INT_VALUE:
        case ResultCode.UNAVAILABLE_INT_VALUE:
        case ResultCode.OTHER_INT_VALUE:
        case ResultCode.SERVER_DOWN_INT_VALUE:
        case ResultCode.LOCAL_ERROR_INT_VALUE:
        case ResultCode.ENCODING_ERROR_INT_VALUE:
        case ResultCode.DECODING_ERROR_INT_VALUE:
        case ResultCode.TIMEOUT_INT_VALUE:
        case ResultCode.NO_MEMORY_INT_VALUE:
        case ResultCode.CONNECT_ERROR_INT_VALUE:
          throw new LDAPException(extendedResult);
      }
    }

    return extendedResult;
  }


  public LDAPResult modify(final String dn, final Modification mod)
         throws LDAPException
  {
    ensureNotNull(dn, mod);

    return modify(new ModifyRequest(dn, mod));
  }



  public LDAPResult modify(final String dn, final Modification... mods)
         throws LDAPException
  {
    ensureNotNull(dn, mods);

    return modify(new ModifyRequest(dn, mods));
  }


  public LDAPResult modify(final String dn, final List<Modification> mods)
         throws LDAPException
  {
    ensureNotNull(dn, mods);

    return modify(new ModifyRequest(dn, mods));
  }


  public LDAPResult modify(final String... ldifModificationLines)
         throws LDIFException, LDAPException
  {
    ensureNotNull(ldifModificationLines);

    return modify(new ModifyRequest(ldifModificationLines));
  }


  public LDAPResult modify(final ModifyRequest modifyRequest)
         throws LDAPException
  {
    ensureNotNull(modifyRequest);

    final LDAPResult ldapResult = modifyRequest.process(this, 1);

    switch (ldapResult.getResultCode().intValue())
    {
      case ResultCode.SUCCESS_INT_VALUE:
      case ResultCode.NO_OPERATION_INT_VALUE:
        return ldapResult;

      default:
        throw new LDAPException(ldapResult);
    }
  }


  public LDAPResult modify(final ReadOnlyModifyRequest modifyRequest)
         throws LDAPException
  {
    return modify((ModifyRequest) modifyRequest);
  }


  public AsyncRequestID asyncModify(final ModifyRequest modifyRequest,
                             final AsyncResultListener resultListener)
         throws LDAPException
  {
    ensureNotNull(modifyRequest, resultListener);

    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return modifyRequest.processAsync(this, resultListener);
  }


  public AsyncRequestID asyncModify(final ReadOnlyModifyRequest modifyRequest,
                             final AsyncResultListener resultListener)
         throws LDAPException
  {
    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return asyncModify((ModifyRequest) modifyRequest, resultListener);
  }


  public LDAPResult modifyDN(final String dn, final String newRDN,
                             final boolean deleteOldRDN)
         throws LDAPException
  {
    ensureNotNull(dn, newRDN);

    return modifyDN(new ModifyDNRequest(dn, newRDN, deleteOldRDN));
  }



  public LDAPResult modifyDN(final String dn, final String newRDN,
                             final boolean deleteOldRDN,
                             final String newSuperiorDN)
         throws LDAPException
  {
    ensureNotNull(dn, newRDN);

    return modifyDN(new ModifyDNRequest(dn, newRDN, deleteOldRDN,
                                        newSuperiorDN));
  }


  public LDAPResult modifyDN(final ModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    ensureNotNull(modifyDNRequest);

    final LDAPResult ldapResult = modifyDNRequest.process(this, 1);

    switch (ldapResult.getResultCode().intValue())
    {
      case ResultCode.SUCCESS_INT_VALUE:
      case ResultCode.NO_OPERATION_INT_VALUE:
        return ldapResult;

      default:
        throw new LDAPException(ldapResult);
    }
  }

  public LDAPResult modifyDN(final ReadOnlyModifyDNRequest modifyDNRequest)
         throws LDAPException
  {
    return modifyDN((ModifyDNRequest) modifyDNRequest);
  }



  public AsyncRequestID asyncModifyDN(final ModifyDNRequest modifyDNRequest,
                             final AsyncResultListener resultListener)
         throws LDAPException
  {
    ensureNotNull(modifyDNRequest, resultListener);

    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return modifyDNRequest.processAsync(this, resultListener);
  }


  public AsyncRequestID asyncModifyDN(
                             final ReadOnlyModifyDNRequest modifyDNRequest,
                             final AsyncResultListener resultListener)
         throws LDAPException
  {
    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return asyncModifyDN((ModifyDNRequest) modifyDNRequest, resultListener);
  }

  public SearchResult search(final String baseDN, final SearchScope scope,
                             final String filter, final String... attributes)
         throws LDAPSearchException
  {
    ensureNotNull(baseDN, filter);

    try
    {
      return search(new SearchRequest(baseDN, scope, filter, attributes));
    }
    catch (LDAPSearchException lse)
    {
      debugException(lse);
      throw lse;
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }
  }


  public SearchResult search(final String baseDN, final SearchScope scope,
                             final Filter filter, final String... attributes)
         throws LDAPSearchException
  {
    ensureNotNull(baseDN, filter);

    return search(new SearchRequest(baseDN, scope, filter, attributes));
  }

  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final String filter, final String... attributes)
         throws LDAPSearchException
  {
    ensureNotNull(baseDN, filter);

    try
    {
      return search(new SearchRequest(searchResultListener, baseDN, scope,
                                      filter, attributes));
    }
    catch (LDAPSearchException lse)
    {
      debugException(lse);
      throw lse;
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }
  }

  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final Filter filter, final String... attributes)
         throws LDAPSearchException
  {
    ensureNotNull(baseDN, filter);

    try
    {
      return search(new SearchRequest(searchResultListener, baseDN, scope,
                                      filter, attributes));
    }
    catch (LDAPSearchException lse)
    {
      debugException(lse);
      throw lse;
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }
  }

  public SearchResult search(final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final String filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    ensureNotNull(baseDN, filter);

    try
    {
      return search(new SearchRequest(baseDN, scope, derefPolicy, sizeLimit,
                                      timeLimit, typesOnly, filter,
                                      attributes));
    }
    catch (LDAPSearchException lse)
    {
      debugException(lse);
      throw lse;
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }
  }

  public SearchResult search(final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final Filter filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    ensureNotNull(baseDN, filter);

    return search(new SearchRequest(baseDN, scope, derefPolicy, sizeLimit,
                                    timeLimit, typesOnly, filter, attributes));
  }

  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final String filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    ensureNotNull(baseDN, filter);

    try
    {
      return search(new SearchRequest(searchResultListener, baseDN, scope,
                                      derefPolicy, sizeLimit, timeLimit,
                                      typesOnly, filter, attributes));
    }
    catch (LDAPSearchException lse)
    {
      debugException(lse);
      throw lse;
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }
  }

  public SearchResult search(final SearchResultListener searchResultListener,
                             final String baseDN, final SearchScope scope,
                             final DereferencePolicy derefPolicy,
                             final int sizeLimit, final int timeLimit,
                             final boolean typesOnly, final Filter filter,
                             final String... attributes)
         throws LDAPSearchException
  {
    ensureNotNull(baseDN, filter);

    return search(new SearchRequest(searchResultListener, baseDN, scope,
                                    derefPolicy, sizeLimit, timeLimit,
                                    typesOnly, filter, attributes));
  }

  public SearchResult search(final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    ensureNotNull(searchRequest);

    final SearchResult searchResult;
    try
    {
      searchResult = searchRequest.process(this, 1);
    }
    catch (LDAPSearchException lse)
    {
      debugException(lse);
      throw lse;
    }
    catch (LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    if (! searchResult.getResultCode().equals(ResultCode.SUCCESS))
    {
      throw new LDAPSearchException(searchResult);
    }

    return searchResult;
  }

  public SearchResult search(final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return search((SearchRequest) searchRequest);
  }

  public SearchResultEntry searchForEntry(final String baseDN,
                                          final SearchScope scope,
                                          final String filter,
                                          final String... attributes)
         throws LDAPSearchException
  {
    final SearchRequest r;
    try
    {
      r = new SearchRequest(baseDN, scope, DereferencePolicy.NEVER, 1, 0, false,
           filter, attributes);
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    return searchForEntry(r);
  }

  public SearchResultEntry searchForEntry(final String baseDN,
                                          final SearchScope scope,
                                          final Filter filter,
                                          final String... attributes)
         throws LDAPSearchException
  {
    return searchForEntry(new SearchRequest(baseDN, scope,
         DereferencePolicy.NEVER, 1, 0, false, filter, attributes));
  }


  public SearchResultEntry searchForEntry(final String baseDN,
                                          final SearchScope scope,
                                          final DereferencePolicy derefPolicy,
                                          final int timeLimit,
                                          final boolean typesOnly,
                                          final String filter,
                                          final String... attributes)
         throws LDAPSearchException
  {
    final SearchRequest r;
    try
    {
      r = new SearchRequest(baseDN, scope, derefPolicy, 1, timeLimit, typesOnly,
           filter, attributes);
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw new LDAPSearchException(le);
    }

    return searchForEntry(r);
  }

  public SearchResultEntry searchForEntry(final String baseDN,
                                          final SearchScope scope,
                                          final DereferencePolicy derefPolicy,
                                          final int timeLimit,
                                          final boolean typesOnly,
                                          final Filter filter,
                                          final String... attributes)
       throws LDAPSearchException
  {
    return searchForEntry(new SearchRequest(baseDN, scope, derefPolicy, 1,
         timeLimit, typesOnly, filter, attributes));
  }


  public SearchResultEntry searchForEntry(final SearchRequest searchRequest)
         throws LDAPSearchException
  {
    final SearchRequest r;
    if ((searchRequest.getSearchResultListener() != null) ||
        (searchRequest.getSizeLimit() != 1))
    {
      r = new SearchRequest(searchRequest.getBaseDN(), searchRequest.getScope(),
           searchRequest.getDereferencePolicy(), 1,
           searchRequest.getTimeLimitSeconds(), searchRequest.typesOnly(),
           searchRequest.getFilter(), searchRequest.getAttributes());

      r.setFollowReferrals(searchRequest.followReferralsInternal());
      r.setResponseTimeoutMillis(searchRequest.getResponseTimeoutMillis(null));

      if (searchRequest.hasControl())
      {
        r.setControlsInternal(searchRequest.getControls());
      }
    }
    else
    {
      r = searchRequest;
    }

    final SearchResult result;
    try
    {
      result = search(r);
    }
    catch (final LDAPSearchException lse)
    {
      debugException(lse);

      if (lse.getResultCode() == ResultCode.NO_SUCH_OBJECT)
      {
        return null;
      }

      throw lse;
    }

    if (result.getEntryCount() == 0)
    {
      return null;
    }
    else
    {
      return result.getSearchEntries().get(0);
    }
  }

  public SearchResultEntry searchForEntry(
                                final ReadOnlySearchRequest searchRequest)
         throws LDAPSearchException
  {
    return searchForEntry((SearchRequest) searchRequest);
  }


  public AsyncRequestID asyncSearch(final SearchRequest searchRequest)
         throws LDAPException
  {
    ensureNotNull(searchRequest);

    final SearchResultListener searchListener =
         searchRequest.getSearchResultListener();
    if (searchListener == null)
    {
      final LDAPException le = new LDAPException(ResultCode.PARAM_ERROR,
           ERR_ASYNC_SEARCH_NO_LISTENER.get());
      debugCodingError(le);
      throw le;
    }
    else if (! (searchListener instanceof AsyncSearchResultListener))
    {
      final LDAPException le = new LDAPException(ResultCode.PARAM_ERROR,
           ERR_ASYNC_SEARCH_INVALID_LISTENER.get());
      debugCodingError(le);
      throw le;
    }

    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return searchRequest.processAsync(this,
         (AsyncSearchResultListener) searchListener);
  }


  public AsyncRequestID asyncSearch(final ReadOnlySearchRequest searchRequest)
         throws LDAPException
  {
    if (synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_ASYNC_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return asyncSearch((SearchRequest) searchRequest);
  }


  public LDAPResult processOperation(final LDAPRequest request)
         throws LDAPException
  {
    return request.process(this, 1);
  }



  public ReferralConnector getReferralConnector()
  {
    if (referralConnector == null)
    {
      return this;
    }
    else
    {
      return referralConnector;
    }
  }

  public void setReferralConnector(final ReferralConnector referralConnector)
  {
    if (referralConnector == null)
    {
      this.referralConnector = this;
    }
    else
    {
      this.referralConnector = referralConnector;
    }
  }



  void sendMessage(final LDAPMessage message)
         throws LDAPException
  {
    if (needsReconnect.compareAndSet(true, false))
    {
      reconnect();
    }

    final LDAPConnectionInternals internals = connectionInternals;
    if (internals == null)
    {
      throw new LDAPException(ResultCode.SERVER_DOWN,
                              ERR_CONN_NOT_ESTABLISHED.get());
    }
    else
    {
      internals.sendMessage(message, connectionOptions.autoReconnect());
    }
  }



  int nextMessageID()
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals == null)
    {
      return -1;
    }
    else
    {
      return internals.nextMessageID();
    }
  }

  DisconnectInfo getDisconnectInfo()
  {
    return disconnectInfo.get();
  }


  public void setDisconnectInfo(final DisconnectType type, final String message,
                                final Throwable cause)
  {
    disconnectInfo.compareAndSet(null,
         new DisconnectInfo(this, type, message, cause));
  }



  DisconnectInfo setDisconnectInfo(final DisconnectInfo info)
  {
    disconnectInfo.compareAndSet(null, info);
    return disconnectInfo.get();
  }


  public DisconnectType getDisconnectType()
  {
    final DisconnectInfo di = disconnectInfo.get();
    if (di == null)
    {
      return null;
    }
    else
    {
      return di.getType();
    }
  }



  public String getDisconnectMessage()
  {
    final DisconnectInfo di = disconnectInfo.get();
    if (di == null)
    {
      return null;
    }
    else
    {
      return di.getMessage();
    }
  }


  public Throwable getDisconnectCause()
  {
    final DisconnectInfo di = disconnectInfo.get();
    if (di == null)
    {
      return null;
    }
    else
    {
      return di.getCause();
    }
  }

  void setClosed()
  {
    needsReconnect.set(false);

    if (disconnectInfo.get() == null)
    {
      try
      {
        final StackTraceElement[] stackElements =
             Thread.currentThread().getStackTrace();
        final StackTraceElement[] parentStackElements =
             new StackTraceElement[stackElements.length - 1];
        System.arraycopy(stackElements, 1, parentStackElements, 0,
             parentStackElements.length);

        setDisconnectInfo(DisconnectType.OTHER,
             ERR_CONN_CLOSED_BY_UNEXPECTED_CALL_PATH.get(
                  getStackTrace(parentStackElements)),
             null);
      }
      catch (final Exception e)
      {
        debugException(e);
      }
    }

    connectionStatistics.incrementNumDisconnects();
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals != null)
    {
      internals.close();
      connectionInternals = null;
    }

    cachedSchema = null;

    if (timer != null)
    {
      timer.cancel();
      timer = null;
    }
  }



  void registerResponseAcceptor(final int messageID,
                                final ResponseAcceptor responseAcceptor)
       throws LDAPException
  {
    if (needsReconnect.compareAndSet(true, false))
    {
      reconnect();
    }

    final LDAPConnectionInternals internals = connectionInternals;
    if (internals == null)
    {
      throw new LDAPException(ResultCode.SERVER_DOWN,
                              ERR_CONN_NOT_ESTABLISHED.get());
    }
    else
    {
      internals.registerResponseAcceptor(messageID, responseAcceptor);
    }
  }


  void deregisterResponseAcceptor(final int messageID)
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals != null)
    {
      internals.deregisterResponseAcceptor(messageID);
    }
  }


  synchronized Timer getTimer()
  {
    if (timer == null)
    {
      timer = new Timer("Timer thread for " + toString(), true);
    }

    return timer;
  }



  public LDAPConnection getReferralConnection(final LDAPURL referralURL,
                                              final LDAPConnection connection)
         throws LDAPException
  {
    final String host = referralURL.getHost();
    final int    port = referralURL.getPort();

    BindRequest bindRequest = null;
    if (connection.lastBindRequest != null)
    {
      bindRequest = connection.lastBindRequest.getRebindRequest(host, port);
      if (bindRequest == null)
      {
        throw new LDAPException(ResultCode.REFERRAL,
                                ERR_CONN_CANNOT_AUTHENTICATE_FOR_REFERRAL.get(
                                     host, port));
      }
    }

    final LDAPConnection conn = new LDAPConnection(connection.socketFactory,
         connection.connectionOptions, host, port);

    if (bindRequest != null)
    {
      try
      {
        conn.bind(bindRequest);
      }
      catch (LDAPException le)
      {
        debugException(le);
        conn.setDisconnectInfo(DisconnectType.BIND_FAILED, null, le);
        conn.close();

        throw le;
      }
    }

    return conn;
  }



  BindRequest getLastBindRequest()
  {
    return lastBindRequest;
  }



  LDAPConnectionInternals getConnectionInternals(
                               final boolean throwIfDisconnected)
       throws LDAPException
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if ((internals == null) && throwIfDisconnected)
    {
      throw new LDAPException(ResultCode.SERVER_DOWN,
           ERR_CONN_NOT_ESTABLISHED.get());
    }
    else
    {
      return internals;
    }
  }



  Schema getCachedSchema()
  {
    return cachedSchema;
  }


  void setCachedSchema(final Schema cachedSchema)
  {
    this.cachedSchema = cachedSchema;
  }


  public boolean synchronousMode()
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals == null)
    {
      return false;
    }
    else
    {
      return internals.synchronousMode();
    }
  }


  LDAPResponse readResponse(final int messageID)
               throws LDAPException
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals != null)
    {
      return internals.getConnectionReader().readResponse(messageID);
    }
    else
    {
      final DisconnectInfo di = disconnectInfo.get();
      if (di == null)
      {
        return new ConnectionClosedResponse(ResultCode.CONNECT_ERROR,
             ERR_CONN_READ_RESPONSE_NOT_ESTABLISHED.get());
      }
      else
      {
        return new ConnectionClosedResponse(di.getType().getResultCode(),
             di.getMessage());
      }
    }
  }


  public long getConnectTime()
  {
    final LDAPConnectionInternals internals = connectionInternals;
    if (internals != null)
    {
      return internals.getConnectTime();
    }
    else
    {
      return -1L;
    }
  }


  public LDAPConnectionStatistics getConnectionStatistics()
  {
    return connectionStatistics;
  }




  public int getActiveOperationCount()
  {
    final LDAPConnectionInternals internals = connectionInternals;

    if (internals == null)
    {
      return -1;
    }
    else
    {
      if (internals.synchronousMode())
      {
        return -1;
      }
      else
      {
        return internals.getConnectionReader().getActiveOperationCount();
      }
    }
  }



  private static Schema getCachedSchema(final LDAPConnection c)
         throws LDAPException
  {
    final Schema s = c.getSchema();

    synchronized (SCHEMA_SET)
    {
      return SCHEMA_SET.addAndGet(s);
    }
  }



  @Override()
  protected void finalize()
            throws Throwable
  {
    super.finalize();

    setDisconnectInfo(DisconnectType.CLOSED_BY_FINALIZER, null, null);
    setClosed();
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
    buffer.append("LDAPConnection(");

    final String name     = connectionName;
    final String poolName = connectionPoolName;
    if (name != null)
    {
      buffer.append("name='");
      buffer.append(name);
      buffer.append("', ");
    }
    else if (poolName != null)
    {
      buffer.append("poolName='");
      buffer.append(poolName);
      buffer.append("', ");
    }

    final LDAPConnectionInternals internals = connectionInternals;
    if ((internals != null) && internals.isConnected())
    {
      buffer.append("connected to ");
      buffer.append(internals.getHost());
      buffer.append(':');
      buffer.append(internals.getPort());
    }
    else
    {
      buffer.append("not connected");
    }

    buffer.append(')');
  }
}
