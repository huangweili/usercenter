package com.hwlcn.ldap.ldap.sdk;



import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.SocketFactory;

import com.hwlcn.ldap.util.Debug;
import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.ldap.util.StaticUtils;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;
import com.hwlcn.ldap.util.Validator;

import static com.hwlcn.ldap.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a server set implementation that will attempt to
 * establish connections to all associated servers in parallel, keeping the one
 * that was first to be successfully established and closing all others.
 * <BR><BR>
 * Note that this server set implementation may only be used in conjunction with
 * connection options that allow the associated socket factory to create
 * multiple connections in parallel.  If the
 * {@link com.hwlcn.ldap.ldap.sdk.LDAPConnectionOptions#allowConcurrentSocketFactoryUse} method returns
 * false for the associated connection options, then the {@code getConnection}
 * methods will throw an exception.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for creating a fastest connect
 * server set that may be used to establish connections to either of two
 * servers.  When using the server set to attempt to create a connection, it
 * will try both in parallel and will return the first connection that it is
 * able to establish:
 * <PRE>
 *   String[] addresses =
 *   {
 *     "ds1.example.com",
 *     "ds2.example.com",
 *   };
 *   int[] ports =
 *   {
 *     389,
 *     389
 *   }
 *   FastestConnectServerSet fastestConnectSet =
 *        new FastestConnectServerSet(addresses, ports);
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class FastestConnectServerSet
       extends ServerSet
{
  private final int[] ports;

  private final LDAPConnectionOptions connectionOptions;

  private final SocketFactory socketFactory;

  private final String[] addresses;



  public FastestConnectServerSet(final String[] addresses, final int[] ports)
  {
    this(addresses, ports, null, null);
  }


  public FastestConnectServerSet(final String[] addresses, final int[] ports,
                                 final LDAPConnectionOptions connectionOptions)
  {
    this(addresses, ports, null, connectionOptions);
  }



  public FastestConnectServerSet(final String[] addresses, final int[] ports,
                                 final SocketFactory socketFactory)
  {
    this(addresses, ports, socketFactory, null);
  }


  public FastestConnectServerSet(final String[] addresses, final int[] ports,
                                 final SocketFactory socketFactory,
                                 final LDAPConnectionOptions connectionOptions)
  {
    Validator.ensureNotNull(addresses, ports);
    Validator.ensureTrue(addresses.length > 0,
         "RoundRobinServerSet.addresses must not be empty.");
    Validator.ensureTrue(addresses.length == ports.length,
         "RoundRobinServerSet addresses and ports arrays must be the same " +
              "size.");

    this.addresses = addresses;
    this.ports     = ports;

    if (socketFactory == null)
    {
      this.socketFactory = SocketFactory.getDefault();
    }
    else
    {
      this.socketFactory = socketFactory;
    }

    if (connectionOptions == null)
    {
      this.connectionOptions = new LDAPConnectionOptions();
    }
    else
    {
      this.connectionOptions = connectionOptions;
    }
  }

  public String[] getAddresses()
  {
    return addresses;
  }

  public int[] getPorts()
  {
    return ports;
  }

  public SocketFactory getSocketFactory()
  {
    return socketFactory;
  }


  public LDAPConnectionOptions getConnectionOptions()
  {
    return connectionOptions;
  }

  @Override()
  public LDAPConnection getConnection()
         throws LDAPException
  {
    return getConnection(null);
  }

  @Override()
  public LDAPConnection getConnection(
                             final LDAPConnectionPoolHealthCheck healthCheck)
         throws LDAPException
  {
    if (! connectionOptions.allowConcurrentSocketFactoryUse())
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR,
           ERR_FASTEST_CONNECT_SET_OPTIONS_NOT_PARALLEL.get());
    }

    final ArrayBlockingQueue<Object> resultQueue =
         new ArrayBlockingQueue<Object>(addresses.length, false);
    final AtomicBoolean connectionSelected = new AtomicBoolean(false);

    final FastestConnectThread[] connectThreads =
         new FastestConnectThread[addresses.length];
    for (int i=0; i < connectThreads.length; i++)
    {
      connectThreads[i] = new FastestConnectThread(addresses[i], ports[i],
           socketFactory, connectionOptions, healthCheck, resultQueue,
           connectionSelected);
    }

    for (final FastestConnectThread t : connectThreads)
    {
      t.start();
    }

    try
    {
      final long effectiveConnectTimeout;
      final long connectTimeout =
           connectionOptions.getConnectTimeoutMillis();
      if ((connectTimeout > 0L) && (connectTimeout < Integer.MAX_VALUE))
      {
        effectiveConnectTimeout = connectTimeout;
      }
      else
      {
        effectiveConnectTimeout = Integer.MAX_VALUE;
      }

      int connectFailures = 0;
      final long stopWaitingTime =
           System.currentTimeMillis() + effectiveConnectTimeout;
      while (true)
      {
        final Object o;
        final long waitTime = stopWaitingTime - System.currentTimeMillis();
        if (waitTime > 0L)
        {
          o = resultQueue.poll(waitTime, TimeUnit.MILLISECONDS);
        }
        else
        {
          o = resultQueue.poll();
        }

        if (o == null)
        {
          throw new LDAPException(ResultCode.CONNECT_ERROR,
               ERR_FASTEST_CONNECT_SET_CONNECT_TIMEOUT.get(
                    effectiveConnectTimeout));
        }
        else if (o instanceof LDAPConnection)
        {
          return (LDAPConnection) o;
        }
        else
        {
          connectFailures++;
          if (connectFailures >= addresses.length)
          {
            throw new LDAPException(ResultCode.CONNECT_ERROR,
                 ERR_FASTEST_CONNECT_SET_ALL_FAILED.get());
          }
        }
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.CONNECT_ERROR,
           ERR_FASTEST_CONNECT_SET_CONNECT_EXCEPTION.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }

  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("FastestConnectServerSet(servers={");

    for (int i=0; i < addresses.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append(addresses[i]);
      buffer.append(':');
      buffer.append(ports[i]);
    }

    buffer.append("})");
  }
}
