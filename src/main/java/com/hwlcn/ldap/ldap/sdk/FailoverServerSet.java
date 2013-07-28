package com.hwlcn.ldap.ldap.sdk;



import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.SocketFactory;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides a server set implementation that will attempt to
 * establish connections to servers in the order they are provided.  If the
 * first server is unavailable, then it will attempt to connect to the second,
 * then to the third, etc.  Note that this implementation also makes it possible
 * to use failover between distinct server sets, which means that it will first
 * attempt to obtain a connection from the first server set and if all attempts
 * fail, it will proceed to the second set, and so on.  This can provide a
 * significant degree of flexibility in complex environments (e.g., first use a
 * round robin server set containing servers in the local data center, but if
 * none of those are available then fail over to a server set with servers in a
 * remote data center).
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for creating a failover server
 * set with information about individual servers.  It will first try to connect
 * to ds1.example.com:389, but if that fails then it will try connecting to
 * ds2.example.com:389:
 * <PRE>
 *   String[] addresses =
 *   {
 *     "ds1.example.com",
 *     "ds2.example.com"
 *   };
 *   int[] ports =
 *   {
 *     389,
 *     389
 *   };
 *   FailoverServerSet failoverSet = new FailoverServerSet(addresses, ports);
 * </PRE>
 * This second example demonstrates the process for creating a failover server
 * set which actually fails over between two different data centers (east and
 * west), with each data center containing two servers that will be accessed in
 * a round-robin manner.  It will first try to connect to one of the servers in
 * the east data center, and if that attempt fails then it will try to connect
 * to the other server in the east data center.  If both of them fail, then it
 * will try to connect to one of the servers in the west data center, and
 * finally as a last resort the other server in the west data center:
 * <PRE>
 *   String[] eastAddresses =
 *   {
 *     "ds-east-1.example.com",
 *     "ds-east-2.example.com",
 *   };
 *   int[] eastPorts =
 *   {
 *     389,
 *     389
 *   }
 *   RoundRobinServerSet eastSet =
 *        new RoundRobinServerSet(eastAddresses, eastPorts);
 *
 *   String[] westAddresses =
 *   {
 *     "ds-west-1.example.com",
 *     "ds-west-2.example.com",
 *   };
 *   int[] westPorts =
 *   {
 *     389,
 *     389
 *   }
 *   RoundRobinServerSet westSet =
 *        new RoundRobinServerSet(westAddresses, westPorts);
 *
 *   FailoverServerSet failoverSet = new FailoverServerSet(eastSet, westSet);
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class FailoverServerSet
       extends ServerSet
{
  private final AtomicBoolean reOrderOnFailover;

  private final ServerSet[] serverSets;


  public FailoverServerSet(final String[] addresses, final int[] ports)
  {
    this(addresses, ports, null, null);
  }

  public FailoverServerSet(final String[] addresses, final int[] ports,
                           final LDAPConnectionOptions connectionOptions)
  {
    this(addresses, ports, null, connectionOptions);
  }

  public FailoverServerSet(final String[] addresses, final int[] ports,
                           final SocketFactory socketFactory)
  {
    this(addresses, ports, socketFactory, null);
  }

  public FailoverServerSet(final String[] addresses, final int[] ports,
                           final SocketFactory socketFactory,
                           final LDAPConnectionOptions connectionOptions)
  {
    ensureNotNull(addresses, ports);
    ensureTrue(addresses.length > 0,
               "FailoverServerSet.addresses must not be empty.");
    ensureTrue(addresses.length == ports.length,
         "FailoverServerSet addresses and ports arrays must be the same size.");

    reOrderOnFailover = new AtomicBoolean(false);

    final SocketFactory sf;
    if (socketFactory == null)
    {
      sf = SocketFactory.getDefault();
    }
    else
    {
      sf = socketFactory;
    }

    final LDAPConnectionOptions co;
    if (connectionOptions == null)
    {
      co = new LDAPConnectionOptions();
    }
    else
    {
      co = connectionOptions;
    }


    serverSets = new ServerSet[addresses.length];
    for (int i=0; i < serverSets.length; i++)
    {
      serverSets[i] = new SingleServerSet(addresses[i], ports[i], sf, co);
    }
  }

  public FailoverServerSet(final ServerSet... serverSets)
  {
    ensureNotNull(serverSets);
    ensureFalse(serverSets.length == 0,
                "FailoverServerSet.serverSets must not be empty.");

    this.serverSets = serverSets;

    reOrderOnFailover = new AtomicBoolean(false);
  }

  public FailoverServerSet(final List<ServerSet> serverSets)
  {
    ensureNotNull(serverSets);
    ensureFalse(serverSets.isEmpty(),
                "FailoverServerSet.serverSets must not be empty.");

    this.serverSets = new ServerSet[serverSets.size()];
    serverSets.toArray(this.serverSets);

    reOrderOnFailover = new AtomicBoolean(false);
  }

  public ServerSet[] getServerSets()
  {
    return serverSets;
  }


  public boolean reOrderOnFailover()
  {
    return reOrderOnFailover.get();
  }

  public void setReOrderOnFailover(final boolean reOrderOnFailover)
  {
    this.reOrderOnFailover.set(reOrderOnFailover);
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
    if (reOrderOnFailover.get() && (serverSets.length > 1))
    {
      synchronized (this)
      {
        try
        {
          return serverSets[0].getConnection(healthCheck);
        }
        catch (final LDAPException le)
        {
          debugException(le);
        }

        int successfulPos = -1;
        LDAPConnection conn = null;
        LDAPException lastException = null;
        for (int i=1; i < serverSets.length; i++)
        {
          try
          {
            conn = serverSets[i].getConnection(healthCheck);
            successfulPos = i;
            break;
          }
          catch (final LDAPException le)
          {
            debugException(le);
            lastException = le;
          }
        }

        if (successfulPos > 0)
        {
          int pos = 0;
          final ServerSet[] setCopy = new ServerSet[serverSets.length];
          for (int i=successfulPos; i < serverSets.length; i++)
          {
            setCopy[pos++] = serverSets[i];
          }

          for (int i=0; i < successfulPos; i++)
          {
            setCopy[pos++] = serverSets[i];
          }

          System.arraycopy(setCopy, 0, serverSets, 0, setCopy.length);
          return conn;
        }
        else
        {
          throw lastException;
        }
      }
    }
    else
    {
      LDAPException lastException = null;

      for (final ServerSet s : serverSets)
      {
        try
        {
          return s.getConnection(healthCheck);
        }
        catch (LDAPException le)
        {
          debugException(le);
          lastException = le;
        }
      }

      throw lastException;
    }
  }


@Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("FailoverServerSet(serverSets={");

    for (int i=0; i < serverSets.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      serverSets[i].toString(buffer);
    }

    buffer.append("})");
  }
}
