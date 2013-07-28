package com.hwlcn.ldap.ldap.sdk;



import javax.net.SocketFactory;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Debug.*;
import static com.hwlcn.ldap.util.Validator.*;



/**
 * This class provides a server set implementation that will use a round-robin
 * algorithm to select the server to which the connection should be established.
 * Any number of servers may be included in this server set, and each request
 * will attempt to retrieve a connection to the next server in the list,
 * circling back to the beginning of the list as necessary.  If a server is
 * unavailable when an attempt is made to establish a connection to it, then
 * the connection will be established to the next available server in the set.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for creating a round-robin
 * server set that may be used to establish connections to either of two
 * servers.  When using the server set to attempt to create a connection, it
 * will first try one of the servers, but will fail over to the other if the
 * first one attempted is not available:
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
 *   };
 *   RoundRobinServerSet roundRobinSet =
 *        new RoundRobinServerSet(addresses, ports);
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RoundRobinServerSet
       extends ServerSet
{
  private final int[] ports;

  private final LDAPConnectionOptions connectionOptions;

  private final SocketFactory socketFactory;

  private final String[] addresses;

  private int nextSlot;



  public RoundRobinServerSet(final String[] addresses, final int[] ports)
  {
    this(addresses, ports, null, null);
  }



  public RoundRobinServerSet(final String[] addresses, final int[] ports,
                             final LDAPConnectionOptions connectionOptions)
  {
    this(addresses, ports, null, connectionOptions);
  }




  public RoundRobinServerSet(final String[] addresses, final int[] ports,
                             final SocketFactory socketFactory)
  {
    this(addresses, ports, socketFactory, null);
  }



  public RoundRobinServerSet(final String[] addresses, final int[] ports,
                             final SocketFactory socketFactory,
                             final LDAPConnectionOptions connectionOptions)
  {
    ensureNotNull(addresses, ports);
    ensureTrue(addresses.length > 0,
               "RoundRobinServerSet.addresses must not be empty.");
    ensureTrue(addresses.length == ports.length,
               "RoundRobinServerSet addresses and ports arrays must be the " +
                    "same size.");

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

    nextSlot = 0;
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
  public synchronized LDAPConnection getConnection(
                           final LDAPConnectionPoolHealthCheck healthCheck)
         throws LDAPException
  {
    final int initialSlotNumber = nextSlot++;

    if (nextSlot >= addresses.length)
    {
      nextSlot = 0;
    }

    try
    {
      final LDAPConnection c = new LDAPConnection(socketFactory,
           connectionOptions, addresses[initialSlotNumber],
           ports[initialSlotNumber]);
      if (healthCheck != null)
      {
        try
        {
          healthCheck.ensureNewConnectionValid(c);
        }
        catch (LDAPException le)
        {
          c.close();
          throw le;
        }
      }
      return c;
    }
    catch (LDAPException le)
    {
      debugException(le);
      LDAPException lastException = le;

      while (nextSlot != initialSlotNumber)
      {
        final int slotNumber = nextSlot++;
        if (nextSlot >= addresses.length)
        {
          nextSlot = 0;
        }

        try
        {
          final LDAPConnection c = new LDAPConnection(socketFactory,
               connectionOptions, addresses[slotNumber], ports[slotNumber]);
          if (healthCheck != null)
          {
            try
            {
              healthCheck.ensureNewConnectionValid(c);
            }
            catch (LDAPException le2)
            {
              c.close();
              throw le2;
            }
          }
          return c;
        }
        catch (LDAPException le2)
        {
          debugException(le2);
          lastException = le2;
        }
      }

      // If we've gotten here, then we've failed to connect to any of the
      // servers, so propagate the last exception to the caller.
      throw lastException;
    }
  }



  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("RoundRobinServerSet(servers={");

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
