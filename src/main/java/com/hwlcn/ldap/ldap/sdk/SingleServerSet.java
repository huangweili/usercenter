package com.hwlcn.ldap.ldap.sdk;



import javax.net.SocketFactory;

import com.hwlcn.core.annotation.NotMutable;
import com.hwlcn.core.annotation.ThreadSafety;
import com.hwlcn.ldap.util.ThreadSafetyLevel;

import static com.hwlcn.ldap.util.Validator.*;


@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SingleServerSet
       extends ServerSet
{
  private final int port;

  private final LDAPConnectionOptions connectionOptions;

  private final SocketFactory socketFactory;


  private final String address;



  public SingleServerSet(final String address, final int port)
  {
    this(address, port, null, null);
  }



  public SingleServerSet(final String address, final int port,
                         final LDAPConnectionOptions connectionOptions)
  {
    this(address, port, null, connectionOptions);
  }



  public SingleServerSet(final String address, final int port,
                         final SocketFactory socketFactory)
  {
    this(address, port, socketFactory, null);
  }



  public SingleServerSet(final String address, final int port,
                         final SocketFactory socketFactory,
                         final LDAPConnectionOptions connectionOptions)
  {
    ensureNotNull(address);
    ensureTrue((port > 0) && (port < 65536),
               "SingleServerSet.port must be between 1 and 65535.");

    this.address = address;
    this.port    = port;

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


  public String getAddress()
  {
    return address;
  }


  public int getPort()
  {
    return port;
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
    return new LDAPConnection(socketFactory, connectionOptions, address, port);
  }



  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("SingleServerSet(server=");
    buffer.append(address);
    buffer.append(':');
    buffer.append(port);
    buffer.append(')');
  }
}
