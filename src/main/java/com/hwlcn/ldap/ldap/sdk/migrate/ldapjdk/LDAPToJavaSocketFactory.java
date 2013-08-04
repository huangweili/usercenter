package com.hwlcn.ldap.ldap.sdk.migrate.ldapjdk;



import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.SocketFactory;

import static com.hwlcn.ldap.util.Debug.*;


final class LDAPToJavaSocketFactory
      extends SocketFactory
{
  private final LDAPSocketFactory f;


  LDAPToJavaSocketFactory(final LDAPSocketFactory f)
  {
    this.f = f;
  }



  @Override()
  public Socket createSocket(final String host, final int port)
         throws IOException
  {
    if (f instanceof SocketFactory)
    {
      synchronized (f)
      {
        return ((SocketFactory) f).createSocket(host, port);
      }
    }

    try
    {
      synchronized (f)
      {
        return f.makeSocket(host, port);
      }
    }
    catch (Exception e)
    {
      debugException(e);
      throw new IOException(e.getMessage());
    }
  }


  @Override()
  public Socket createSocket(final String host, final int port,
                             final InetAddress localAddress,
                             final int localPort)
         throws IOException
  {
    if (f instanceof SocketFactory)
    {
      synchronized (f)
      {
        return ((SocketFactory) f).createSocket(host, port, localAddress,
             localPort);
      }
    }

    return createSocket(host, port);
  }



  @Override()
  public Socket createSocket(final InetAddress address, final int port)
         throws IOException
  {
    if (f instanceof SocketFactory)
    {
      synchronized (f)
      {
        return ((SocketFactory) f).createSocket(address, port);
      }
    }

    return createSocket(address.getHostAddress(), port);
  }


  @Override()
  public Socket createSocket(final InetAddress address, final int port,
                             final InetAddress localAddress,
                             final int localPort)
         throws IOException
  {
    if (f instanceof SocketFactory)
    {
      synchronized (f)
      {
        return ((SocketFactory) f).createSocket(address, port, localAddress,
             localPort);
      }
    }

    return createSocket(address.getHostAddress(), port);
  }
}
